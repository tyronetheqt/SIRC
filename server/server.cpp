#include "../common.h"
#include "server.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static auto serverStartTime = std::chrono::steady_clock::now();

std::map<SOCKET, std::pair<std::string, std::shared_ptr<SimpleAES>>> onlineUsers;
std::mutex onlineUsers_mutex;

struct Channel {
    std::string name;
    std::map<SOCKET, std::string> members;
    std::mutex mutex;

    Channel(std::string n) : name(std::move(n)) {}
};

std::map<std::string, std::shared_ptr<Channel>> channels;
std::mutex channels_mutex;

CryptoPP::RSA::PrivateKey rsaPrivateKey;
CryptoPP::RSA::PublicKey rsaPublicKey;

void generateRSAKeys()
{
    CryptoPP::AutoSeededRandomPool rng;
    rsaPrivateKey.GenerateRandomWithKeySize(rng, 2048);
    rsaPublicKey = CryptoPP::RSA::PublicKey(rsaPrivateKey);

    std::cout << "Server: RSA keys generated. Public key modulus size: "
        << rsaPublicKey.GetModulus().ByteCount() * 8 << " bits.\n";
}

void sendMessageToClient(SOCKET clientSocket, const std::string& message) {
    std::shared_ptr<SimpleAES> clientAesCipher;
    {
        std::lock_guard<std::mutex> lock(onlineUsers_mutex);
        auto it = onlineUsers.find(clientSocket);
        if (it != onlineUsers.end()) {
            clientAesCipher = it->second.second;
        }
    }

    if (clientAesCipher) {
        try {
            std::vector<unsigned char> responseBytes(message.begin(), message.end());
            std::vector<unsigned char> encryptedResponse = clientAesCipher->encrypt(responseBytes);
            if (!send_message_with_length(clientSocket, encryptedResponse)) {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "Server: Error sending message to socket " << clientSocket << ". Error Code: " << WSAGetLastError() << "\n";
            }
        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Server: Exception encrypting/sending message to socket " << clientSocket << ": " << e.what() << "\n";
        }
    }
}

void broadcastToChannel(const std::string& channelName, const std::string& message, SOCKET senderSocket = INVALID_SOCKET) {
    std::shared_ptr<Channel> targetChannel;
    {
        std::lock_guard<std::mutex> lock(channels_mutex);
        auto it = channels.find(channelName);
        if (it != channels.end()) {
            targetChannel = it->second;
        }
    }

    if (targetChannel) {
        std::lock_guard<std::mutex> channelLock(targetChannel->mutex);
        for (const auto& memberPair : targetChannel->members) {
            if (memberPair.first != senderSocket) {
                sendMessageToClient(memberPair.first, message);
            }
        }
    }
}

void handleClient(SOCKET clientSocket) {
    std::string clientUsername = "Unknown";
    bool client_setup_successful = false;
    std::vector<std::string> joinedChannels;

    CryptoPP::AutoSeededRandomPool rng;

    std::string encodedPubKey;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encodedPubKey), false);
    rsaPublicKey.DEREncode(encoder);
    encoder.MessageEnd();

    size_t totalSent = 0;
    size_t remaining = encodedPubKey.size();
    const char* dataPtr = encodedPubKey.data();

    while (remaining > 0) {
        int sent = send(clientSocket, dataPtr + totalSent, (int)remaining, 0);
        if (sent == SOCKET_ERROR) {
            std::cerr << "Server: failed to send public key fully. Error: " << WSAGetLastError() << "\n";
            closesocket(clientSocket);
            return;
        }
        totalSent += sent;
        remaining -= sent;
    }

    std::vector<unsigned char> encryptedAESKeyVec = recv_message_with_length(clientSocket);
    if (encryptedAESKeyVec.empty()) {
        std::cerr << "Server: Failed to receive encrypted AES key or client disconnected during key exchange.\n";
        closesocket(clientSocket);
        return;
    }
    std::string encryptedAESKeyStr(encryptedAESKeyVec.begin(), encryptedAESKeyVec.end());

    std::string decryptedAESKey;
    try {
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivateKey);
        CryptoPP::AutoSeededRandomPool rng_local;

        if (encryptedAESKeyStr.size() != decryptor.FixedCiphertextLength()) {
            std::cerr << "Server: Error: Received encrypted AES key size (" << encryptedAESKeyStr.size()
                << " bytes) does not match expected RSA ciphertext length ("
                << decryptor.FixedCiphertextLength() << " bytes).\n";
            closesocket(clientSocket);
            return;
        }

        CryptoPP::StringSource ss(encryptedAESKeyStr, true,
            new CryptoPP::PK_DecryptorFilter(rng_local, decryptor,
                new CryptoPP::StringSink(decryptedAESKey)));

        if (decryptedAESKey.size() != 32) {
            std::cerr << "Server: Warning: Decrypted AES key has unexpected size: " << decryptedAESKey.size() << " bytes. Expected 32 for AES-256.\n";
            closesocket(clientSocket);
            return;
        }
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Server: Crypto++ Exception during AES key decryption: " << e.what() << "\n";
        closesocket(clientSocket);
        return;
    }
    catch (const std::exception& e) {
        std::cerr << "Server: Standard Exception during AES key decryption: " << e.what() << "\n";
        closesocket(clientSocket);
        return;
    }
    catch (...) {
        std::cerr << "Server: Unknown Exception during AES key decryption.\n";
        closesocket(clientSocket);
        return;
    }

    std::shared_ptr<SimpleAES> clientAesCipher;
    try {
        clientAesCipher = std::make_shared<SimpleAES>(std::vector<unsigned char>(decryptedAESKey.begin(), decryptedAESKey.end()));
    }
    catch (const std::exception& e) {
        std::cerr << "Server: Error initializing SimpleAES (GCM) for client: " << e.what() << "\n";
        closesocket(clientSocket);
        return;
    }

    std::vector<unsigned char> encryptedUsername = recv_message_with_length(clientSocket);

    if (encryptedUsername.empty()) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Error receiving username from client or client disconnected during username exchange.\n";
        closesocket(clientSocket);
        return;
    }

    try {
        std::vector<unsigned char> decryptedUsernameBytes = clientAesCipher->decrypt(encryptedUsername);
        clientUsername.assign(decryptedUsernameBytes.begin(), decryptedUsernameBytes.end());

        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Server: Received username: '" << clientUsername << "'\n";
        }

        std::string ackMessage = "Welcome, " + clientUsername + "! Type /CMDS for commands. Join a channel with /JOIN <channel_name>.";
        std::vector<unsigned char> ackBytes(ackMessage.begin(), ackMessage.end());
        std::vector<unsigned char> encryptedAck = clientAesCipher->encrypt(ackBytes);

        if (!send_message_with_length(clientSocket, encryptedAck)) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Server: Error sending username ack to '" << clientUsername << "' (with length prefix): " << WSAGetLastError() << "\n";
            closesocket(clientSocket);
            return;
        }
        else {
            client_setup_successful = true;
        }
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Exception during username decryption/welcome encryption (GCM error likely indicates tampering): " << e.what() << "\n";
        closesocket(clientSocket);
        return;
    }

    if (client_setup_successful) {
        {
            std::lock_guard<std::mutex> lock(onlineUsers_mutex);
            onlineUsers[clientSocket] = { clientUsername, clientAesCipher };
        }
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Server: Client '" << clientUsername << "' (Socket: " << clientSocket << ") added to online users list.\n";
            std::cout << "Server: Client '" << clientUsername << "' connected, ready to receive encrypted data.\n";
        }

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(1, 100);

        do {
            std::vector<unsigned char> encryptedData = recv_message_with_length(clientSocket);

            if (encryptedData.empty()) {
                std::lock_guard<std::mutex> lock(console_mutex);
                if (WSAGetLastError() == 0) {
                    std::cout << "Server: Client '" << clientUsername << "' disconnected gracefully.\n";
                }
                else {
                    std::cout << "Server: recv error from '" << clientUsername << "' (with length prefix). Error Code: " << WSAGetLastError() << "\n";
                }
                break;
            }

            try {
                std::vector<unsigned char> decryptedData = clientAesCipher->decrypt(encryptedData);
                std::string decryptedCommand(decryptedData.begin(), decryptedData.end());

                std::string processedCommand = decryptedCommand;
                std::transform(processedCommand.begin(), processedCommand.end(), processedCommand.begin(),
                    [](unsigned char c) { return static_cast<unsigned char>(std::toupper(c)); });

                {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cout << "Server received " << encryptedData.size() << " bytes from '" << clientUsername << "'. Decrypted command: '" << decryptedCommand << "'\n";
                }

                std::string responseMessage;

                if (processedCommand == "PING") {
                    SOCKADDR_IN clientAddr;
                    int clientAddrLen = sizeof(clientAddr);
                    getpeername(clientSocket, (SOCKADDR*)&clientAddr, &clientAddrLen);
                    IPAddr ipAddress = clientAddr.sin_addr.S_un.S_addr;

                    HANDLE hIcmpFile = IcmpCreateFile();
                    if (hIcmpFile == INVALID_HANDLE_VALUE) {
                        responseMessage = "Server: Could not create ICMP handle.";
                        std::lock_guard<std::mutex> lock(console_mutex);
                        std::cerr << "Server: IcmpCreateFile failed: " << GetLastError() << "\n";
                    }
                    else {
                        char sendData[] = "PingData";
                        int requestSize = sizeof(sendData);

                        std::vector<char> replyBuffer(sizeof(ICMP_ECHO_REPLY) + requestSize);

                        DWORD timeout = 1000;

                        DWORD dwRetVal = IcmpSendEcho(
                            hIcmpFile,
                            ipAddress,
                            sendData,
                            requestSize,
                            NULL,
                            replyBuffer.data(),
                            static_cast<DWORD>(replyBuffer.size()),
                            timeout
                        );

                        if (dwRetVal != 0) {
                            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)replyBuffer.data();
                            if (pEchoReply->Status == IP_SUCCESS) {
                                responseMessage = "Ping RTT: " + std::to_string(pEchoReply->RoundTripTime) + "ms";
                            }
                            else {
                                responseMessage = "Ping failed with status: " + std::to_string(pEchoReply->Status);
                            }
                        }
                        else {
                            responseMessage = "Ping timed out or failed. Error: " + std::to_string(GetLastError());
                        }
                        IcmpCloseHandle(hIcmpFile);
                    }
                }
                else if (processedCommand == "TIME") {
                    std::time_t now_time_t = std::time(nullptr);
                    std::tm ltm_buf;
                    errno_t err = localtime_s(&ltm_buf, &now_time_t);

                    if (err != 0) {
                        responseMessage = "Error getting server time.";
                        std::lock_guard<std::mutex> lock(console_mutex);
                        std::cerr << "Server: localtime_s failed with error: " << err << "\n";
                    }
                    else {
                        std::stringstream ss;
                        ss << std::put_time(&ltm_buf, "%Y-%m-%d %H:%M:%S");
                        responseMessage = ss.str();
                    }
                }
                else if (processedCommand == "STATUS") {
                    responseMessage = "Server operational. All systems green.";
                }
                else if (processedCommand.rfind("ECHO ", 0) == 0 && processedCommand.length() > 5) {
                    responseMessage = decryptedCommand.substr(processedCommand.find("ECHO ") + 5);
                }
                else if (processedCommand == "RANDOM") {
                    responseMessage = std::to_string(distrib(gen));
                }
                else if (processedCommand == "MOTD") {
                    responseMessage = "Today's fun fact: A group of owls is called a parliament!";
                }
                else if (processedCommand == "UPTIME") {
                    auto now = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - serverStartTime);
                    long long total_seconds = duration.count();
                    long long hours = total_seconds / 3600;
                    long long minutes = (total_seconds % 3600) / 60;
                    long long seconds = total_seconds % 60;

                    std::stringstream ss;
                    ss << "Server Uptime: ";
                    if (hours > 0) ss << hours << "h ";
                    if (minutes > 0 || hours > 0) ss << minutes << "m ";
                    ss << seconds << "s";
                    responseMessage = ss.str();
                }
                else if (processedCommand == "CMDS" || processedCommand == "COMMANDS") {
                    responseMessage = "Available commands:\n";
                    responseMessage += "- PING: Checks server responsiveness\n";
                    responseMessage += "- TIME: Get current server time\n";
                    responseMessage += "- STATUS: Get server operational status\n";
                    responseMessage += "- ECHO <message>: Server echoes back your message\n";
                    responseMessage += "- RANDOM: Get a random number (1-100)\n";
                    responseMessage += "- MOTD: Get a fun message of the day\n";
                    responseMessage += "- UPTIME: Get server uptime\n";
                    responseMessage += "- ONLINE / USERS: List current online users\n";
                    responseMessage += "- MSG <username> <message>: Send a private message to a user\n";
                    responseMessage += "- JOIN <channel_name>: Join or create a channel\n";
                    responseMessage += "- LEAVE [<channel_name>]: Leave a specific channel, or all if none specified\n";
                    responseMessage += "- LIST: List all active channels\n";
                    responseMessage += "- WHO <channel_name>: List users in a channel\n";
                    responseMessage += "- MSG #<channel_name> <message>: Send a message to a channel\n";
                    responseMessage += "- CMDS / COMMANDS: List all commands";
                }
                else if (processedCommand == "ONLINE" || processedCommand == "USERS") {
                    std::string userListString = "--- Currently Online Users ---\n";
                    std::lock_guard<std::mutex> lock(onlineUsers_mutex);
                    if (onlineUsers.empty()) {
                        userListString = "No users currently online.";
                    }
                    else {
                        for (const auto& pair : onlineUsers) {
                            userListString += "- " + pair.second.first + "\n";
                        }
                        if (userListString.back() == '\n') {
                            userListString.pop_back();
                        }
                    }
                    responseMessage = userListString;
                }
                else if (processedCommand.rfind("MSG #", 0) == 0) {
                    std::string fullMsgArgs = decryptedCommand.substr(processedCommand.find("MSG #") + 5);
                    size_t firstSpace = fullMsgArgs.find(' ');

                    if (firstSpace == std::string::npos || firstSpace == 0 || firstSpace == fullMsgArgs.length() - 1) {
                        responseMessage = "Error: Invalid channel message format. Usage: MSG #<channel_name> <message>";
                    }
                    else {
                        std::string targetChannelName = fullMsgArgs.substr(0, firstSpace);
                        std::string messageContent = fullMsgArgs.substr(firstSpace + 1);

                        std::transform(targetChannelName.begin(), targetChannelName.end(), targetChannelName.begin(),
                            [](unsigned char c) { return static_cast<unsigned char>(std::tolower(c)); });

                        std::shared_ptr<Channel> targetChannel;
                        {
                            std::lock_guard<std::mutex> lock(channels_mutex);
                            auto it = channels.find(targetChannelName);
                            if (it != channels.end()) {
                                targetChannel = it->second;
                            }
                        }

                        if (targetChannel) {
                            bool isMember = false;
                            {
                                std::lock_guard<std::mutex> channelLock(targetChannel->mutex);
                                isMember = targetChannel->members.count(clientSocket);
                            }

                            if (isMember) {
                                std::string fullChannelMessage = "[" + targetChannelName + "] <" + clientUsername + ">: " + messageContent;
                                broadcastToChannel(targetChannelName, fullChannelMessage, clientSocket);
                                responseMessage = "Message sent to channel #" + targetChannelName + ".";
                            }
                            else {
                                responseMessage = "Error: You are not a member of channel #" + targetChannelName + ". Join it first with /JOIN " + targetChannelName;
                            }
                        }
                        else {
                            responseMessage = "Error: Channel #" + targetChannelName + " does not exist.";
                        }
                    }
                }
                else if (processedCommand.rfind("MSG ", 0) == 0) {
                    std::string fullMsgArgs = decryptedCommand.substr(processedCommand.find("MSG ") + 4);
                    size_t firstSpace = fullMsgArgs.find(' ');

                    if (firstSpace == std::string::npos || firstSpace == 0 || firstSpace == fullMsgArgs.length() - 1) {
                        responseMessage = "Error: Invalid private message format. Usage: MSG <username> <message>";
                    }
                    else {
                        std::string targetUsername = fullMsgArgs.substr(0, firstSpace);
                        std::string messageContent = fullMsgArgs.substr(firstSpace + 1);

                        SOCKET targetSocket = INVALID_SOCKET;
                        std::shared_ptr<SimpleAES> targetAesCipher = nullptr;
                        std::string senderResponseMessage;

                        {
                            std::lock_guard<std::mutex> lock(onlineUsers_mutex);
                            for (const auto& pair : onlineUsers) {
                                if (pair.second.first == targetUsername) {
                                    targetSocket = pair.first;
                                    targetAesCipher = pair.second.second;
                                    break;
                                }
                            }
                        }

                        if (targetSocket != INVALID_SOCKET) {
                            if (targetSocket == clientSocket) {
                                senderResponseMessage = "Error: You cannot send a private message to yourself.";
                            }
                            else if (!targetAesCipher) {
                                senderResponseMessage = "Error: Target user's encryption context not found.";
                                std::lock_guard<std::mutex> lock(console_mutex);
                                std::cerr << "Server: Logic error: target socket found but no cipher for '" << targetUsername << "'.\n";
                            }
                            else {
                                std::string messageToRecipient = "[PM from " + clientUsername + "]: " + messageContent;
                                std::vector<unsigned char> encryptedMessage = targetAesCipher->encrypt(
                                    std::vector<unsigned char>(messageToRecipient.begin(), messageToRecipient.end())
                                );

                                if (!send_message_with_length(targetSocket, encryptedMessage)) {
                                    std::lock_guard<std::mutex> lock(console_mutex);
                                    std::cerr << "Server: Error sending message to '" << targetUsername << "' (Socket: " << targetSocket << ") with length prefix: " << WSAGetLastError() << "\n";
                                    senderResponseMessage = "Error: Could not send message to '" + targetUsername + "'. They might have disconnected.";
                                }
                                else {
                                    senderResponseMessage = "Message sent to '" + targetUsername + "'.";
                                    std::lock_guard<std::mutex> lock(console_mutex);
                                    std::cout << "Server: Message from '" << clientUsername << "' to '" << targetUsername << "' sent (with length prefix).\n";
                                }
                            }
                        }
                        else {
                            senderResponseMessage = "Error: User '" + targetUsername + "' not found or is offline.";
                            std::lock_guard<std::mutex> lock(console_mutex);
                            std::cout << "Server: Message from '" << clientUsername << "' to '" << targetUsername << "' failed: User not found.\n";
                        }
                        responseMessage = senderResponseMessage;
                    }
                }
                else if (processedCommand.rfind("JOIN ", 0) == 0 && processedCommand.length() > 5) {
                    std::string channelName = decryptedCommand.substr(processedCommand.find("JOIN ") + 5);

                    if (channelName.empty() || channelName.find('#') != std::string::npos || channelName.find(' ') != std::string::npos) {
                        responseMessage = "Error: Invalid channel name. Channel names cannot contain '#' or spaces.";
                    }
                    else {
                        std::transform(channelName.begin(), channelName.end(), channelName.begin(),
                            [](unsigned char c) { return static_cast<unsigned char>(std::tolower(c)); });

                        std::shared_ptr<Channel> channel;
                        bool newChannelCreated = false;
                        std::string joinBroadcastMessage;

                        {
                            std::lock_guard<std::mutex> lock(channels_mutex);
                            auto it = channels.find(channelName);
                            if (it == channels.end()) {
                                channel = std::make_shared<Channel>(channelName);
                                channels[channelName] = channel;
                                newChannelCreated = true;
                            }
                            else {
                                channel = it->second;
                            }
                        }

                        {
                            std::lock_guard<std::mutex> channelLock(channel->mutex);
                            if (channel->members.count(clientSocket) == 0) {
                                channel->members[clientSocket] = clientUsername;
                                joinedChannels.push_back(channelName);
                                responseMessage = "Joined channel #" + channelName + ".";
                                joinBroadcastMessage = clientUsername + " has joined #" + channelName + ".";
                            }
                            else {
                                responseMessage = "You are already in channel #" + channelName + ".";
                            }
                        }

                        if (!joinBroadcastMessage.empty()) {
                            broadcastToChannel(channelName, joinBroadcastMessage, clientSocket);
                        }
                        if (newChannelCreated) {
                            std::lock_guard<std::mutex> lock(console_mutex);
                            std::cout << "Server: Channel #" << channelName << " created.\n";
                        }
                    }
                }
                else if (processedCommand.rfind("LEAVE", 0) == 0) {
                    std::string channelNameArg = decryptedCommand.substr(processedCommand.find("LEAVE") + 5);
                    if (!channelNameArg.empty() && channelNameArg[0] == ' ') {
                        channelNameArg = channelNameArg.substr(1);
                        std::transform(channelNameArg.begin(), channelNameArg.end(), channelNameArg.begin(),
                            [](unsigned char c) { return static_cast<unsigned char>(std::tolower(c)); });
                    }

                    if (channelNameArg.empty()) {
                        if (joinedChannels.empty()) {
                            responseMessage = "You are not in any channels to leave.";
                        }
                        else {
                            std::string leaveConfirmation = "Left channels: ";
                            std::vector<std::string> channelsToCleanUp;

                            for (const std::string& channelToLeave : joinedChannels) {
                                std::shared_ptr<Channel> channel;
                                {
                                    std::lock_guard<std::mutex> lock(channels_mutex);
                                    auto it = channels.find(channelToLeave);
                                    if (it != channels.end()) {
                                        channel = it->second;
                                    }
                                }

                                if (channel) {
                                    std::string leaveBroadcastMessage = clientUsername + " has left #" + channelToLeave + ".";
                                    bool channelBecameEmpty = false;
                                    {
                                        std::lock_guard<std::mutex> channelLock(channel->mutex);
                                        channel->members.erase(clientSocket);
                                        if (channel->members.empty()) {
                                            channelBecameEmpty = true;
                                        }
                                    }

                                    broadcastToChannel(channelToLeave, leaveBroadcastMessage, clientSocket);

                                    if (channelBecameEmpty) {
                                        channelsToCleanUp.push_back(channelToLeave);
                                    }
                                    leaveConfirmation += "#" + channelToLeave + " ";
                                }
                            }

                            {
                                std::lock_guard<std::mutex> lock(channels_mutex);
                                for (const std::string& emptyChannel : channelsToCleanUp) {
                                    channels.erase(emptyChannel);
                                    std::lock_guard<std::mutex> consoleLock(console_mutex);
                                    std::cout << "Server: Channel #" << emptyChannel << " is now empty and removed.\n";
                                }
                            }
                            joinedChannels.clear();
                            responseMessage = leaveConfirmation;
                        }
                    }
                    else {
                        auto it = std::find(joinedChannels.begin(), joinedChannels.end(), channelNameArg);
                        if (it != joinedChannels.end()) {
                            std::shared_ptr<Channel> channel;
                            {
                                std::lock_guard<std::mutex> lock(channels_mutex);
                                auto channel_it = channels.find(channelNameArg);
                                if (channel_it != channels.end()) {
                                    channel = channel_it->second;
                                }
                            }

                            if (channel) {
                                std::string leaveBroadcastMessage = clientUsername + " has left #" + channelNameArg + ".";
                                bool channelBecameEmpty = false;
                                {
                                    std::lock_guard<std::mutex> channelLock(channel->mutex);
                                    channel->members.erase(clientSocket);
                                    if (channel->members.empty()) {
                                        channelBecameEmpty = true;
                                    }
                                }

                                broadcastToChannel(channelNameArg, leaveBroadcastMessage, clientSocket);

                                if (channelBecameEmpty) {
                                    std::lock_guard<std::mutex> lock(channels_mutex);
                                    channels.erase(channelNameArg);
                                    std::lock_guard<std::mutex> consoleLock(console_mutex);
                                    std::cout << "Server: Channel #" << channelNameArg << " is now empty and removed.\n";
                                }
                                joinedChannels.erase(it);
                                responseMessage = "Left channel #" + channelNameArg + ".";
                            }
                            else {
                                responseMessage = "Error: Channel #" + channelNameArg + " not found (internal error).";
                            }
                        }
                        else {
                            responseMessage = "Error: You are not in channel #" + channelNameArg + ".";
                        }
                    }
                }
                else if (processedCommand == "LIST") {
                    std::lock_guard<std::mutex> lock(channels_mutex);
                    if (channels.empty()) {
                        responseMessage = "No active channels.";
                    }
                    else {
                        responseMessage = "--- Active Channels ---\n";
                        for (const auto& pair : channels) {
                            std::lock_guard<std::mutex> channelLock(pair.second->mutex);
                            responseMessage += "#" + pair.first + " (" + std::to_string(pair.second->members.size()) + " users)\n";
                        }
                        if (responseMessage.back() == '\n') {
                            responseMessage.pop_back();
                        }
                    }
                }
                else if (processedCommand.rfind("WHO ", 0) == 0 && processedCommand.length() > 4) {
                    std::string channelName = decryptedCommand.substr(processedCommand.find("WHO ") + 4);
                    std::transform(channelName.begin(), channelName.end(), channelName.begin(),
                        [](unsigned char c) { return static_cast<unsigned char>(std::tolower(c)); });

                    std::shared_ptr<Channel> targetChannel;
                    {
                        std::lock_guard<std::mutex> lock(channels_mutex);
                        auto it = channels.find(channelName);
                        if (it != channels.end()) {
                            targetChannel = it->second;
                        }
                    }

                    if (targetChannel) {
                        std::lock_guard<std::mutex> channelLock(targetChannel->mutex);
                        if (targetChannel->members.empty()) {
                            responseMessage = "Channel #" + channelName + " has no members.";
                        }
                        else {
                            responseMessage = "--- Users in #" + channelName + " ---\n";
                            for (const auto& memberPair : targetChannel->members) {
                                responseMessage += "- " + memberPair.second + "\n";
                            }
                            if (responseMessage.back() == '\n') {
                                responseMessage.pop_back();
                            }
                        }
                    }
                    else {
                        responseMessage = "Error: Channel #" + channelName + " does not exist.";
                    }
                }
                else {
                    responseMessage = "?";
                }

                std::vector<unsigned char> responseBytes(responseMessage.begin(), responseMessage.end());
                std::vector<unsigned char> encryptedResponse = clientAesCipher->encrypt(responseBytes);

                if (!send_message_with_length(clientSocket, encryptedResponse)) {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cerr << "Server: send error to '" << clientUsername << "' (with length prefix). Error Code: " << WSAGetLastError() << "\n";
                    break;
                }
                else {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cout << "Server: Sent encrypted response (" << encryptedResponse.size() << " bytes) for command '" << decryptedCommand << "' to '" << clientUsername << "'.\n";
                }
            }
            catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "Server: Exception during command decryption/response encryption for '" << clientUsername << "' (GCM error likely indicates tampering): " << e.what() << "\n";
                break;
            }

        } while (true);
    }

    if (client_setup_successful) {
        {
            std::lock_guard<std::mutex> lock(onlineUsers_mutex);
            onlineUsers.erase(clientSocket);
        }
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Server: Client '" << clientUsername << "' (Socket: " << clientSocket << ") removed from online users list.\n";
        }
    }

    std::vector<std::string> channelsToCleanUp;
    for (const std::string& channelToLeave : joinedChannels) {
        std::shared_ptr<Channel> channel;
        {
            std::lock_guard<std::mutex> lock(channels_mutex);
            auto it = channels.find(channelToLeave);
            if (it != channels.end()) {
                channel = it->second;
            }
        }
        if (channel) {
            std::string leaveBroadcastMessage = clientUsername + " has left #" + channelToLeave + ".";
            bool channelBecameEmpty = false;
            {
                std::lock_guard<std::mutex> channelLock(channel->mutex);
                channel->members.erase(clientSocket);
                if (channel->members.empty()) {
                    channelBecameEmpty = true;
                }
            } // channelLock released

            broadcastToChannel(channelToLeave, leaveBroadcastMessage, clientSocket);

            if (channelBecameEmpty) {
                channelsToCleanUp.push_back(channelToLeave);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(channels_mutex);
        for (const std::string& emptyChannel : channelsToCleanUp) {
            channels.erase(emptyChannel);
            std::lock_guard<std::mutex> consoleLock(console_mutex);
            std::cout << "Server: Channel #" << emptyChannel << " is now empty and removed (during client disconnect).\n";
        }
    }

    int iresult = shutdown(clientSocket, SD_SEND);
    if (iresult == SOCKET_ERROR) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: shutdown error for client '" << clientUsername << "'. Error Code: " << WSAGetLastError() << "\n";
    }
    iresult = closesocket(clientSocket);
    if (iresult == SOCKET_ERROR) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: closesocket error for client '" << clientUsername << "'. Error Code: " << WSAGetLastError() << "\n";
    }
}


int runServer(const std::string& port) {
    WSADATA wsadata;
    int iresult = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (iresult != 0) {
        std::cerr << "Error WSAStartup: " << iresult << "\n";
        return 1;
    }

    generateRSAKeys();

    SOCKET listener = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints{};

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iresult = getaddrinfo(NULL, port.c_str(), &hints, &result);

    if (iresult != 0) {
        std::cerr << "Error getaddrinfo: " << iresult << "\n";
        WSACleanup();
        return 1;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        listener = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

        if (listener == INVALID_SOCKET) {
            std::cerr << "Error creating socket: " << WSAGetLastError() << "\n";
            continue;
        }
        auto optval = 1;
        iresult = setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

        if (iresult == SOCKET_ERROR) {
            std::cerr << "Error calling setsockopt: " << WSAGetLastError() << "\n";
            closesocket(listener);
            WSACleanup();
            return 1;
        }

        iresult = bind(listener, ptr->ai_addr, (int)ptr->ai_addrlen);

        if (iresult == SOCKET_ERROR) {
            std::cerr << "Error binding to addr: " << WSAGetLastError() << "\n";
            closesocket(listener);
            listener = INVALID_SOCKET;
            continue;
        }
        else {
            break;
        }
    }

    if (listener == INVALID_SOCKET) {
        std::cerr << "Found no addresses to bind to\n";
        WSACleanup();
        return 1;
    }
    freeaddrinfo(result);

    iresult = listen(listener, SOMAXCONN);

    if (iresult == SOCKET_ERROR) {
        std::cerr << "Failed calling listen on socket: " << WSAGetLastError() << "\n";
        closesocket(listener);
        WSACleanup();
        return 1;
    }

    std::cout << "Server: Listening on port " << port << std::endl;

    while (true) {
        SOCKET clientsock = INVALID_SOCKET;

        std::cout << "Server: Waiting for a new client connection...\n";
        clientsock = accept(listener, NULL, NULL);

        if (clientsock == INVALID_SOCKET) {
            std::cerr << "Failed accepting socket: " << WSAGetLastError() << "\n";
            continue;
        }

        std::thread clientThread(handleClient, clientsock);
        clientThread.detach();
    }

    iresult = closesocket(listener);
    if (iresult == SOCKET_ERROR) {
        std::cerr << "Server: closesocket error for listener: " << WSAGetLastError() << "\n";
    }
    WSACleanup();
    return 0;
}