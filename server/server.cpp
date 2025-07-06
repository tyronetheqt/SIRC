#include "../common.h"
#include "server.h"
#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <set>
#include <map>
#include <memory>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

static auto serverStartTime = std::chrono::steady_clock::now();

std::map<std::shared_ptr<tcp::socket>, std::pair<std::string, std::shared_ptr<SimpleAES>>> onlineUsers;
std::mutex onlineUsers_mutex;

struct Channel {
    std::string name;
    std::map<std::shared_ptr<tcp::socket>, std::string> members;
    std::mutex mutex;

    Channel(std::string n) : name(std::move(n)) {}
};

std::map<std::string, std::shared_ptr<Channel>> channels;
std::mutex channels_mutex;

CryptoPP::RSA::PrivateKey rsaPrivateKey;
CryptoPP::RSA::PublicKey rsaPublicKey;

void generateRSAKeys() {
    CryptoPP::AutoSeededRandomPool rng;
    rsaPrivateKey.GenerateRandomWithKeySize(rng, 2048);
    rsaPublicKey = CryptoPP::RSA::PublicKey(rsaPrivateKey);

    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << "Server: RSA keys generated. Public key modulus size: "
        << rsaPublicKey.GetModulus().ByteCount() * 8 << " bits.\n";
}

void sendMessageToClient(std::shared_ptr<tcp::socket> clientSocketPtr, const std::string& message) {
    std::shared_ptr<SimpleAES> clientAesCipher;
    {
        std::lock_guard<std::mutex> lock(onlineUsers_mutex);
        auto it = onlineUsers.find(clientSocketPtr);
        if (it != onlineUsers.end()) {
            clientAesCipher = it->second.second;
        }
    }

    if (clientAesCipher && clientSocketPtr->is_open()) {
        try {
            std::vector<unsigned char> responseBytes(message.begin(), message.end());
            std::vector<unsigned char> encryptedResponse = clientAesCipher->encrypt(responseBytes);
            if (!send_message_with_length(*clientSocketPtr, encryptedResponse)) {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "Server: Error sending message to socket " << clientSocketPtr->remote_endpoint().address().to_string()
                    << ":" << clientSocketPtr->remote_endpoint().port() << ". Socket might be closed.\n";
            }
        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Server: Exception encrypting/sending message to socket " << clientSocketPtr->remote_endpoint().address().to_string()
                << ":" << clientSocketPtr->remote_endpoint().port() << ": " << e.what() << "\n";
        }
    }
}

void broadcastToChannel(const std::string& channelName, const std::string& message, std::shared_ptr<tcp::socket> senderSocketPtr = nullptr) {
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
            if (memberPair.first != senderSocketPtr) {
                sendMessageToClient(memberPair.first, message);
            }
        }
    }
}

void handleClient(std::shared_ptr<tcp::socket> clientSocketPtr) {
    std::string clientUsername = "Unknown";
    bool client_setup_successful = false;
    std::vector<std::string> joinedChannels;

    std::string encodedPubKey;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encodedPubKey), false);
    rsaPublicKey.DEREncode(encoder);
    encoder.MessageEnd();

    try {
        asio::write(*clientSocketPtr, asio::buffer(encodedPubKey + "\n"));
    }
    catch (const boost::system::system_error& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: failed to send public key fully to " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << ". Error: " << e.what() << "\n";
        clientSocketPtr->close();
        return;
    }

    std::vector<unsigned char> encryptedAESKeyVec = recv_message_with_length(*clientSocketPtr);
    if (encryptedAESKeyVec.empty()) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Failed to receive encrypted AES key or client disconnected during key exchange from " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << ".\n";
        clientSocketPtr->close();
        return;
    }
    std::string encryptedAESKeyStr(encryptedAESKeyVec.begin(), encryptedAESKeyVec.end());

    std::string decryptedAESKey;
    try {
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivateKey);
        CryptoPP::AutoSeededRandomPool rng_local;

        if (encryptedAESKeyStr.size() != decryptor.FixedCiphertextLength()) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Server: Error: Received encrypted AES key size (" << encryptedAESKeyStr.size()
                << " bytes) does not match expected RSA ciphertext length ("
                << decryptor.FixedCiphertextLength() << " bytes) from " << clientSocketPtr->remote_endpoint().address().to_string()
                << ":" << clientSocketPtr->remote_endpoint().port() << ".\n";
            clientSocketPtr->close();
            return;
        }

        CryptoPP::StringSource ss(encryptedAESKeyStr, true,
            new CryptoPP::PK_DecryptorFilter(rng_local, decryptor,
                new CryptoPP::StringSink(decryptedAESKey)));

        if (decryptedAESKey.size() != 32) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Server: Warning: Decrypted AES key has unexpected size: " << decryptedAESKey.size() << " bytes. Expected 32 for AES-256 from " << clientSocketPtr->remote_endpoint().address().to_string()
                << ":" << clientSocketPtr->remote_endpoint().port() << ".\n";
            clientSocketPtr->close();
            return;
        }
    }
    catch (const CryptoPP::Exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Crypto++ Exception during AES key decryption from " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << ": " << e.what() << "\n";
        clientSocketPtr->close();
        return;
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Standard Exception during AES key decryption from " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << ": " << e.what() << "\n";
        clientSocketPtr->close();
        return;
    }
    catch (...) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Unknown Exception during AES key decryption from " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << ".\n";
        clientSocketPtr->close();
        return;
    }

    std::shared_ptr<SimpleAES> clientAesCipher;
    try {
        clientAesCipher = std::make_shared<SimpleAES>(std::vector<unsigned char>(decryptedAESKey.begin(), decryptedAESKey.end()));
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Error initializing SimpleAES (GCM) for client " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << ": " << e.what() << "\n";
        clientSocketPtr->close();
        return;
    }

    // Receive encrypted username
    std::vector<unsigned char> encryptedUsername = recv_message_with_length(*clientSocketPtr);

    if (encryptedUsername.empty()) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Error receiving username from client " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << " or client disconnected during username exchange.\n";
        clientSocketPtr->close();
        return;
    }

    try {
        std::vector<unsigned char> decryptedUsernameBytes = clientAesCipher->decrypt(encryptedUsername);
        clientUsername.assign(decryptedUsernameBytes.begin(), decryptedUsernameBytes.end());

        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Server: Received username: '" << clientUsername << "' from " << clientSocketPtr->remote_endpoint().address().to_string()
                << ":" << clientSocketPtr->remote_endpoint().port() << "\n";
        }

        std::string ackMessage = "Welcome, " + clientUsername + "! Type /CMDS for commands. Join a channel with /JOIN <channel_name>.";
        std::vector<unsigned char> ackBytes(ackMessage.begin(), ackMessage.end());
        std::vector<unsigned char> encryptedAck = clientAesCipher->encrypt(ackBytes);

        if (!send_message_with_length(*clientSocketPtr, encryptedAck)) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Server: Error sending username ack to '" << clientUsername << "' (with length prefix) " << clientSocketPtr->remote_endpoint().address().to_string()
                << ":" << clientSocketPtr->remote_endpoint().port() << ".\n";
            clientSocketPtr->close();
            return;
        }
        else {
            client_setup_successful = true;
        }
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Exception during username decryption/welcome encryption (GCM error likely indicates tampering) from " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << ": " << e.what() << "\n";
        clientSocketPtr->close();
        return;
    }

    if (client_setup_successful) {
        {
            std::lock_guard<std::mutex> lock(onlineUsers_mutex);
            onlineUsers[clientSocketPtr] = { clientUsername, clientAesCipher };
        }
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Server: Client '" << clientUsername << "' (Socket: " << clientSocketPtr->remote_endpoint().address().to_string()
                << ":" << clientSocketPtr->remote_endpoint().port() << ") added to online users list.\n";
            std::cout << "Server: Client '" << clientUsername << "' connected, ready to receive encrypted data.\n";
        }

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(1, 100);

        do {
            std::vector<unsigned char> encryptedData = recv_message_with_length(*clientSocketPtr);

            if (encryptedData.empty()) {
                std::lock_guard<std::mutex> lock(console_mutex);
                boost::system::error_code ec;
                clientSocketPtr->remote_endpoint(ec);
                if (ec == boost::asio::error::eof || ec == boost::asio::error::bad_descriptor) {
                    std::cout << "Server: Client '" << clientUsername << "' disconnected gracefully from " << clientSocketPtr->remote_endpoint().address().to_string()
                        << ":" << clientSocketPtr->remote_endpoint().port() << ".\n";
                }
                else {
                    std::cout << "Server: recv error from '" << clientUsername << "' (with length prefix) " << clientSocketPtr->remote_endpoint().address().to_string()
                        << ":" << clientSocketPtr->remote_endpoint().port() << ". Error Code: " << ec.message() << "\n";
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
                    std::cout << "Server received " << encryptedData.size() << " bytes from '" << clientUsername << "' (" << clientSocketPtr->remote_endpoint().address().to_string()
                        << ":" << clientSocketPtr->remote_endpoint().port() << "). Decrypted command: '" << decryptedCommand << "'\n";
                }

                std::string responseMessage;

                if (processedCommand == "PING") {
                    responseMessage = "ill do it later";
                }
                else if (processedCommand == "TIME") {
                    std::time_t now_time_t = std::time(nullptr);
                    std::tm ltm_buf;
                    std::tm* result_tm = std::localtime(&now_time_t);

                    if (result_tm == nullptr) {
                        responseMessage = "Error getting server time.";
                        std::lock_guard<std::mutex> lock(console_mutex);
                        std::cerr << "Server: std::localtime failed.\n";
                    }
                    else {
                        ltm_buf = *result_tm;
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
                                for (const auto& member : targetChannel->members) {
                                    if (member.first == clientSocketPtr) {
                                        isMember = true;
                                        break;
                                    }
                                }
                            }

                            if (isMember) {
                                std::string fullChannelMessage = "[" + targetChannelName + "] <" + clientUsername + ">: " + messageContent;
                                broadcastToChannel(targetChannelName, fullChannelMessage, clientSocketPtr);
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

                        std::shared_ptr<tcp::socket> targetSocketPtr = nullptr;
                        std::shared_ptr<SimpleAES> targetAesCipher = nullptr;
                        std::string senderResponseMessage;

                        {
                            std::lock_guard<std::mutex> lock(onlineUsers_mutex);
                            for (const auto& pair : onlineUsers) {
                                if (pair.second.first == targetUsername) {
                                    targetSocketPtr = pair.first;
                                    targetAesCipher = pair.second.second;
                                    break;
                                }
                            }
                        }

                        if (targetSocketPtr) {
                            if (targetSocketPtr == clientSocketPtr) {
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

                                if (!send_message_with_length(*targetSocketPtr, encryptedMessage)) {
                                    std::lock_guard<std::mutex> lock(console_mutex);
                                    std::cerr << "Server: Error sending message to '" << targetUsername << "' (Socket: " << targetSocketPtr->remote_endpoint().address().to_string()
                                        << ":" << targetSocketPtr->remote_endpoint().port() << ") with length prefix.\n";
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
                            bool alreadyMember = false;
                            for (const auto& member : channel->members) {
                                if (member.first == clientSocketPtr) {
                                    alreadyMember = true;
                                    break;
                                }
                            }

                            if (!alreadyMember) {
                                channel->members[clientSocketPtr] = clientUsername;
                                joinedChannels.push_back(channelName);
                                responseMessage = "Joined channel #" + channelName + ".";
                                joinBroadcastMessage = clientUsername + " has joined #" + channelName + ".";
                            }
                            else {
                                responseMessage = "You are already in channel #" + channelName + ".";
                            }
                        }

                        if (!joinBroadcastMessage.empty()) {
                            broadcastToChannel(channelName, joinBroadcastMessage, clientSocketPtr);
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
                            std::vector<std::string> channelsLeftSuccessfully;

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
                                        bool wasMember = false;
                                        for (auto it_member = channel->members.begin(); it_member != channel->members.end(); ++it_member) {
                                            if (it_member->first == clientSocketPtr) {
                                                channel->members.erase(it_member);
                                                wasMember = true;
                                                break;
                                            }
                                        }
                                        if (channel->members.empty()) {
                                            channelBecameEmpty = true;
                                        }
                                        if (wasMember) {
                                            channelsLeftSuccessfully.push_back(channelToLeave);
                                        }
                                    }

                                    if (std::find(channelsLeftSuccessfully.begin(), channelsLeftSuccessfully.end(), channelToLeave) != channelsLeftSuccessfully.end()) {
                                        broadcastToChannel(channelToLeave, leaveBroadcastMessage);
                                    }

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
                                    std::cout << "Server: Channel #" << emptyChannel << " is now empty and removed (client disconnect cleanup).\n";
                                }
                            }
                            joinedChannels.clear();
                            for (const std::string& ch : channelsLeftSuccessfully) {
                                leaveConfirmation += "#" + ch + " ";
                            }
                            if (channelsLeftSuccessfully.empty()) {
                                responseMessage = "You were not a member of any of the specified channels.";
                            }
                            else {
                                responseMessage = leaveConfirmation;
                            }
                        }
                    }
                    else {
                        auto it_joined = std::find(joinedChannels.begin(), joinedChannels.end(), channelNameArg);
                        if (it_joined != joinedChannels.end()) {
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
                                    bool wasMember = false;
                                    for (auto it_member = channel->members.begin(); it_member != channel->members.end(); ++it_member) {
                                        if (it_member->first == clientSocketPtr) {
                                            channel->members.erase(it_member);
                                            wasMember = true;
                                            break;
                                        }
                                    }
                                    if (channel->members.empty()) {
                                        channelBecameEmpty = true;
                                    }
                                    if (!wasMember) {
                                        responseMessage = "Error: You are not a member of channel #" + channelNameArg + ".";
                                    }
                                }

                                if (responseMessage.empty()) {
                                    broadcastToChannel(channelNameArg, leaveBroadcastMessage);
                                }

                                if (channelBecameEmpty) {
                                    std::lock_guard<std::mutex> lock(channels_mutex);
                                    channels.erase(channelNameArg);
                                    std::lock_guard<std::mutex> consoleLock(console_mutex);
                                    std::cout << "Server: Channel #" << channelNameArg << " is now empty and removed.\n";
                                }
                                if (responseMessage.empty()) {
                                    joinedChannels.erase(it_joined);
                                    responseMessage = "Left channel #" + channelNameArg + ".";
                                }
                            }
                            else {
                                responseMessage = "Error: Channel #" + channelNameArg + " does not exist.";
                            }
                        }
                        else {
                            responseMessage = "Error: You are not in channel #" + channelNameArg + ".";
                        }
                    }
                }
                else if (processedCommand == "LIST") {
                    std::string channelListString = "--- Active Channels ---\n";
                    std::lock_guard<std::mutex> lock(channels_mutex);
                    if (channels.empty()) {
                        channelListString = "No active channels.";
                    }
                    else {
                        for (const auto& pair : channels) {
                            channelListString += "- #" + pair.first + "\n";
                        }
                        if (channelListString.back() == '\n') {
                            channelListString.pop_back();
                        }
                    }
                    responseMessage = channelListString;
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
                        std::string memberListString = "--- Members in #" + channelName + " ---\n";
                        std::lock_guard<std::mutex> channelLock(targetChannel->mutex);
                        if (targetChannel->members.empty()) {
                            memberListString = "Channel #" + channelName + " has no members.";
                        }
                        else {
                            for (const auto& memberPair : targetChannel->members) {
                                memberListString += "- " + memberPair.second + "\n";
                            }
                            if (memberListString.back() == '\n') {
                                memberListString.pop_back();
                            }
                        }
                        responseMessage = memberListString;
                    }
                    else {
                        responseMessage = "Error: Channel #" + channelName + " does not exist.";
                    }
                }
                else {
                    responseMessage = "Unknown command: '" + decryptedCommand + "'. Type /CMDS for a list of commands.";
                }

                if (!responseMessage.empty()) {
                    sendMessageToClient(clientSocketPtr, responseMessage);
                }

            }
            catch (const CryptoPP::Exception& e) {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "Server: Crypto++ Exception during decryption from '" << clientUsername << "' (" << clientSocketPtr->remote_endpoint().address().to_string()
                    << ":" << clientSocketPtr->remote_endpoint().port() << "): " << e.what() << "\n";
                sendMessageToClient(clientSocketPtr, "Error: Failed to decrypt message. Possible tampering or key mismatch.");
            }
            catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "Server: Standard Exception during command processing from '" << clientUsername << "' (" << clientSocketPtr->remote_endpoint().address().to_string()
                    << ":" << clientSocketPtr->remote_endpoint().port() << "): " << e.what() << "\n";
                sendMessageToClient(clientSocketPtr, "Error processing your command.");
            }
        } while (clientSocketPtr->is_open());
    }

    {
        std::lock_guard<std::mutex> lock(onlineUsers_mutex);
        onlineUsers.erase(clientSocketPtr);
    }
    {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << "Server: Client '" << clientUsername << "' (Socket: " << clientSocketPtr->remote_endpoint().address().to_string()
            << ":" << clientSocketPtr->remote_endpoint().port() << ") removed from online users list.\n";
    }

    {
        std::lock_guard<std::mutex> lock(channels_mutex);
        for (const std::string& channelName : joinedChannels) {
            auto it = channels.find(channelName);
            if (it != channels.end()) {
                std::shared_ptr<Channel> channel = it->second;
                std::lock_guard<std::mutex> channelLock(channel->mutex);
                bool wasMember = false;
                for (auto it_member = channel->members.begin(); it_member != channel->members.end(); ++it_member) {
                    if (it_member->first == clientSocketPtr) {
                        channel->members.erase(it_member);
                        wasMember = true;
                        break;
                    }
                }
                if (wasMember) {
                    std::string leaveBroadcastMessage = clientUsername + " has left #" + channelName + ".";
                    broadcastToChannel(channelName, leaveBroadcastMessage);
                }
                if (channel->members.empty()) {
                    channels.erase(channelName);
                    std::lock_guard<std::mutex> consoleLock(console_mutex);
                    std::cout << "Server: Channel #" << channelName << " is now empty and removed (client disconnect cleanup).\n";
                }
            }
        }
    }
    boost::system::error_code ec;
    clientSocketPtr->shutdown(tcp::socket::shutdown_both, ec);
    clientSocketPtr->close(ec);
}

int runServer(int port) {
    generateRSAKeys();

    try {
        asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));

        print_to_console(std::string("server: Listening on port ") + std::to_string(port) + "...");

        while (true) {
            std::shared_ptr<tcp::socket> socket_ptr = std::make_shared<tcp::socket>(io_context);
            acceptor.accept(*socket_ptr);

            std::thread(handleClient, socket_ptr).detach();
        }
    }
    catch (const boost::system::system_error& e) {
        print_to_console(std::string("server: Error: ") + e.what());
        return 1;
    }
    return 0;
}
