#include "../common.h" // Assuming common.h will be reverted too
#include "server.h"

static auto serverStartTime = std::chrono::steady_clock::now();

// Reverted to std::string for username
std::map<SOCKET, std::pair<std::string, std::shared_ptr<SimpleAES>>> onlineUsers;
std::mutex onlineUsers_mutex;

CryptoPP::RSA::PrivateKey rsaPrivateKey;
CryptoPP::RSA::PublicKey rsaPublicKey;

void generateRSAKeys()
{
    CryptoPP::AutoSeededRandomPool rng;
    rsaPrivateKey.GenerateRandomWithKeySize(rng, 2048); // Generate a 2048-bit key
    rsaPublicKey = CryptoPP::RSA::PublicKey(rsaPrivateKey);

    std::cout << "Server: RSA keys generated. Public key modulus size: "
        << rsaPublicKey.GetModulus().ByteCount() * 8 << " bits.\n";
}

void handleClient(SOCKET clientSocket) {
    // clientUsername will now be stored and processed as std::string
    std::string clientUsername = "Unknown";
    bool client_setup_successful = false;

    CryptoPP::AutoSeededRandomPool rng; // RNG for this thread's crypto operations

    // --- Send Server's RSA Public Key ---
    std::string encodedPubKey;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encodedPubKey), false /*no newlines*/);
    rsaPublicKey.DEREncode(encoder);
    encoder.MessageEnd();

    std::cout << "Server: Sending public key of size: " << encodedPubKey.size() << " bytes.\n";
    std::cout << "Server: Public Key (Base64 preview, first 100 chars): "
        << encodedPubKey.substr(0, std::min((size_t)100, encodedPubKey.length())) << "...\n";

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

    if (totalSent != encodedPubKey.size()) {
        std::cerr << "Server: WARNING: Incomplete public key sent! Expected " << encodedPubKey.size()
            << ", sent " << totalSent << ".\n";
        closesocket(clientSocket);
        return;
    }
    std::cout << "Server: Public key sent successfully (" << totalSent << " bytes).\n";


    // --- Receive Encrypted AES Key ---
    std::vector<unsigned char> encryptedAESKeyVec = recv_message_with_length(clientSocket);
    if (encryptedAESKeyVec.empty()) {
        std::cerr << "Server: Failed to receive encrypted AES key or client disconnected during key exchange.\n";
        closesocket(clientSocket);
        return;
    }
    std::string encryptedAESKeyStr(encryptedAESKeyVec.begin(), encryptedAESKeyVec.end());
    std::cout << "Server: Received " << encryptedAESKeyVec.size() << " bytes for encrypted AES key (via length prefix).\n";

    // 3. Decrypt AES key with private RSA key
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
        std::cout << "Server: AES key decrypted successfully. Decrypted size: " << decryptedAESKey.size() << " bytes.\n";

        if (decryptedAESKey.size() != 32) { // AES-256 key size
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

    // 4. Initialize AES cipher with decrypted key
    std::shared_ptr<SimpleAES> clientAesCipher;
    try {
        clientAesCipher = std::make_shared<SimpleAES>(std::vector<unsigned char>(decryptedAESKey.begin(), decryptedAESKey.end()));
        std::cout << "Server: SimpleAES (GCM) cipher initialized with negotiated key for this client.\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Server: Error initializing SimpleAES (GCM) for client: " << e.what() << "\n";
        closesocket(clientSocket);
        return;
    }

    // --- Receive Encrypted Username ---
    std::vector<unsigned char> encryptedUsername = recv_message_with_length(clientSocket);

    if (encryptedUsername.empty()) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Server: Error receiving username from client or client disconnected during username exchange.\n";
        closesocket(clientSocket);
        return;
    }

    try {
        // Decrypt bytes to plaintext std::string
        std::vector<unsigned char> decryptedUsernameBytes = clientAesCipher->decrypt(encryptedUsername);
        clientUsername.assign(decryptedUsernameBytes.begin(), decryptedUsernameBytes.end()); // Assign directly to std::string

        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Server: Received username: '" << clientUsername << "'\n";
        }

        // --- Send Welcome Message ---
        std::string ackMessage = "Welcome, " + clientUsername + "!"; // Construct as std::string
        std::vector<unsigned char> ackBytes(ackMessage.begin(), ackMessage.end());
        // Encrypt std::string bytes
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
            // Store the client's username (as std::string) AND their dedicated SimpleAES cipher
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

        // Main loop for receiving commands from this client
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
                // Decrypt bytes to plaintext std::string
                std::vector<unsigned char> decryptedData = clientAesCipher->decrypt(encryptedData);
                std::string decryptedCommand(decryptedData.begin(), decryptedData.end());

                // Create a copy for case-insensitive processing
                std::string processedCommand = decryptedCommand;
                // Ensure toupper works on all characters for reliable command matching
                std::transform(processedCommand.begin(), processedCommand.end(), processedCommand.begin(),
                    [](unsigned char c) { return static_cast<unsigned char>(std::toupper(c)); });

                {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cout << "Server received " << encryptedData.size() << " bytes from '" << clientUsername << "'. Decrypted command: '" << decryptedCommand << "'\n";
                }

                std::string responseMessage; // Response message will be std::string

                if (processedCommand == "PING") {
                    responseMessage = "PONG";
                }
                else if (processedCommand == "TIME") {
                    std::time_t now_time_t = std::time(nullptr);
                    std::tm ltm_buf;
#ifdef _WIN32
                    errno_t err = localtime_s(&ltm_buf, &now_time_t);
#else
                    std::tm* tm_ptr = localtime(&now_time_t);
                    if (tm_ptr) ltm_buf = *tm_ptr;
                    int err = tm_ptr ? 0 : 1;
#endif

                    if (err != 0) {
                        responseMessage = "Error getting server time.";
                        std::lock_guard<std::mutex> lock(console_mutex);
                        std::cerr << "Server: localtime_s failed with error: " << err << "\n";
                    }
                    else {
                        std::stringstream ss;
                        ss << std::put_time(&ltm_buf, "%Y-%m-%d %H:%M:%S"); // Back to char* format string
                        responseMessage = ss.str();
                    }
                }
                else if (processedCommand == "STATUS") {
                    responseMessage = "Server operational. All systems green.";
                }
                else if (processedCommand.rfind("ECHO ", 0) == 0 && processedCommand.length() > 5) {
                    // Use decryptedCommand for the message part of ECHO (original case)
                    responseMessage = decryptedCommand.substr(processedCommand.find("ECHO ") + 5);
                }
                else if (processedCommand == "RANDOM") {
                    responseMessage = std::to_string(distrib(gen)); // Back to std::to_string
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

                    std::stringstream ss; // Back to stringstream
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
                            userListString += "- " + pair.second.first + "\n"; // pair.second.first is already std::string
                        }
                        if (userListString.back() == '\n') {
                            userListString.pop_back();
                        }
                    }
                    responseMessage = userListString;
                }
                else if (processedCommand.rfind("MSG ", 0) == 0) {
                    // Parse arguments from the original (case-sensitive) decryptedCommand
                    std::string fullMsgArgs = decryptedCommand.substr(processedCommand.find("MSG ") + 4);
                    size_t firstSpace = fullMsgArgs.find(' ');

                    if (firstSpace == std::string::npos || firstSpace == 0 || firstSpace == fullMsgArgs.length() - 1) {
                        responseMessage = "Error: Invalid message format. Usage: MSG <username> <message>";
                    }
                    else {
                        std::string targetUsername = fullMsgArgs.substr(0, firstSpace);
                        std::string messageContent = fullMsgArgs.substr(firstSpace + 1);

                        SOCKET targetSocket = INVALID_SOCKET;
                        std::shared_ptr<SimpleAES> targetAesCipher = nullptr;
                        std::string senderResponseMessage; // Sender's response will be std::string

                        {
                            std::lock_guard<std::mutex> lock(onlineUsers_mutex);
                            for (const auto& pair : onlineUsers) {
                                if (pair.second.first == targetUsername) { // Compare std::string usernames
                                    targetSocket = pair.first;
                                    targetAesCipher = pair.second.second; // Get the recipient's AES cipher!
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
                        responseMessage = senderResponseMessage; // This response goes back to the SENDER of the MSG command
                    }
                }
                else {
                    responseMessage = "?"; // Unknown command
                }

                // Convert server's response to bytes for encryption
                std::vector<unsigned char> responseBytes(responseMessage.begin(), responseMessage.end());
                // Encrypt response using this client's specific GCM AES cipher
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

    // --- Client Disconnection Cleanup ---
    if (client_setup_successful) {
        {
            std::lock_guard<std::mutex> lock(onlineUsers_mutex);
            onlineUsers.erase(clientSocket); // Remove the entry from the map
        }
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Server: Client '" << clientUsername << "' (Socket: " << clientSocket << ") removed from online users list.\n";
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