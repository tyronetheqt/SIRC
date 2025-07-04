#include "../common.h"
#include "client.h"
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

std::atomic<bool> stop_threads(false);

void receiveMessages(SOCKET serverSocket, const SimpleAES& aesCipher) {
    while (!stop_threads) {
        std::vector<unsigned char> encryptedData = recv_message_with_length(serverSocket);

        if (encryptedData.empty()) {
            if (!stop_threads) {
                std::lock_guard<std::mutex> lock(console_mutex);
                if (WSAGetLastError() == 0) {
                    std::cerr << "\nServer disconnected gracefully.\n" << std::flush;
                }
                else {
                    std::cerr << "\nClient: Receive error (in receiveMessages thread): " << WSAGetLastError() << "\n" << std::flush;
                }
            }
            break;
        }

        try {
            std::vector<unsigned char> decryptedData = aesCipher.decrypt(encryptedData);
            std::string receivedMessage(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());

            {
                std::lock_guard<std::mutex> lock(incoming_messages_mutex);
                incoming_messages_queue.push(receivedMessage);
            }
            incoming_messages_cv.notify_one();

        }
        catch (const CryptoPP::Exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "\nClient: Crypto++ Exception during message decryption (in receiveMessages thread): " << e.what() << "\n" << std::flush;
            break;
        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "\nClient: Standard Exception during message decryption (in receiveMessages thread): " << e.what() << "\n" << std::flush;
            break;
        }
    }
}

void printQueuedMessages() {
    while (!stop_threads) {
        std::unique_lock<std::mutex> lock(incoming_messages_mutex);
        incoming_messages_cv.wait(lock, [&] { return stop_threads || !incoming_messages_queue.empty(); });

        if (stop_threads && incoming_messages_queue.empty()) {
            break;
        }

        while (!incoming_messages_queue.empty()) {
            std::string message = incoming_messages_queue.front();
            incoming_messages_queue.pop();
            lock.unlock();

            {
                std::lock_guard<std::mutex> console_lock(console_mutex);
                std::cout << "\r" << std::string(80, ' ') << "\r";
                std::cout << message << "\n" << std::flush;
                std::cout << "Enter command: " << std::flush;
            }
            lock.lock();
        }
    }
}


int runClient(const std::string& ipAddress, const std::string& port, const std::string& username) {
    WSADATA wsaData;
    SOCKET clientSocket = INVALID_SOCKET;
    struct addrinfo* result = nullptr, * ptr = nullptr, hints;
    int iResult;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "Client: WSAStartup failed: " << iResult << "\n" << std::flush;
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo(ipAddress.c_str(), port.c_str(), &hints, &result);
    if (iResult != 0) {
        std::cerr << "Client: getaddrinfo failed: " << iResult << "\n" << std::flush;
        WSACleanup();
        return 1;
    }

    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        clientSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Client: socket failed with error: " << WSAGetLastError() << "\n" << std::flush;
            continue;
        }

        iResult = connect(clientSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(clientSocket);
            clientSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Client: Unable to connect to server!\n" << std::flush;
        WSACleanup();
        return 1;
    }

    std::cout << "Connected to server.\n" << std::flush;

    char pubkeyBuf[4096];
    int bytesReceived = recv(clientSocket, pubkeyBuf, sizeof(pubkeyBuf), 0);
    if (bytesReceived <= 0) {
        std::cerr << "Client: Failed to receive server public key. ";
        if (bytesReceived == 0) {
            std::cerr << "Server disconnected.\n";
        }
        else {
            std::cerr << "Error: " << WSAGetLastError() << "\n";
        }
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    std::string encodedPubKey(pubkeyBuf, bytesReceived);

    CryptoPP::RSA::PublicKey serverPublicKey;
    CryptoPP::ByteQueue queue;

    try {
        CryptoPP::StringSource ss(encodedPubKey, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::Redirector(queue)));

        if (queue.IsEmpty()) {
            std::cerr << "Client: Error: Decoded public key queue is empty. Server likely sent invalid or empty Base64 data.\n";
            closesocket(clientSocket);
            WSACleanup();
            return 1;
        }

        serverPublicKey.Load(queue);

        CryptoPP::AutoSeededRandomPool rng_validation;
        if (!serverPublicKey.Validate(rng_validation, 3)) {
            std::cerr << "Client: Warning: Loaded server public key failed internal validation. It might be corrupt or malformed.\n";
        }
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Client: Crypto++ Exception while decoding/loading server public key: " << e.what() << "\n";
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Client: Standard Exception while decoding/loading server public key: " << e.what() << "\n";
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    catch (...) {
        std::cerr << "Client: Unknown Exception while decoding/loading server public key.\n";
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    CryptoPP::AutoSeededRandomPool rng;
    std::vector<unsigned char> aesKey(32);
    rng.GenerateBlock(aesKey.data(), aesKey.size());

    std::vector<unsigned char> encryptedAESKey;
    try {
        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(serverPublicKey);

        if (aesKey.size() > encryptor.FixedMaxPlaintextLength()) {
            std::cerr << "Client: Error: AES key size (" << aesKey.size() << " bytes) is too large for RSA encryption with this public key and padding scheme. Max plaintext: " << encryptor.FixedMaxPlaintextLength() << " bytes.\n";
            closesocket(clientSocket);
            WSACleanup();
            return 1;
        }

        std::string temp_encrypted_aes_key_str;
        CryptoPP::StringSource ss2(aesKey.data(), aesKey.size(), true,
            new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                new CryptoPP::StringSink(temp_encrypted_aes_key_str)));

        encryptedAESKey.assign(temp_encrypted_aes_key_str.begin(), temp_encrypted_aes_key_str.end());

    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Client: Crypto++ Exception while encrypting AES key: " << e.what() << "\n";
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Client: Standard Exception while encrypting AES key: " << e.what() << "\n";
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    catch (...) {
        std::cerr << "Client: Unknown Exception while encrypting AES key.\n";
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    if (!send_message_with_length(clientSocket, encryptedAESKey)) {
        std::cerr << "Client: Failed to send encrypted AES key with length prefix. Error: " << WSAGetLastError() << "\n" << std::flush;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    SimpleAES aesCipher(aesKey);

    std::vector<unsigned char> encryptedUsername;
    try {
        encryptedUsername = aesCipher.encrypt(std::vector<unsigned char>(username.begin(), username.end()));
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Client: Crypto++ Exception while encrypting username: " << e.what() << "\n";
        closesocket(clientSocket); WSACleanup(); return 1;
    }

    if (!send_message_with_length(clientSocket, encryptedUsername)) {
        std::cerr << "Client: send username error (with length prefix): " << WSAGetLastError() << "\n" << std::flush;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    std::vector<unsigned char> encryptedWelcome = recv_message_with_length(clientSocket);

    if (encryptedWelcome.empty()) {
        if (WSAGetLastError() == 0) {
            std::cerr << "Client: Server disconnected during welcome message reception.\n" << std::flush;
        }
        else {
            std::cerr << "Client: recv welcome error (with length prefix): " << WSAGetLastError() << "\n" << std::flush;
        }
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    else {
        try {
            std::vector<unsigned char> decryptedWelcome = aesCipher.decrypt(encryptedWelcome);
            std::string welcomeMessage(reinterpret_cast<const char*>(decryptedWelcome.data()), decryptedWelcome.size());
            std::cout << welcomeMessage << "\n" << std::flush;
        }
        catch (const CryptoPP::Exception& e) {
            std::cerr << "Client: Crypto++ Exception while decrypting welcome message: " << e.what() << "\n";
            closesocket(clientSocket);
            WSACleanup();
            return 1;
        }
    }

    std::thread receiverThread(receiveMessages, clientSocket, std::cref(aesCipher));
    std::thread printerThread(printQueuedMessages);

    std::string command;
    while (true) {
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Enter command: " << std::flush;
        }

        std::getline(std::cin, command);

        if (std::cin.fail()) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Client: Input stream error detected. Clearing state.\n" << std::flush;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }

        if (command == "exit") {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Exiting client.\n" << std::flush;
            break;
        }

        std::vector<unsigned char> encryptedCommand;
        try {
            encryptedCommand = aesCipher.encrypt(std::vector<unsigned char>(command.begin(), command.end()));
        }
        catch (const CryptoPP::Exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Client: Crypto++ Exception while encrypting command: " << e.what() << "\n";
            break;
        }

        if (!send_message_with_length(clientSocket, encryptedCommand)) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Client: send error (with length prefix): " << WSAGetLastError() << "\n" << std::flush;
            break;
        }
    }

    stop_threads = true;
    incoming_messages_cv.notify_all();

    shutdown(clientSocket, SD_RECEIVE);

    if (receiverThread.joinable()) {
        receiverThread.join();
    }
    if (printerThread.joinable()) {
        printerThread.join();
    }

    int iResultShutdown = shutdown(clientSocket, SD_SEND);
    if (iResultShutdown == SOCKET_ERROR) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Client: shutdown send error: " << WSAGetLastError() << "\n" << std::flush;
    }

    closesocket(clientSocket);
    WSACleanup();
    return 0;
}