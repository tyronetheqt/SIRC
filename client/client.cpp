// client/client.cpp
#include "../common.h"
#include "client.h"
#include <boost/asio.hpp>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory> // For std::shared_ptr

// CryptoPP includes (already in common.h)
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

std::atomic<bool> stop_threads(false);

std::shared_ptr<SimpleAES> clientAesCipher_g;

void receiveMessages(std::shared_ptr<tcp::socket> socket_ptr) {
    while (!stop_threads && socket_ptr->is_open()) {
        std::vector<unsigned char> encryptedData = recv_message_with_length(*socket_ptr);

        if (encryptedData.empty()) {
            if (!stop_threads) {
                boost::system::error_code ec;
                socket_ptr->remote_endpoint(ec);
                if (ec == boost::asio::error::eof || ec == boost::asio::error::bad_descriptor) {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cerr << "\nClient: Server disconnected gracefully.\n" << std::flush;
                }
                else if (ec) {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cerr << "\nClient: Receive error (in receiveMessages thread): " << ec.message() << "\n" << std::flush;
                }
            }
            break;
        }

        if (!clientAesCipher_g) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "\nClient: Error: AES cipher not initialized for decryption (in receiveMessages thread).\n" << std::flush;
            break;
        }

        try {
            std::vector<unsigned char> decryptedData = clientAesCipher_g->decrypt(encryptedData);
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
    if (socket_ptr->is_open()) {
        boost::system::error_code ec;
        socket_ptr->shutdown(tcp::socket::shutdown_both, ec);
        socket_ptr->close(ec);
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

int runClient(const std::string& ipAddress, int port, const std::string& username) {
    asio::io_context io_context;
    std::shared_ptr<tcp::socket> socket_ptr = std::make_shared<tcp::socket>(io_context);
    int app_result = 0;

    std::thread receiverThread;
    std::thread printerThread;

    try {
        tcp::resolver resolver(io_context);
        asio::connect(*socket_ptr, resolver.resolve(ipAddress, std::to_string(port)));

        print_to_console(std::string("Connected to server: ") + socket_ptr->remote_endpoint().address().to_string() + ":" + std::to_string(socket_ptr->remote_endpoint().port()));

        asio::streambuf server_pubkey_buffer;
        boost::system::error_code error;
        asio::read_until(*socket_ptr, server_pubkey_buffer, '\n', error);

        if (error && error != asio::error::eof) {
            throw boost::system::system_error(error, "Error receiving server public key.");
        }
        std::string encodedPubKey((std::istreambuf_iterator<char>(&server_pubkey_buffer)), std::istreambuf_iterator<char>());
        if (!encodedPubKey.empty() && encodedPubKey.back() == '\n') {
            encodedPubKey.pop_back();
        }

        CryptoPP::RSA::PublicKey serverPublicKey;
        CryptoPP::ByteQueue queue;

        try {
            CryptoPP::StringSource ss(encodedPubKey, true,
                new CryptoPP::Base64Decoder(
                    new CryptoPP::Redirector(queue)));

            if (queue.IsEmpty()) {
                throw std::runtime_error("Decoded public key queue is empty. Server likely sent invalid or empty Base64 data.");
            }

            serverPublicKey.Load(queue);

            CryptoPP::AutoSeededRandomPool rng_validation;
            if (!serverPublicKey.Validate(rng_validation, 3)) {
                print_to_console("Client: Warning: Loaded server public key failed internal validation. It might be corrupt or malformed.");
            }
        }
        catch (const CryptoPP::Exception& e) {
            throw std::runtime_error(std::string("Crypto++ Exception while decoding/loading server public key: ") + e.what());
        }
        catch (const std::exception& e) {
            throw std::runtime_error(std::string("Standard Exception while decoding/loading server public key: ") + e.what());
        }
        catch (...) {
            throw std::runtime_error("Unknown Exception while decoding/loading server public key.");
        }

        CryptoPP::AutoSeededRandomPool rng;
        std::vector<unsigned char> aesKey(32);
        rng.GenerateBlock(aesKey.data(), aesKey.size());

        std::vector<unsigned char> encryptedAESKey;
        try {
            CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(serverPublicKey);

            if (aesKey.size() > encryptor.FixedMaxPlaintextLength()) {
                throw std::runtime_error(std::string("AES key size (") + std::to_string(aesKey.size()) + " bytes) is too large for RSA encryption with this public key and padding scheme. Max plaintext: " + std::to_string(encryptor.FixedMaxPlaintextLength()) + " bytes.");
            }

            std::string temp_encrypted_aes_key_str;
            CryptoPP::StringSource ss2(aesKey.data(), aesKey.size(), true,
                new CryptoPP::PK_EncryptorFilter(rng, encryptor,
                    new CryptoPP::StringSink(temp_encrypted_aes_key_str)));

            encryptedAESKey.assign(temp_encrypted_aes_key_str.begin(), temp_encrypted_aes_key_str.end());
        }
        catch (const CryptoPP::Exception& e) {
            throw std::runtime_error(std::string("Crypto++ Exception while encrypting AES key: ") + e.what());
        }
        catch (const std::exception& e) {
            throw std::runtime_error(std::string("Standard Exception while encrypting AES key: ") + e.what());
        }
        catch (...) {
            throw std::runtime_error("Unknown Exception while encrypting AES key.");
        }

        if (!send_message_with_length(*socket_ptr, encryptedAESKey)) {
            throw std::runtime_error("Failed to send encrypted AES key with length prefix.");
        }

        clientAesCipher_g = std::make_shared<SimpleAES>(aesKey);

        std::vector<unsigned char> encryptedUsername;
        try {
            encryptedUsername = clientAesCipher_g->encrypt(std::vector<unsigned char>(username.begin(), username.end()));
        }
        catch (const CryptoPP::Exception& e) {
            throw std::runtime_error(std::string("Crypto++ Exception while encrypting username: ") + e.what());
        }

        if (!send_message_with_length(*socket_ptr, encryptedUsername)) {
            throw std::runtime_error("Failed to send encrypted username with length prefix.");
        }

        std::vector<unsigned char> encryptedWelcome = recv_message_with_length(*socket_ptr);

        if (encryptedWelcome.empty()) {
            throw std::runtime_error("Failed to receive welcome message (ACK) from server or server disconnected.");
        }
        else {
            try {
                std::vector<unsigned char> decryptedWelcome = clientAesCipher_g->decrypt(encryptedWelcome);
                std::string welcomeMessage(reinterpret_cast<const char*>(decryptedWelcome.data()), decryptedWelcome.size());
                print_to_console(welcomeMessage);
            }
            catch (const CryptoPP::Exception& e) {
                throw std::runtime_error(std::string("Crypto++ Exception while decrypting welcome message: ") + e.what());
            }
        }

        receiverThread = std::thread(receiveMessages, socket_ptr);
        printerThread = std::thread(printQueuedMessages);

        std::string command;
        while (socket_ptr->is_open()) {
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
                if (!clientAesCipher_g) {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cerr << "Client: Error: AES cipher not initialized. Cannot send command.\n";
                    break;
                }
                encryptedCommand = clientAesCipher_g->encrypt(std::vector<unsigned char>(command.begin(), command.end()));
            }
            catch (const CryptoPP::Exception& e) {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "Client: Crypto++ Exception while encrypting command: " << e.what() << "\n";
                break;
            }

            if (!send_message_with_length(*socket_ptr, encryptedCommand)) {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cerr << "Client: send error (with length prefix).\n" << std::flush;
                break;
            }
        }

    }
    catch (const boost::system::system_error& e) {
        print_to_console(std::string("Client: Network Error: ") + e.what());
        app_result = 1;
    }
    catch (const std::exception& e) {
        print_to_console(std::string("Client: Application Error: ") + e.what());
        app_result = 1;
    }

    stop_threads = true;
    incoming_messages_cv.notify_all();

    boost::system::error_code ec_shutdown;
    if (socket_ptr->is_open()) {
        socket_ptr->shutdown(tcp::socket::shutdown_send, ec_shutdown);
    }

    if (printerThread.joinable()) {
        printerThread.join();
    }
    if (receiverThread.joinable()) {
        receiverThread.join();
    }

    boost::system::error_code ec_close;
    if (socket_ptr->is_open()) {
        socket_ptr->close(ec_close);
    }

    return app_result;
}
