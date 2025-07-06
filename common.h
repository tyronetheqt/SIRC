// common.h
#ifndef COMMON_H
#define COMMON_H

// Standard library includes
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cctype>
#include <limits>
#include <string_view>
#include <thread>
#include <mutex>
#include <map>
#include <queue>
#include <condition_variable>
#include <memory>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>

#include <boost/asio.hpp>
#include <boost/asio/ts/buffer.hpp>
#include <boost/asio/ts/internet.hpp>
#include <boost/asio/detail/socket_ops.hpp>

extern std::mutex console_mutex;

extern std::queue<std::string> incoming_messages_queue;
extern std::mutex incoming_messages_mutex;
extern std::condition_variable incoming_messages_cv;

const int port = 12345;

constexpr size_t BUF_SIZE = 4096;

// Maximum message size
constexpr uint32_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024;

const int GCM_TAG_SIZE = 16;

inline void print_to_console(const std::string& message) {
    std::lock_guard<std::mutex> lock(console_mutex);
    std::cout << message << std::endl;
}

class SimpleAES {
private:
    CryptoPP::SecByteBlock key_;
    mutable CryptoPP::AutoSeededRandomPool prng_;

public:
    explicit SimpleAES(const std::vector<unsigned char>& key) : key_(key.data(), key.size()) {
        if (key_.size() != CryptoPP::AES::MAX_KEYLENGTH) {
            throw std::runtime_error("Invalid AES key length. Expected 32 bytes for AES-256.");
        }
    }

    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const {
        CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
        prng_.GenerateBlock(iv, iv.size());

        std::string ciphertext_and_tag_str;

        try {
            CryptoPP::GCM<CryptoPP::AES>::Encryption gcmEncryption;
            gcmEncryption.SetKeyWithIV(key_, key_.size(), iv, iv.size());

            CryptoPP::AuthenticatedEncryptionFilter ef(gcmEncryption,
                new CryptoPP::StringSink(ciphertext_and_tag_str),
                false,
                GCM_TAG_SIZE);

            CryptoPP::StringSource ss(
                reinterpret_cast<const CryptoPP::byte*>(plaintext.data()),
                plaintext.size(),
                true,
                new CryptoPP::Redirector(ef)
            );
        }
        catch (const CryptoPP::Exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "AES GCM Encryption Error: " << e.what() << std::endl;
            throw;
        }

        std::vector<unsigned char> result;
        result.reserve(iv.size() + ciphertext_and_tag_str.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext_and_tag_str.begin(), ciphertext_and_tag_str.end());

        return result;
    }

    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& iv_ciphertext_tag) const {
        if (iv_ciphertext_tag.size() < CryptoPP::AES::BLOCKSIZE + GCM_TAG_SIZE) {
            throw std::runtime_error("Ciphertext too short to contain IV and GCM tag.");
        }

        CryptoPP::SecByteBlock iv(iv_ciphertext_tag.data(), CryptoPP::AES::BLOCKSIZE);

        const CryptoPP::byte* ciphertext_start = iv_ciphertext_tag.data() + CryptoPP::AES::BLOCKSIZE;
        size_t ciphertext_and_tag_len = iv_ciphertext_tag.size() - CryptoPP::AES::BLOCKSIZE;

        std::string decryptedtext_str;

        try {
            CryptoPP::GCM<CryptoPP::AES>::Decryption gcmDecryption;
            gcmDecryption.SetKeyWithIV(key_, key_.size(), iv, iv.size());

            CryptoPP::AuthenticatedDecryptionFilter df(gcmDecryption,
                new CryptoPP::StringSink(decryptedtext_str),
                CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                GCM_TAG_SIZE);

            CryptoPP::StringSource ss(
                ciphertext_start,
                ciphertext_and_tag_len,
                true,
                new CryptoPP::Redirector(df)
            );
        }
        catch (const CryptoPP::Exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "AES GCM Decryption/Verification failed: " << e.what() << std::endl;
            throw std::runtime_error(std::string("AES GCM Decryption/Verification failed: ") + e.what());
        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Standard Exception during AES GCM Decryption: " << e.what() << std::endl;
            throw;
        }

        return std::vector<unsigned char>(decryptedtext_str.begin(), decryptedtext_str.end());
    }
};

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

inline bool send_message_with_length(tcp::socket& socket, const std::vector<unsigned char>& data) {
    uint32_t len = static_cast<uint32_t>(data.size());

    if (len > MAX_MESSAGE_SIZE) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Error: Attempted to send message of size " << len << " which exceeds MAX_MESSAGE_SIZE (" << MAX_MESSAGE_SIZE << ").\n";
        return false;
    }

    try {
        uint32_t network_length = asio::detail::socket_ops::host_to_network_long(len);
        asio::write(socket, asio::buffer(&network_length, sizeof(network_length)));

        asio::write(socket, asio::buffer(data));
        return true;
    }
    catch (const boost::system::system_error& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Network Error (send_message_with_length): " << e.what() << std::endl;
        return false;
    }
}

inline std::vector<unsigned char> recv_message_with_length(tcp::socket& socket) {
    try {
        uint32_t network_length;
        asio::read(socket, asio::buffer(&network_length, sizeof(network_length)));
        uint32_t length = asio::detail::socket_ops::network_to_host_long(network_length);

        if (length == 0) {
            return {};
        }

        if (length > MAX_MESSAGE_SIZE) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Error: Incoming message size (" << length << ") exceeds MAX_MESSAGE_SIZE (" << MAX_MESSAGE_SIZE << "). Disconnecting.\n";
            return {};
        }

        std::vector<unsigned char> data(length);
        asio::read(socket, asio::buffer(data));
        return data;
    }
    catch (const boost::system::system_error& e) {
        if (e.code() == asio::error::eof) {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << "Network Info (recv_message_with_length): Peer disconnected gracefully." << std::endl;
        }
        else {
            std::lock_guard<std::mutex> lock(console_mutex);
            std::cerr << "Network Error (recv_message_with_length): " << e.what() << std::endl;
        }
        return {};
    }
}

inline std::vector<unsigned char> generateRandomKey(size_t length) {
    std::vector<unsigned char> key(length);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key.data(), key.size());
    return key;
}

#endif
