#pragma once

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

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

#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <osrng.h>
#include <base64.h>
#include <rsa.h>
#include <files.h>
#include <gcm.h>
#include <hex.h>
#include <secblock.h>
#include <eccrypto.h>
#include <oids.h>
#include <hkdf.h>
#include <sha.h>

inline std::mutex console_mutex;

inline std::queue<std::string> incoming_messages_queue;
inline std::mutex incoming_messages_mutex;
inline std::condition_variable incoming_messages_cv;

constexpr std::string port_str = "12345";
const std::string port = "12345";

constexpr size_t BUF_SIZE = 4096;

constexpr uint32_t MAX_MESSAGE_SIZE = 1397969993;

#pragma comment(lib, "Ws2_32.lib")

const int GCM_TAG_SIZE = 16;

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
            std::cerr << "AES GCM Decryption/Verification failed: " << e.what() << std::endl;
            throw std::runtime_error(std::string("AES GCM Decryption/Verification failed: ") + e.what());
        }
        catch (const std::exception& e) {
            std::cerr << "Standard Exception during AES GCM Decryption: " << e.what() << std::endl;
            throw;
        }

        return std::vector<unsigned char>(decryptedtext_str.begin(), decryptedtext_str.end());
    }
};

inline std::vector<unsigned char> to_network_byte_order(uint32_t value) {
    std::vector<unsigned char> bytes(4);
    bytes[0] = static_cast<unsigned char>((value >> 24) & 0xFF);
    bytes[1] = static_cast<unsigned char>((value >> 16) & 0xFF);
    bytes[2] = static_cast<unsigned char>((value >> 8) & 0xFF);
    bytes[3] = static_cast<unsigned char>(value & 0xFF);
    return bytes;
}

inline uint32_t from_network_byte_order(const unsigned char* bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 24) |
        (static_cast<uint32_t>(bytes[1]) << 16) |
        (static_cast<uint32_t>(bytes[2]) << 8) |
        static_cast<uint32_t>(bytes[3]);
}

inline bool send_message_with_length(SOCKET sock, const std::vector<unsigned char>& data) {
    uint32_t len = static_cast<uint32_t>(data.size());

    if (len > MAX_MESSAGE_SIZE) {
        std::cerr << "Error: Attempted to send message of size " << len << " which exceeds MAX_MESSAGE_SIZE (" << MAX_MESSAGE_SIZE << ").\n";
        return false;
    }

    std::vector<unsigned char> len_bytes = to_network_byte_order(len);

    int bytes_sent_len = send(sock, (char*)len_bytes.data(), len_bytes.size(), 0);
    if (bytes_sent_len == SOCKET_ERROR || bytes_sent_len != len_bytes.size()) {
        std::cerr << "Failed to send length prefix: " << WSAGetLastError() << "\n";
        return false;
    }

    size_t total_data_sent = 0;
    while (total_data_sent < len) {
        int sent = send(sock, (char*)data.data() + total_data_sent, (int)(len - total_data_sent), 0);
        if (sent == SOCKET_ERROR) {
            std::cerr << "Failed to send data: " << WSAGetLastError() << "\n";
            return false;
        }
        total_data_sent += sent;
    }
    return true;
}

inline std::vector<unsigned char> recv_message_with_length(SOCKET sock) {
    unsigned char len_buf[4];
    int bytes_received_len = 0;
    int current_recv_len = 0;

    while (bytes_received_len < 4) {
        current_recv_len = recv(sock, (char*)len_buf + bytes_received_len, 4 - bytes_received_len, 0);
        if (current_recv_len <= 0) {
            if (current_recv_len < 0) {
                std::cerr << "Failed to receive length prefix: " << WSAGetLastError() << "\n";
            }
            return {};
        }
        bytes_received_len += current_recv_len;
    }

    uint32_t expected_data_len = from_network_byte_order(len_buf);

    if (expected_data_len == 0) {
        return {};
    }

    if (expected_data_len > MAX_MESSAGE_SIZE) {
        std::cerr << "Error: Incoming message size (" << expected_data_len << ") exceeds MAX_MESSAGE_SIZE (" << MAX_MESSAGE_SIZE << "). Disconnecting.\n";
        return {};
    }

    std::vector<unsigned char> received_data;
    received_data.reserve(expected_data_len);

    size_t total_data_received = 0;
    char temp_buf[BUF_SIZE];

    while (total_data_received < expected_data_len) {
        size_t remaining_to_recv = expected_data_len - total_data_received;
        int to_recv = (int)std::min((size_t)BUF_SIZE, remaining_to_recv);

        int received_chunk = recv(sock, temp_buf, to_recv, 0);

        if (received_chunk <= 0) {
            if (received_chunk < 0) {
                std::cerr << "Failed to receive data chunk: " << WSAGetLastError() << "\n";
            }
            return {};
        }
        received_data.insert(received_data.end(), temp_buf, temp_buf + received_chunk);
        total_data_received += received_chunk;
    }
    return received_data;
}

inline std::vector<unsigned char> generateRandomKey(size_t length) {
    std::vector<unsigned char> key(length);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key.data(), key.size());
    return key;
}