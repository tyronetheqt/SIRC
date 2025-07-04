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
#include <string> // Keep for std::string
#include <random>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cctype>
#include <limits>
#include <string_view> // Keep if you use string_view elsewhere, but 'port' won't be one

#include <thread>
#include <mutex>
#include <map>
#include <queue>
#include <condition_variable> // Explicitly include for std::condition_variable

// Crypto++ includes (now fully consistent with your setup)
#include <aes.h>         // AES algorithm
#include <modes.h>       // Modes of operation (like CBC_Mode; might also define GCM_Mode or GCM)
#include <filters.h>     // Stream transformation filters
#include <osrng.h>       // AutoSeededRandomPool for IV generation
#include <base64.h>      // For RSA key exchange
#include <rsa.h>         // For RSA
#include <files.h>       // For key loading/saving if needed
#include <gcm.h>         // Explicitly include gcm.h - CRITICAL for GCM class definition
#include <hex.h>         // Potentially useful for debugging
#include <secblock.h>    // Corrected: For CryptoPP::SecByteBlock

inline std::mutex console_mutex;

inline std::queue<std::string> incoming_messages_queue;
inline std::mutex incoming_messages_mutex;
inline std::condition_variable incoming_messages_cv;

// --- REINSTATED 'port' as const std::string ---
constexpr std::string port_str = "12345"; // Helper string if needed for string_view
const std::string port = "12345"; // Reverted to const std::string for compatibility with existing functions

constexpr size_t BUF_SIZE = 4096; // Consistent type with std::min

// Max message size to prevent allocation attacks for incoming data
constexpr uint32_t MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10 MB limit, adjust as needed

#pragma comment(lib, "Ws2_32.lib")

// Define the GCM Tag size (standard is 16 bytes for AES-GCM)
const int GCM_TAG_SIZE = 16; // 128-bit tag

// --- REVISED SimpleAES CLASS ---
class SimpleAES {
private:
    CryptoPP::SecByteBlock key_; // Crypto++'s secure byte block for keys
    mutable CryptoPP::AutoSeededRandomPool prng_; // Add mutable for const encrypt method

public:
    // Constructor takes the AES key
    explicit SimpleAES(const std::vector<unsigned char>& key) : key_(key.data(), key.size()) {
        // Ensure key size is valid for AES-256 (32 bytes)
        // AES::MAX_KEYLENGTH is 32 bytes for 256-bit AES
        if (key_.size() != CryptoPP::AES::MAX_KEYLENGTH) {
            throw std::runtime_error("Invalid AES key length. Expected 32 bytes for AES-256.");
        }
    }

    // Encrypts plaintext using AES-256 GCM.
    // Returns a vector<unsigned char> containing:
    // [IV (AES::BLOCKSIZE bytes)] [Ciphertext] [Authentication Tag (GCM_TAG_SIZE bytes)]
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const {
        CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
        prng_.GenerateBlock(iv, iv.size()); // Generate a new random IV for each message

        std::string ciphertext_and_tag_str; // Will hold ciphertext + tag

        try {
            CryptoPP::GCM<CryptoPP::AES>::Encryption gcmEncryption;
            gcmEncryption.SetKeyWithIV(key_, key_.size(), iv, iv.size());

            CryptoPP::AuthenticatedEncryptionFilter ef(gcmEncryption,
                new CryptoPP::StringSink(ciphertext_and_tag_str),
                false, // Don't put "random" pad bytes (GCM is stream cipher, no padding)
                GCM_TAG_SIZE); // Specify the size of the authentication tag

            CryptoPP::StringSource ss(
                reinterpret_cast<const CryptoPP::byte*>(plaintext.data()),
                plaintext.size(),
                true, // Pump all data
                new CryptoPP::Redirector(ef) // Redirect output to the filter
            );
        }
        catch (const CryptoPP::Exception& e) {
            std::cerr << "AES GCM Encryption Error: " << e.what() << std::endl;
            throw; // Re-throw to caller
        }

        // Combine IV, ciphertext, and tag for transmission
        std::vector<unsigned char> result;
        result.reserve(iv.size() + ciphertext_and_tag_str.size()); // Pre-allocate for efficiency
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext_and_tag_str.begin(), ciphertext_and_tag_str.end());

        return result;
    }

    // Decrypts data (IV + Ciphertext + Tag) using AES-256 GCM.
    // Throws std::runtime_error if decryption/tag verification fails (data tampered with).
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& iv_ciphertext_tag) const {
        if (iv_ciphertext_tag.size() < CryptoPP::AES::BLOCKSIZE + GCM_TAG_SIZE) {
            throw std::runtime_error("Ciphertext too short to contain IV and GCM tag.");
        }

        // Extract IV (first AES::BLOCKSIZE bytes)
        CryptoPP::SecByteBlock iv(iv_ciphertext_tag.data(), CryptoPP::AES::BLOCKSIZE);

        // Extract Ciphertext and Tag (remaining bytes)
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
                true, // Pump all data
                new CryptoPP::Redirector(df) // Redirect output to the filter
            );

            // The AuthenticatedDecryptionFilter throws CryptoPP::HashVerificationFailed
            // if the GCM tag does not match. If no exception, it's verified.
        }
        catch (const CryptoPP::Exception& e) {
            std::cerr << "AES GCM Decryption/Verification failed: " << e.what() << std::endl;
            throw std::runtime_error(std::string("AES GCM Decryption/Verification failed: ") + e.what());
        }
        catch (const std::exception& e) {
            std::cerr << "Standard Exception during AES GCM Decryption: " << e.what() << std::endl;
            throw; // Re-throw any other standard exceptions
        }

        return std::vector<unsigned char>(decryptedtext_str.begin(), decryptedtext_str.end());
    }
};

// Converts a 32-bit unsigned integer to network byte order (big-endian)
inline std::vector<unsigned char> to_network_byte_order(uint32_t value) {
    std::vector<unsigned char> bytes(4);
    bytes[0] = static_cast<unsigned char>((value >> 24) & 0xFF);
    bytes[1] = static_cast<unsigned char>((value >> 16) & 0xFF);
    bytes[2] = static_cast<unsigned char>((value >> 8) & 0xFF);
    bytes[3] = static_cast<unsigned char>(value & 0xFF);
    return bytes;
}

// Converts a 32-bit unsigned integer from network byte order to host byte order
inline uint32_t from_network_byte_order(const unsigned char* bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 24) |
        (static_cast<uint32_t>(bytes[1]) << 16) |
        (static_cast<uint32_t>(bytes[2]) << 8) |
        static_cast<uint32_t>(bytes[3]);
}

// Function to send a message with a 4-byte length prefix
inline bool send_message_with_length(SOCKET sock, const std::vector<unsigned char>& data) {
    uint32_t len = static_cast<uint32_t>(data.size());

    // Check for excessively large messages to send
    if (len > MAX_MESSAGE_SIZE) {
        std::cerr << "Error: Attempted to send message of size " << len << " which exceeds MAX_MESSAGE_SIZE (" << MAX_MESSAGE_SIZE << ").\n";
        return false;
    }

    std::vector<unsigned char> len_bytes = to_network_byte_order(len);

    // Send length prefix
    int bytes_sent_len = send(sock, (char*)len_bytes.data(), len_bytes.size(), 0);
    if (bytes_sent_len == SOCKET_ERROR || bytes_sent_len != len_bytes.size()) {
        std::cerr << "Failed to send length prefix: " << WSAGetLastError() << "\n";
        return false;
    }

    // Send actual data
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

// Function to receive a message based on a 4-byte length prefix
inline std::vector<unsigned char> recv_message_with_length(SOCKET sock) {
    unsigned char len_buf[4];
    int bytes_received_len = 0;
    int current_recv_len = 0;

    // Receive length prefix (4 bytes)
    while (bytes_received_len < 4) {
        current_recv_len = recv(sock, (char*)len_buf + bytes_received_len, 4 - bytes_received_len, 0);
        if (current_recv_len <= 0) { // 0 means disconnect, <0 means error
            // Log if it's an error, but for graceful disconnect, just return empty
            if (current_recv_len < 0) {
                std::cerr << "Failed to receive length prefix: " << WSAGetLastError() << "\n";
            }
            return {}; // Return empty vector to indicate error/disconnect
        }
        bytes_received_len += current_recv_len;
    }

    uint32_t expected_data_len = from_network_byte_order(len_buf);

    if (expected_data_len == 0) {
        return {}; // Empty message
    }

    // Critical check: prevent huge allocations from malicious length prefixes
    if (expected_data_len > MAX_MESSAGE_SIZE) {
        std::cerr << "Error: Incoming message size (" << expected_data_len << ") exceeds MAX_MESSAGE_SIZE (" << MAX_MESSAGE_SIZE << "). Disconnecting.\n";
        // It's usually good to shut down the connection here as it indicates an attack
        // shutdown(sock, SD_BOTH);
        // closesocket(sock);
        return {};
    }

    std::vector<unsigned char> received_data;
    received_data.reserve(expected_data_len); // Pre-allocate memory

    size_t total_data_received = 0;
    char temp_buf[BUF_SIZE]; // Use BUF_SIZE for chunks

    while (total_data_received < expected_data_len) {
        size_t remaining_to_recv = expected_data_len - total_data_received;
        int to_recv = (int)std::min((size_t)BUF_SIZE, remaining_to_recv);

        int received_chunk = recv(sock, temp_buf, to_recv, 0);

        if (received_chunk <= 0) {
            if (received_chunk < 0) {
                std::cerr << "Failed to receive data chunk: " << WSAGetLastError() << "\n";
            }
            return {}; // Indicate error/disconnect
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