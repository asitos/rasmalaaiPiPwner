#pragma once

#include "crypto.hpp"
#include <vector>
#include <cstdint>

struct SessionKeys {
    std::vector<uint8_t> iv_client_to_server;
    std::vector<uint8_t> iv_server_to_client;
    std::vector<uint8_t> key_client_to_server;
    std::vector<uint8_t> key_server_to_client;
    std::vector<uint8_t> mac_client_to_server;
    std::vector<uint8_t> mac_server_to_client;
};

// Helper to write mpint format specifically for key derivation
inline void cipher_write_mpint(std::vector<uint8_t>& buf, const std::vector<uint8_t>& val) {
    if (val.empty()) { 
        buf.push_back(0); buf.push_back(0); buf.push_back(0); buf.push_back(0); 
        return; 
    }
    if (val[0] & 0x80) { 
        buf.push_back(((val.size() + 1) >> 24) & 0xFF); buf.push_back(((val.size() + 1) >> 16) & 0xFF);
        buf.push_back(((val.size() + 1) >> 8) & 0xFF);  buf.push_back((val.size() + 1) & 0xFF);
        buf.push_back(0x00);
        buf.insert(buf.end(), val.begin(), val.end());
    } else {
        buf.push_back((val.size() >> 24) & 0xFF); buf.push_back((val.size() >> 16) & 0xFF);
        buf.push_back((val.size() >> 8) & 0xFF);  buf.push_back(val.size() & 0xFF);
        buf.insert(buf.end(), val.begin(), val.end());
    }
}

// Derives a single symmetric key based on the specific character identifier
inline std::vector<uint8_t> derive_key(const std::vector<uint8_t>& K, const std::vector<uint8_t>& H, char key_char, const std::vector<uint8_t>& session_id, size_t required_length) {
    std::vector<uint8_t> buf;
    
    // K (mpint)
    cipher_write_mpint(buf, K);
    // H (raw bytes)
    buf.insert(buf.end(), H.begin(), H.end());
    // Single character identifier ('A', 'B', 'C', etc.)
    buf.push_back(static_cast<uint8_t>(key_char));
    // Session ID (raw bytes, equals H for the initial exchange)
    buf.insert(buf.end(), session_id.begin(), session_id.end());

    std::vector<uint8_t> key = kernel_sha256(buf);
    
    // Truncate the 32-byte SHA-256 hash to the requested key/IV length (16 bytes for AES-128)
    if (key.size() > required_length) {
        key.resize(required_length);
    }
    return key;
}

// Generates all 6 session keys needed for the encrypted tunnel
inline SessionKeys generate_session_keys(const std::vector<uint8_t>& K, const std::vector<uint8_t>& H) {
    SessionKeys keys;
    // AES-128-CTR requires 16-byte keys and 16-byte IVs
    keys.iv_client_to_server = derive_key(K, H, 'A', H, 16);
    keys.iv_server_to_client = derive_key(K, H, 'B', H, 16);
    keys.key_client_to_server = derive_key(K, H, 'C', H, 16);
    keys.key_server_to_client = derive_key(K, H, 'D', H, 16);
    
    // HMAC-SHA2-256 requires 32-byte MAC keys
    keys.mac_client_to_server = derive_key(K, H, 'E', H, 32);
    keys.mac_server_to_client = derive_key(K, H, 'F', H, 32);
    
    return keys;
}
