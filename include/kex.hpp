#pragma once

#include "crypto.hpp"
#include "math_bridge.hpp"
#include <vector>
#include <string>
#include <cstdint>

inline void kex_write_uint32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back((val >> 24) & 0xFF); buf.push_back((val >> 16) & 0xFF);
    buf.push_back((val >> 8) & 0xFF);  buf.push_back(val & 0xFF);
}

inline void kex_write_string(std::vector<uint8_t>& buf, const std::vector<uint8_t>& str) {
    kex_write_uint32(buf, str.size());
    buf.insert(buf.end(), str.begin(), str.end());
}

inline void kex_write_mpint(std::vector<uint8_t>& buf, const std::vector<uint8_t>& val) {
    if (val.empty()) { kex_write_uint32(buf, 0); return; }
    if (val[0] & 0x80) { 
        kex_write_uint32(buf, val.size() + 1);
        buf.push_back(0x00);
        buf.insert(buf.end(), val.begin(), val.end());
    } else {
        kex_write_uint32(buf, val.size());
        buf.insert(buf.end(), val.begin(), val.end());
    }
}

// DYNAMIC UPDATE: Pass RSA_N directly from config
inline std::vector<uint8_t> build_rsa_host_key(const std::string& n_hex) {
    std::vector<uint8_t> e_bytes = {0x01, 0x00, 0x01}; // 65537
    std::vector<uint8_t> n_bytes = hex_to_bytes(n_hex);

    std::vector<uint8_t> host_key;
    std::string type = "ssh-rsa";
    kex_write_string(host_key, std::vector<uint8_t>(type.begin(), type.end()));
    kex_write_mpint(host_key, e_bytes);
    kex_write_mpint(host_key, n_bytes);
    return host_key;
}

// DYNAMIC UPDATE: Pass RSA_N and RSA_D directly from config
inline std::vector<uint8_t> rsa_sign_sha256(const std::vector<uint8_t>& data, const std::string& n_hex, const std::string& d_hex) {
    std::vector<uint8_t> double_digest = kernel_sha256(data);
    std::vector<uint8_t> asn1 = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    
    std::vector<uint8_t> padded;
    padded.push_back(0x00);
    padded.push_back(0x01);
    for (int i = 0; i < 202; ++i) padded.push_back(0xFF);
    padded.push_back(0x00);
    padded.insert(padded.end(), asn1.begin(), asn1.end());
    padded.insert(padded.end(), double_digest.begin(), double_digest.end());

    std::vector<uint8_t> raw_sig = math_mod_exp(padded, hex_to_bytes(d_hex), hex_to_bytes(n_hex));
    while (raw_sig.size() < 256) raw_sig.insert(raw_sig.begin(), 0x00);
    return raw_sig;
}

// DYNAMIC UPDATE: Passing config keys down the chain
inline std::vector<uint8_t> build_kexdh_reply(const std::string& v_c, const std::string& v_s, 
                                              const std::vector<uint8_t>& i_c, const std::vector<uint8_t>& i_s,
                                              const std::vector<uint8_t>& e, const std::vector<uint8_t>& f, 
                                              const std::vector<uint8_t>& K,
                                              std::vector<uint8_t>& out_H,
                                              const std::string& rsa_n, const std::string& rsa_d) {
    std::vector<uint8_t> K_S = build_rsa_host_key(rsa_n);

    std::vector<uint8_t> h_buf;
    kex_write_string(h_buf, std::vector<uint8_t>(v_c.begin(), v_c.end()));
    kex_write_string(h_buf, std::vector<uint8_t>(v_s.begin(), v_s.end()));
    kex_write_string(h_buf, i_c);
    kex_write_string(h_buf, i_s);
    kex_write_string(h_buf, K_S);
    kex_write_mpint(h_buf, e);
    kex_write_mpint(h_buf, f);
    kex_write_mpint(h_buf, K);

    out_H = kernel_sha256(h_buf);
    std::vector<uint8_t> signature_raw = rsa_sign_sha256(out_H, rsa_n, rsa_d);
    
    std::vector<uint8_t> sig_blob;
    std::string sig_alg = "rsa-sha2-256";
    kex_write_string(sig_blob, std::vector<uint8_t>(sig_alg.begin(), sig_alg.end()));
    kex_write_string(sig_blob, signature_raw);

    std::vector<uint8_t> reply;
    reply.push_back(31); 
    kex_write_string(reply, K_S);
    kex_write_mpint(reply, f);
    kex_write_string(reply, sig_blob);

    return reply;
}
