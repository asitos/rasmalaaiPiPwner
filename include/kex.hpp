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

inline std::vector<uint8_t> build_rsa_host_key() {
    std::string n_hex = "f1126449cf5910d460ee8f9d2d8be740571a065421edc4dd207d653b6288eaba3bb78f4802c14bd4da23af62369ae665d237ff64842cf003e09d7044a7dc76782f0a26baa473d12d1f6c7351b030c1c1ef413901d1dacafdfbffb8a57a04be05756b837c7a77d0b8fa4c276ec7b9c413ba4951aa6f8f37cd3052ffccd272e884dff1b21bbc22803d1e5f91a20804346e0d0b0feeeaae5c74db0c876e043954c176805bbc524effef7f14bde017f5192b340c9f08b6e63e6ea2732aba6fc297231c308f6a550319858ff0bae95153abd770c124500fd7b536970ddc4708feec4d1150da56d344f8aad592e8fff10da86cfa64995240d60974e561657c2ac593b9";
    std::vector<uint8_t> e_bytes = {0x01, 0x00, 0x01}; // 65537
    std::vector<uint8_t> n_bytes = hex_to_bytes(n_hex);

    std::vector<uint8_t> host_key;
    std::string type = "ssh-rsa";
    kex_write_string(host_key, std::vector<uint8_t>(type.begin(), type.end()));
    kex_write_mpint(host_key, e_bytes);
    kex_write_mpint(host_key, n_bytes);
    return host_key;
}

inline std::vector<uint8_t> rsa_sign_sha256(const std::vector<uint8_t>& data) {
    std::string n_hex = "f1126449cf5910d460ee8f9d2d8be740571a065421edc4dd207d653b6288eaba3bb78f4802c14bd4da23af62369ae665d237ff64842cf003e09d7044a7dc76782f0a26baa473d12d1f6c7351b030c1c1ef413901d1dacafdfbffb8a57a04be05756b837c7a77d0b8fa4c276ec7b9c413ba4951aa6f8f37cd3052ffccd272e884dff1b21bbc22803d1e5f91a20804346e0d0b0feeeaae5c74db0c876e043954c176805bbc524effef7f14bde017f5192b340c9f08b6e63e6ea2732aba6fc297231c308f6a550319858ff0bae95153abd770c124500fd7b536970ddc4708feec4d1150da56d344f8aad592e8fff10da86cfa64995240d60974e561657c2ac593b9";
    std::string d_hex = "1ddf529016e2898457b298173902a21845f2d29ff0485f61ab59fe865a526f0bbec4a33ba023c5bacd8128857a10bdc616439c211f83d60614fa4d64248cdc1d4e6eea97ac3331d36e9668bfd19e6914180ab3feb6bb6ef604190f0f6a4c5623a5063a97dd3125ab1651037de5bfee3d2793584c4f60a6e0854173b334ccca65172adb18358a61d084fd5444145c17519e9359ff02aa38ecd186e7fd0584f7bbf52220b463a00c050d5373084696f0c57081c1504c1d59648ae2534265f8bae23bb05cf6a95533f4f5991e8868a4d9a4f315baa57804e3c7b29315a5786dfd86a33d09b37f219900f8a51bbf11df82b102cac53fe2d121e9f9ba652c4f925c01";
    
    // FIX: SSH double-hashes the Exchange Hash. H is passed as 'data'. We hash it again here.
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

    while (raw_sig.size() < 256) {
        raw_sig.insert(raw_sig.begin(), 0x00);
    }
    
    return raw_sig;
}

inline std::vector<uint8_t> build_kexdh_reply(const std::string& v_c, const std::string& v_s, 
                                              const std::vector<uint8_t>& i_c, const std::vector<uint8_t>& i_s,
                                              const std::vector<uint8_t>& e, const std::vector<uint8_t>& f, 
                                              const std::vector<uint8_t>& K,
					      std::vector<uint8_t>& out_H) {
    std::vector<uint8_t> K_S = build_rsa_host_key();

    std::vector<uint8_t> h_buf;
    kex_write_string(h_buf, std::vector<uint8_t>(v_c.begin(), v_c.end()));
    kex_write_string(h_buf, std::vector<uint8_t>(v_s.begin(), v_s.end()));
    kex_write_string(h_buf, i_c);
    kex_write_string(h_buf, i_s);
    kex_write_string(h_buf, K_S);
    kex_write_mpint(h_buf, e);
    kex_write_mpint(h_buf, f);
    kex_write_mpint(h_buf, K);

    std::vector<uint8_t> H = kernel_sha256(h_buf);
    out_H = kernel_sha256(h_buf); // <-- ASSIGN IT HERE
    std::vector<uint8_t> signature_raw = rsa_sign_sha256(out_H); // <-- USE IT HERE

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
