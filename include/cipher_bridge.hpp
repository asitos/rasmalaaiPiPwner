#pragma once

#include <sys/socket.h>
#include <linux/if_alg.h>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <iostream>

class AesCtrEngine {
    int tfm_fd;
    std::vector<uint8_t> current_iv;
    
public:
    AesCtrEngine() : tfm_fd(-1) {}
    ~AesCtrEngine() { if (tfm_fd >= 0) close(tfm_fd); }
    
    bool init(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
        current_iv = iv;
        tfm_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (tfm_fd < 0) return false;
        
        struct sockaddr_alg salg{};
        salg.salg_family = AF_ALG;
        std::memcpy(salg.salg_type, "skcipher", 8);
        std::memcpy(salg.salg_name, "ctr(aes)", 8);
        
        if (bind(tfm_fd, (struct sockaddr*)&salg, sizeof(salg)) < 0) return false;
        if (setsockopt(tfm_fd, SOL_ALG, ALG_SET_KEY, key.data(), key.size()) < 0) return false;
        
        return true;
    }

    std::vector<uint8_t> process_blocks(const std::vector<uint8_t>& data, __u32 op_type) {
        if (tfm_fd < 0 || data.empty()) return {};
        
        int op_fd = accept(tfm_fd, nullptr, nullptr);
        if (op_fd < 0) return {};

        char cbuf[CMSG_SPACE(4) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16)];
        memset(cbuf, 0, sizeof(cbuf));
        
        struct msghdr msg{};
        struct iovec iov{};
        
        iov.iov_base = (void*)data.data();
        iov.iov_len = data.size();
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof(cbuf);
        
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_OP;
        cmsg->cmsg_len = CMSG_LEN(4);
        *(__u32*)CMSG_DATA(cmsg) = op_type;
        
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type = ALG_SET_IV;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 16);
        struct af_alg_iv* alg_iv = (struct af_alg_iv*)CMSG_DATA(cmsg);
        alg_iv->ivlen = 16;
        memcpy(alg_iv->iv, current_iv.data(), 16);
        
        if (sendmsg(op_fd, &msg, 0) < 0) {
            close(op_fd);
            return {};
        }
        
        std::vector<uint8_t> out_data(data.size());
        if (read(op_fd, out_data.data(), out_data.size()) < 0) {
            close(op_fd);
            return {};
        }
        close(op_fd);
        
        size_t blocks = data.size() / 16;
        for (size_t b = 0; b < blocks; ++b) {
            for (int i = 15; i >= 0; --i) {
                if (++current_iv[i] != 0) break;
            }
        }
        
        return out_data;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
        return process_blocks(ciphertext, ALG_OP_DECRYPT);
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
        return process_blocks(plaintext, ALG_OP_ENCRYPT);
    }
};

class HmacEngine {
    int tfm_fd;
public:
    HmacEngine() : tfm_fd(-1) {}
    ~HmacEngine() { if (tfm_fd >= 0) close(tfm_fd); }

    bool init(const std::vector<uint8_t>& mac_key) {
        tfm_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
        if (tfm_fd < 0) return false;

        struct sockaddr_alg salg{};
        salg.salg_family = AF_ALG;
        std::memcpy(salg.salg_type, "hash", 4);
        std::memcpy(salg.salg_name, "hmac(sha256)", 12);

        if (bind(tfm_fd, (struct sockaddr*)&salg, sizeof(salg)) < 0) return false;
        if (setsockopt(tfm_fd, SOL_ALG, ALG_SET_KEY, mac_key.data(), mac_key.size()) < 0) return false;
        return true;
    }

    std::vector<uint8_t> sign(uint32_t sequence_number, const std::vector<uint8_t>& unencrypted_packet) {
        int op_fd = accept(tfm_fd, nullptr, nullptr);
        if (op_fd < 0) return {};

        // FIX: Concatenate the sequence number and the payload into a single buffer
        std::vector<uint8_t> mac_buf;
        mac_buf.reserve(4 + unencrypted_packet.size());
        mac_buf.push_back((sequence_number >> 24) & 0xFF);
        mac_buf.push_back((sequence_number >> 16) & 0xFF);
        mac_buf.push_back((sequence_number >> 8) & 0xFF);
        mac_buf.push_back(sequence_number & 0xFF);
        mac_buf.insert(mac_buf.end(), unencrypted_packet.begin(), unencrypted_packet.end());

        // Execute a single write to bypass the MSG_MORE requirement
        if (write(op_fd, mac_buf.data(), mac_buf.size()) < 0) { close(op_fd); return {}; }

        std::vector<uint8_t> mac(32);
        if (read(op_fd, mac.data(), 32) < 0) { close(op_fd); return {}; }
        close(op_fd);

        return mac;
    }
};
