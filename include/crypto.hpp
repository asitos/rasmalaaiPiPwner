#pragma once

#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <cstdint>

#ifndef AF_ALG
#define AF_ALG 38
#endif

// Abuses the Linux kernel's AF_ALG socket API to calculate SHA-256 without OpenSSL
inline std::vector<uint8_t> kernel_sha256(const std::vector<uint8_t>& data) {
    // 1. Open a seqpacket socket to the kernel crypto API
    int tfm_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfm_fd < 0) {
        std::cerr << "[-] AF_ALG socket failed. Kernel crypto API unavailable." << std::endl;
        return {};
    }

    // 2. Bind to the specific hash algorithm
    struct sockaddr_alg salg{};
    salg.salg_family = AF_ALG;
    std::memcpy(salg.salg_type, "hash", 4);
    std::memcpy(salg.salg_name, "sha256", 6);

    if (bind(tfm_fd, reinterpret_cast<struct sockaddr*>(&salg), sizeof(salg)) < 0) {
        std::cerr << "[-] AF_ALG bind to sha256 failed." << std::endl;
        close(tfm_fd);
        return {};
    }

    // 3. Accept gives us an operational file descriptor to stream data into
    int op_fd = accept(tfm_fd, nullptr, nullptr);
    if (op_fd < 0) {
        std::cerr << "[-] AF_ALG accept failed." << std::endl;
        close(tfm_fd);
        return {};
    }

    // 4. Write the raw bytes into the kernel
    if (write(op_fd, data.data(), data.size()) < 0) {
        std::cerr << "[-] AF_ALG write failed." << std::endl;
    }

    // 5. Read the 32-byte digest back from the kernel
    std::vector<uint8_t> hash(32);
    if (read(op_fd, hash.data(), 32) < 0) {
        std::cerr << "[-] AF_ALG read failed." << std::endl;
    }

    close(op_fd);
    close(tfm_fd);
    
    return hash;
}
