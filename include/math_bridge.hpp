#pragma once

#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cstdio>
#include <memory>
#include <array>

// Converts raw bytes to a "0x..." hex string
inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << "0x";
    for (uint8_t b : bytes) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (int)b;
    }
    return ss.str();
}

// Converts a hex string back to raw bytes
inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::string h = hex;
    if (h.substr(0, 2) == "0x") h = h.substr(2);
    if (h.length() % 2 != 0) h = "0" + h; // Pad if odd length
    
    for (size_t i = 0; i < h.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

// Custom deleter to satisfy GCC attribute strictness on pclose
struct PipeDeleter {
    void operator()(FILE* fp) const {
        if (fp) {
            pclose(fp);
        }
    }
};

// Abuses POSIX pipes and python3 to calculate (base^exp) % mod
inline std::vector<uint8_t> math_mod_exp(const std::vector<uint8_t>& base,
                                         const std::vector<uint8_t>& exp,
                                         const std::vector<uint8_t>& mod) {
    std::string b_hex = bytes_to_hex(base);
    std::string e_hex = bytes_to_hex(exp);
    std::string m_hex = bytes_to_hex(mod);

    // Build the shell command
    std::string cmd = "python3 -c 'print(hex(pow(" + b_hex + ", " + e_hex + ", " + m_hex + ")))'";

    std::array<char, 2048> buffer;
    std::string result;
    
    // Execute and read stdout using the custom struct deleter
    std::unique_ptr<FILE, PipeDeleter> pipe(popen(cmd.c_str(), "r"));
    if (!pipe) return {};
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    if (!result.empty() && result.back() == '\n') result.pop_back();

    return hex_to_bytes(result);
}
