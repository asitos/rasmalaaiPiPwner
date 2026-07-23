#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>

class Config {
private:
    std::unordered_map<std::string, std::string> settings;

public:
    bool load(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) return false;

        std::string line;
        while (std::getline(file, line)) {
            // Ignore empty lines and comments
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;

            size_t delimiter_pos = line.find('=');
            if (delimiter_pos != std::string::npos) {
                std::string key = line.substr(0, delimiter_pos);
                std::string value = line.substr(delimiter_pos + 1);
                
                // Basic trim for carriage returns (\r) if edited on Windows
                if (!value.empty() && value.back() == '\r') value.pop_back();
                
                settings[key] = value;
            }
        }
        return true;
    }

    std::string get(const std::string& key, const std::string& default_value = "") const {
        auto it = settings.find(key);
        if (it != settings.end()) {
            return it->second;
        }
        return default_value;
    }
};
