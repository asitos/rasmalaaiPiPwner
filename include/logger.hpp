#pragma once

#include <sqlite3.h>
#include <string>
#include <iostream>
#include <fstream>

class DatabaseLogger {
private:
    sqlite3* db;

    // helper to sanitize malicious quotes/slashes from bot passwords
    std::string escape_json(const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\b') out += "\\b";
            else if (c == '\f') out += "\\f";
            else if (c == '\n') out += "\\n";
            else if (c == '\r') out += "\\r";
            else if (c == '\t') out += "\\t";
            else if (static_cast<unsigned char>(c) <= 0x1f) continue; // strip control chars
            else out += c;
        }
        return out;
    }

    // dumps the entire sqlite db into a flat json array
    void export_to_json() {
        if (!db) return;
        const char* query = "SELECT id, ip_address, username, password, timestamp FROM captures ORDER BY timestamp DESC;";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) return;

        std::string json = "[\n";
        bool first = true;
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json += ",\n";
            first = false;
            
            json += "  {\n";
            json += "    \"id\": " + std::to_string(sqlite3_column_int(stmt, 0)) + ",\n";
            json += "    \"ip\": \"" + escape_json(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))) + "\",\n";
            json += "    \"username\": \"" + escape_json(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))) + "\",\n";
            json += "    \"password\": \"" + escape_json(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))) + "\",\n";
            json += "    \"timestamp\": \"" + escape_json(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))) + "\"\n";
            json += "  }";
        }
        json += "\n]\n";
        sqlite3_finalize(stmt);

        // write to file in the project root
        std::ofstream out("captures.json");
        if (out.is_open()) {
            out << json;
            out.close();
        }
    }

public:
    DatabaseLogger() : db(nullptr) {}
    ~DatabaseLogger() { if (db) sqlite3_close(db); }

    bool init(const std::string& db_file) {
        if (sqlite3_open(db_file.c_str(), &db) != SQLITE_OK) {
            std::cerr << "[-] Failed to open database: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        const char* create_table_sql = 
            "CREATE TABLE IF NOT EXISTS captures ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ip_address TEXT, "
            "username TEXT, "
            "password TEXT, "
            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);";

        char* err_msg = nullptr;
        if (sqlite3_exec(db, create_table_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
            std::cerr << "[-] Failed to create table: " << err_msg << std::endl;
            sqlite3_free(err_msg);
            return false;
        }
        
        export_to_json();
        return true;
    }

    void log_credential(const std::string& ip, const std::string& username, const std::string& password) {
        if (!db) return;

        const char* insert_sql = "INSERT INTO captures (ip_address, username, password) VALUES (?, ?, ?);";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, password.c_str(), -1, SQLITE_TRANSIENT);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                std::cerr << "[-] Failed to insert record: " << sqlite3_errmsg(db) << std::endl;
            }
            sqlite3_finalize(stmt);
            
            // instantly update the json file whenever a new trap is triggered
            export_to_json();
        }
    }
};
