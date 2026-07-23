#include "crypto.hpp"
#include "math_bridge.hpp"
#include "kex.hpp"
#include "cipher.hpp"
#include "cipher_bridge.hpp"
#include "config.hpp"
#include "logger.hpp"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <random>
#include <unordered_map>
#include <memory>
#include <sys/epoll.h>

#define MAX_EVENTS 64
#define SSH_MSG_KEXINIT 20

enum SessionState {
    STATE_WAIT_CLIENT_BANNER,
    STATE_WAIT_CLIENT_KEXINIT,
    STATE_WAIT_NEWKEYS,
    STATE_ENCRYPTED
};

struct ClientSession {
    int fd;
    std::string ip_address; // To log to DB
    SessionState state;
    std::string rx_text_buffer;
    std::vector<uint8_t> rx_binary_buffer;
    std::string v_c;
    std::vector<uint8_t> i_s; 
    std::vector<uint8_t> i_c;
    
    std::shared_ptr<AesCtrEngine> rx_cipher;
    std::shared_ptr<AesCtrEngine> tx_cipher;
    std::shared_ptr<HmacEngine> rx_mac;
    std::shared_ptr<HmacEngine> tx_mac;
    
    uint32_t rx_seq = 0;
    uint32_t tx_seq = 0;

    bool reading_first_block = true;
    uint32_t expected_encrypted_bytes = 0;
    std::vector<uint8_t> current_plaintext;
};

void write_uint32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back((val >> 24) & 0xFF); buf.push_back((val >> 16) & 0xFF);
    buf.push_back((val >> 8) & 0xFF);  buf.push_back(val & 0xFF);
}

void write_ssh_string(std::vector<uint8_t>& buf, const std::string& str) {
    write_uint32(buf, str.length());
    buf.insert(buf.end(), str.begin(), str.end());
}

std::vector<uint8_t> wrap_in_binary_packet(const std::vector<uint8_t>& payload) {
    uint32_t payload_len = payload.size();
    uint8_t padding_len = 8 - ((5 + payload_len) % 8);
    if (padding_len < 4) padding_len += 8;
    
    uint32_t packet_length = 1 + payload_len + padding_len;
    std::vector<uint8_t> packet;
    write_uint32(packet, packet_length);
    packet.push_back(padding_len);
    packet.insert(packet.end(), payload.begin(), payload.end());

    std::random_device rd;
    for (int i = 0; i < padding_len; ++i) packet.push_back(static_cast<uint8_t>(rd() % 256));
    return packet;
}

std::vector<uint8_t> build_encrypted_packet(const std::vector<uint8_t>& payload, 
                                            std::shared_ptr<AesCtrEngine>& cipher, 
                                            std::shared_ptr<HmacEngine>& mac_engine, 
                                            uint32_t& seq_no) {
    uint32_t payload_len = payload.size();
    uint8_t padding_len = 16 - ((5 + payload_len) % 16);
    if (padding_len < 4) padding_len += 16;
    
    uint32_t packet_length = 1 + payload_len + padding_len;
    
    std::vector<uint8_t> unencrypted_packet;
    write_uint32(unencrypted_packet, packet_length);
    unencrypted_packet.push_back(padding_len);
    unencrypted_packet.insert(unencrypted_packet.end(), payload.begin(), payload.end());
    
    std::random_device rd;
    for (int i = 0; i < padding_len; ++i) unencrypted_packet.push_back(static_cast<uint8_t>(rd() % 256));
    
    std::vector<uint8_t> mac = mac_engine->sign(seq_no, unencrypted_packet);
    std::vector<uint8_t> encrypted = cipher->encrypt(unencrypted_packet);
    encrypted.insert(encrypted.end(), mac.begin(), mac.end());
    seq_no++;
    return encrypted;
}

std::vector<uint8_t> build_server_kexinit() {
    std::vector<uint8_t> payload;
    payload.push_back(SSH_MSG_KEXINIT);
    std::random_device rd;
    for (int i = 0; i < 16; ++i) payload.push_back(static_cast<uint8_t>(rd() % 256));

    write_ssh_string(payload, "diffie-hellman-group14-sha256");
    write_ssh_string(payload, "rsa-sha2-256");
    write_ssh_string(payload, "aes128-ctr");
    write_ssh_string(payload, "aes128-ctr");
    write_ssh_string(payload, "hmac-sha2-256");
    write_ssh_string(payload, "hmac-sha2-256");
    write_ssh_string(payload, "none");
    write_ssh_string(payload, "none");
    write_ssh_string(payload, "");
    write_ssh_string(payload, "");
    payload.push_back(0);
    write_uint32(payload, 0);
    return payload;
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    // 1. Boot Subsystems
    Config config;
    if (!config.load("config.ini")) {
        std::cerr << "[-] Missing config.ini. Aborting." << std::endl;
        return 1;
    }

    DatabaseLogger db;
    if (!db.init("captures.db")) {
        std::cerr << "[-] Database init failed. Aborting." << std::endl;
        return 1;
    }

    int port = std::stoi(config.get("PORT", "2222"));
    std::string banner = config.get("BANNER", "SSH-2.0-Default") + "\r\n";
    std::string rsa_n = config.get("RSA_N");
    std::string rsa_d = config.get("RSA_D");

    std::cout << "[+] Config Loaded. Port: " << port << std::endl;
    std::cout << "[+] Database Online: captures.db" << std::endl;

    // 2. Setup Socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    set_nonblocking(server_fd);

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    bind(server_fd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address));
    listen(server_fd, SOMAXCONN);

    int epoll_fd = epoll_create1(0);
    struct epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    std::unordered_map<int, ClientSession> sessions;
    std::cout << "[+] State Engine active. Awaiting targets..." << std::endl;
    struct epoll_event events[MAX_EVENTS];

    while (true) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; ++i) {
            int current_fd = events[i].data.fd;

            if (current_fd == server_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
                if (client_fd < 0) continue;

                // Extract IP for database logging
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);

                set_nonblocking(client_fd);
                send(client_fd, banner.c_str(), banner.length(), 0);

                sessions[client_fd] = ClientSession{client_fd, std::string(ip_str), STATE_WAIT_CLIENT_BANNER, "", {}, "", {}, {}, nullptr, nullptr, nullptr, nullptr, 0, 0, true, 0, {}};
                
                struct epoll_event client_ev{};
                client_ev.events = EPOLLIN | EPOLLET;
                client_ev.data.fd = client_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev);
                std::cout << "[+] Target Connected: " << ip_str << std::endl;
                
            } else {
                auto& session = sessions[current_fd];
                char read_buf[2048];
                ssize_t bytes_read = read(current_fd, read_buf, sizeof(read_buf));

                if (bytes_read > 0) {
                    if (session.state == STATE_WAIT_CLIENT_BANNER) {
                        session.rx_text_buffer.append(read_buf, bytes_read);
                    } else {
                        session.rx_binary_buffer.insert(session.rx_binary_buffer.end(), read_buf, read_buf + bytes_read);
                    }

                    if (session.state == STATE_WAIT_CLIENT_BANNER) {
                        size_t newline_pos = session.rx_text_buffer.find('\n');
                        if (newline_pos != std::string::npos) {
                            session.v_c = session.rx_text_buffer.substr(0, newline_pos);
                            if (!session.v_c.empty() && session.v_c.back() == '\r') session.v_c.pop_back();

                            session.state = STATE_WAIT_CLIENT_KEXINIT;
                            session.i_s = build_server_kexinit();
                            std::vector<uint8_t> kex_packet = wrap_in_binary_packet(session.i_s);
                            send(current_fd, kex_packet.data(), kex_packet.size(), 0);
                        }
                    } 
                    
                    if (session.state == STATE_WAIT_CLIENT_KEXINIT) {
                        while (session.rx_binary_buffer.size() >= 4) {
                            uint32_t pkt_len = (static_cast<uint8_t>(session.rx_binary_buffer[0]) << 24) |
                                               (static_cast<uint8_t>(session.rx_binary_buffer[1]) << 16) |
                                               (static_cast<uint8_t>(session.rx_binary_buffer[2]) << 8)  |
                                                static_cast<uint8_t>(session.rx_binary_buffer[3]);
                            
                            if (session.rx_binary_buffer.size() >= pkt_len + 4) {
                                uint8_t pad_len = session.rx_binary_buffer[4];
                                uint8_t msg_code = session.rx_binary_buffer[5];
                                
                                if (msg_code == SSH_MSG_KEXINIT) {
                                    size_t payload_len = pkt_len - pad_len - 1;
                                    session.i_c = std::vector<uint8_t>(session.rx_binary_buffer.begin() + 5, session.rx_binary_buffer.begin() + 5 + payload_len);
                                } 
                                else if (msg_code == 30) { 
                                    uint32_t e_len = (session.rx_binary_buffer[6] << 24) | (session.rx_binary_buffer[7] << 16) |
                                                     (session.rx_binary_buffer[8] << 8)  | session.rx_binary_buffer[9];
                                    std::vector<uint8_t> client_e(session.rx_binary_buffer.begin() + 10, session.rx_binary_buffer.begin() + 10 + e_len);
                                    
                                    std::string p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
                                    std::vector<uint8_t> p_bytes = hex_to_bytes(p_hex);
                                    std::vector<uint8_t> g_bytes = {0x02};

                                    std::vector<uint8_t> server_y(32);
                                    std::random_device rd;
                                    for(int j=0; j<32; ++j) server_y[j] = static_cast<uint8_t>(rd() % 256);

                                    std::vector<uint8_t> server_f = math_mod_exp(g_bytes, server_y, p_bytes);
                                    std::vector<uint8_t> shared_K = math_mod_exp(client_e, server_y, p_bytes);
                                    
                                    std::vector<uint8_t> session_H;
                                    
                                    // DYNAMIC UPDATE: Pass config variables in
                                    std::vector<uint8_t> reply_payload = build_kexdh_reply(session.v_c, config.get("BANNER", SERVER_BANNER_STR), session.i_c, session.i_s, client_e, server_f, shared_K, session_H, rsa_n, rsa_d);
                                    
                                    std::vector<uint8_t> reply_packet = wrap_in_binary_packet(reply_payload);
                                    send(current_fd, reply_packet.data(), reply_packet.size(), 0);
                                    
                                    std::vector<uint8_t> newkeys_payload = {21};
                                    std::vector<uint8_t> newkeys_packet = wrap_in_binary_packet(newkeys_payload);
                                    send(current_fd, newkeys_packet.data(), newkeys_packet.size(), 0);

                                    SessionKeys keys = generate_session_keys(shared_K, session_H);
                                    
                                    session.rx_cipher = std::make_shared<AesCtrEngine>();
                                    session.rx_cipher->init(keys.key_client_to_server, keys.iv_client_to_server);
                                    session.tx_cipher = std::make_shared<AesCtrEngine>();
                                    session.tx_cipher->init(keys.key_server_to_client, keys.iv_server_to_client);

                                    session.rx_mac = std::make_shared<HmacEngine>();
                                    session.rx_mac->init(keys.mac_client_to_server);
                                    session.tx_mac = std::make_shared<HmacEngine>();
                                    session.tx_mac->init(keys.mac_server_to_client);

                                    session.state = STATE_WAIT_NEWKEYS;
                                }
                                session.rx_binary_buffer.erase(session.rx_binary_buffer.begin(), session.rx_binary_buffer.begin() + 4 + pkt_len);
                            } else break; 
                        }
                    } 
                    
                    if (session.state == STATE_WAIT_NEWKEYS) {
                        while (session.rx_binary_buffer.size() >= 4) {
                            uint32_t pkt_len = (static_cast<uint8_t>(session.rx_binary_buffer[0]) << 24) |
                                               (static_cast<uint8_t>(session.rx_binary_buffer[1]) << 16) |
                                               (static_cast<uint8_t>(session.rx_binary_buffer[2]) << 8)  |
                                                static_cast<uint8_t>(session.rx_binary_buffer[3]);
                            
                            if (session.rx_binary_buffer.size() >= pkt_len + 4) {
                                uint8_t msg_code = session.rx_binary_buffer[5];
                                if (msg_code == 21) {
                                    session.state = STATE_ENCRYPTED;
                                    session.rx_seq = 3;
                                    session.tx_seq = 3;
                                    session.rx_binary_buffer.erase(session.rx_binary_buffer.begin(), session.rx_binary_buffer.begin() + 4 + pkt_len);
                                    break;
                                } else {
                                    session.rx_binary_buffer.erase(session.rx_binary_buffer.begin(), session.rx_binary_buffer.begin() + 4 + pkt_len);
                                }
                            } else break;
                        }
                    } 
                    
                    if (session.state == STATE_ENCRYPTED) {
                        while (true) {
                            if (session.reading_first_block) {
                                if (session.rx_binary_buffer.size() >= 16) {
                                    std::vector<uint8_t> block(session.rx_binary_buffer.begin(), session.rx_binary_buffer.begin() + 16);
                                    std::vector<uint8_t> plain = session.rx_cipher->decrypt(block);
                                    session.current_plaintext.insert(session.current_plaintext.end(), plain.begin(), plain.end());
                                    
                                    uint32_t pkt_len = (static_cast<uint8_t>(plain[0]) << 24) |
                                                       (static_cast<uint8_t>(plain[1]) << 16) |
                                                       (static_cast<uint8_t>(plain[2]) << 8)  |
                                                        static_cast<uint8_t>(plain[3]);
                                                        
                                    session.expected_encrypted_bytes = (pkt_len + 4) - 16;
                                    session.rx_binary_buffer.erase(session.rx_binary_buffer.begin(), session.rx_binary_buffer.begin() + 16);
                                    session.reading_first_block = false;
                                } else break; 
                            }
                            
                            if (!session.reading_first_block) {
                                if (session.rx_binary_buffer.size() >= session.expected_encrypted_bytes + 32) {
                                    if (session.expected_encrypted_bytes > 0) {
                                        std::vector<uint8_t> rest(session.rx_binary_buffer.begin(), session.rx_binary_buffer.begin() + session.expected_encrypted_bytes);
                                        std::vector<uint8_t> plain_rest = session.rx_cipher->decrypt(rest);
                                        session.current_plaintext.insert(session.current_plaintext.end(), plain_rest.begin(), plain_rest.end());
                                    }
                                    
                                    session.rx_binary_buffer.erase(session.rx_binary_buffer.begin(), session.rx_binary_buffer.begin() + session.expected_encrypted_bytes + 32);
                                    uint8_t msg_code = session.current_plaintext[5];
                                    
                                    if (msg_code == 5) {
                                        std::vector<uint8_t> reply_payload;
                                        reply_payload.push_back(6);
                                        write_ssh_string(reply_payload, "ssh-userauth");
                                        std::vector<uint8_t> tx_packet = build_encrypted_packet(reply_payload, session.tx_cipher, session.tx_mac, session.tx_seq);
                                        send(current_fd, tx_packet.data(), tx_packet.size(), 0);
                                    }
                                    else if (msg_code == 50) {
                                        // String extraction for parsing
                                        std::string raw_payload_str;
                                        for(size_t j = 5; j < session.current_plaintext.size() - session.current_plaintext[4]; ++j) {
                                            char c = session.current_plaintext[j];
                                            if (c >= 32 && c <= 126) raw_payload_str += c;
                                            else raw_payload_str += ".";
                                        }
                                        
                                        if (raw_payload_str.find("none") != std::string::npos) {
                                            std::vector<uint8_t> fail_payload;
                                            fail_payload.push_back(51); 
                                            write_ssh_string(fail_payload, "password");
                                            fail_payload.push_back(0); 
                                            
                                            std::vector<uint8_t> tx_packet = build_encrypted_packet(fail_payload, session.tx_cipher, session.tx_mac, session.tx_seq);
                                            send(current_fd, tx_packet.data(), tx_packet.size(), 0);
                                        } 
                                        else if (raw_payload_str.find("password") != std::string::npos) {
                                            
                                            // VERY hacky parsing of the raw decrypted dump to extract user/pass cleanly
                                            // The string looks like: .root.ssh-connection.password..passwordLMAO
                                            std::string ext_user = "unknown";
                                            std::string ext_pass = "unknown";
                                            
                                            size_t ssh_conn_pos = raw_payload_str.find(".ssh-connection");
                                            if (ssh_conn_pos != std::string::npos && ssh_conn_pos > 1) {
                                                ext_user = raw_payload_str.substr(1, ssh_conn_pos - 1);
                                            }
                                            
                                            size_t pass_str_pos = raw_payload_str.find("password.");
                                            if (pass_str_pos != std::string::npos) {
                                                ext_pass = raw_payload_str.substr(pass_str_pos + 10);
                                            }

                                            std::cout << "[$$$] INTERCEPT: " << session.ip_address << " | User: " << ext_user << " | Pass: " << ext_pass << std::endl;
                                            
                                            // DYNAMIC UPDATE: Log to SQLite Database!
                                            db.log_credential(session.ip_address, ext_user, ext_pass);
                                            
                                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, nullptr);
                                            close(current_fd);
                                            sessions.erase(current_fd);
                                        }
                                    }
                                    
                                    session.current_plaintext.clear();
                                    session.reading_first_block = true;
                                    session.rx_seq++;
                                } else break; 
                            }
                        }
                    }
                } else {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, nullptr);
                    close(current_fd);
                    sessions.erase(current_fd);
                    std::cout << "[-] Client disconnected." << std::endl;
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}
