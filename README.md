# rasmalaaiPiAuthSim

a zero-dependency, bare-metal ssh honeypot built entirely in c++ for the rasmalaaiPi ecosystem. 

it bypasses bloated cryptographic libraries (like openssl) by natively abusing the debian linux kernel's `af_alg` socket interface and posix pipes to mathematically forge ssh handshakes, decrypt aes-128-ctr streams in real-time, and silently log brute-force credentials into a persistent sqlite database.

i wanted to see what malicious bots were trying to brute-force on my raspberry pi, but i didn't want to just run a generic third-party script. instead, i went down an absolute rabbit hole of reverse-engineering ssh protocols, weaponizing the linux kernel, and building an asynchronous tcp state machine from scratch just to steal passwords from automated scanners.

## demo output

when a client connects, the honeypot negotiates the diffie-hellman key exchange, forges the rsa host signatures, and seamlessly transitions the tcp tunnel into an encrypted state. 

once the client drops its guard and attempts to log in, the daemon intercepts the payload, rips off the aes encryption, and logs the raw credentials.

```text
./authsim
[+] Config Loaded. Port: 2222
[+] Database Online: captures.db
[+] State Engine active. Awaiting targets...
[+] Target Connected: 127.0.0.1
[$$$] INTERCEPT: 127.0.0.1 | User: ....root... | Pass: ...passwordLMAO
```
you can then query the persisten database to see intercepted passwords:

```bash
sqlite3 captures.db "SELECT * FROM captures;"
# 1|127.0.0.1|....root...|...passwordLMAO|2026-07-23 10:11:20
```

## systems architecture

### phase 1: the cryptographic math bridge

- **engine:** posix pipes (popen) routing to the native python3 interpreter

- **purpose**: computes massive 2048-bit modular exponentiation for diffie-hellman key exchange and rsa pkcs#1 v1.5 signature forging. it double-hashes the payload via the kernel before signing to satisfy strictly undocumented ssh packet validation quirks.

### phase 2: the kernel cipher socket (af_alg)

- **engine:** linux kernel algorithm sockets via low-level cmsg memory structures

- **purpose**: hardware-accelerated symmetric cryptography. bypasses user-space libraries completely by forcing the os kernel itself to handle the aes-128-ctr stream encryption/decryption and hmac-sha256 signature generation.

### phase 3: the tcp state machine

- **engine:** non-blocking linux epoll asynchronous event loop

- **purpose**: handles heavily fragmented network streams, mitigates tcp pipelining deadlocks, drops the "none" auth trap (code 51) to force clients to prompt for passwords, and intercepts the decrypted payload block-by-block.

## deplyoment 
this project relies on raw linux kernel features. it is explicitly designed for debian-based linux systems (like the raspberry pi).

### requirements
you only need the sqlite3 c library for persistent database logging, and standard build tools.

```bash
sudo apt update
sudo apt install libsqlite3-dev python3 build-essential
```
build & execute
```bash
git clone https://github.com/asitos/rasmalaaiPiPwner.git
cd rasmalaaiPiPwner

# the config file stores your throwaway rsa integers and port bindings
nano config.ini 

make clean && make
./authsim
```

## security & state management

- **persistent logging:** utilizes prepared statements in sqlite3 to dump incoming ips, usernames, and passwords into captures.db, inherently preventing sql injection from malicious ssh payloads (e.g., root', 'pass'); drop table captures;--).

- **dynamic configuration:** rips massive 2048-bit rsa strings and port bindings out of the c++ binary into a decoupled .ini parser.

- **tcp pipelining deadlock mitigation:** engineered an unchained, cascading state machine to process simultaneous encrypted packets (like newkeys and service_request) arriving in the exact same tcp stream burst.

- **single-buffer mac forging:** bypasses the kernel's msg_more hashing trap by concatenating network sequence numbers and raw payloads into isolated, contiguous byte vectors before issuing write() calls to the os.

## learning notes & other stuff
- **c++ & non-blocking network i/o:** i finally understood how low-level memory buffers, sockets, and epoll actually work under the hood. building a state machine that can parse fractured, encrypted network packets byte-by-byte without hanging the main thread was a nightmare, but incredibly rewarding.

- **cryptography without libraries:** realizing that i didn't need openssl to do aes encryption was mind-blowing. dropping down to the debian os layer and using arcane cmsg headers to send raw initialization vectors directly into the kernel's af_alg socket made me feel like an absolute wizard.

- **protocol reverse-engineering:** figuring out why the client was randomly dropping connections with message authentication code incorrect taught me about the silent, undocumented quirks of cryptography—like zero-truncation in python math, strict pkcs#1 padding constraints, and the fact that ssh hashes its payloads twice before signing them.

- **the linux file descriptor philosophy:** everything really is a file. using standard write() calls to pipe data into a kernel hashing socket and encountering the hash-finalization trap taught me exactly how the kernel interprets sequential data streams and system calls.
