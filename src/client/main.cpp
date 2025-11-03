#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdlib>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace messageu {

constexpr std::size_t CLIENT_ID_LEN = 16;
constexpr std::size_t NAME_LEN = 255;
constexpr std::size_t PUBKEY_LEN = 160;
constexpr std::uint8_t CLIENT_VERSION = 2;
constexpr std::array<std::uint8_t, 2> ACCEPTED_SERVER_VERSIONS{1, 2};

constexpr std::uint16_t REQ_REGISTER = 600;
constexpr std::uint16_t REQ_CLIENTS_LIST = 601;
constexpr std::uint16_t REQ_PUBLIC_KEY = 602;
constexpr std::uint16_t REQ_SEND_MESSAGE = 603;
constexpr std::uint16_t REQ_FETCH_MESSAGES = 604;

constexpr std::uint16_t RESP_REGISTER_OK = 2100;
constexpr std::uint16_t RESP_CLIENTS_LIST = 2101;
constexpr std::uint16_t RESP_PUBLIC_KEY = 2102;
constexpr std::uint16_t RESP_MESSAGE_ACCEPTED = 2103;
constexpr std::uint16_t RESP_WAITING_MESSAGES = 2104;
constexpr std::uint16_t RESP_ERROR = 9000;

constexpr std::uint8_t MSG_TYPE_REQUEST_KEY = 1;
constexpr std::uint8_t MSG_TYPE_SEND_KEY = 2;
constexpr std::uint8_t MSG_TYPE_TEXT = 3;
constexpr std::uint8_t MSG_TYPE_FILE = 4;

inline void appendLE16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
}

inline void appendLE32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

inline std::uint16_t readLE16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(data[0]) | (static_cast<std::uint16_t>(data[1]) << 8);
}

inline std::uint32_t readLE32(const std::uint8_t* data) {
    return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) | (static_cast<std::uint32_t>(data[3]) << 24);
}

class Tcp {
public:
    Tcp() : socket_(INVALID_SOCKET) {}
    ~Tcp() { close(); }

    Tcp(const Tcp&) = delete;
    Tcp& operator=(const Tcp&) = delete;

    Tcp(Tcp&& other) noexcept : socket_(other.socket_) { other.socket_ = INVALID_SOCKET; }
    Tcp& operator=(Tcp&& other) noexcept {
        if (this != &other) {
            close();
            socket_ = other.socket_;
            other.socket_ = INVALID_SOCKET;
        }
        return *this;
    }

    void connect(const std::string& host, std::uint16_t port) {
        close();

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* result = nullptr;
        const std::string portStr = std::to_string(port);
        if (GetAddrInfoA(host.c_str(), portStr.c_str(), &hints, &result) != 0) {
            throwLastError("GetAddrInfoA");
        }

        SOCKET connected = INVALID_SOCKET;
        for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
            SOCKET candidate = ::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (candidate == INVALID_SOCKET) {
                continue;
            }

            if (::connect(candidate, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == 0) {
                connected = candidate;
                break;
            }

            ::closesocket(candidate);
        }

        FreeAddrInfoA(result);

        if (connected == INVALID_SOCKET) {
            throwLastError("connect");
        }

        socket_ = connected;
    }

    void sendAll(const std::vector<std::uint8_t>& data) const {
        sendAll(data.data(), data.size());
    }

    void sendAll(const std::uint8_t* data, std::size_t length) const {
        std::size_t sentTotal = 0;
        while (sentTotal < length) {
            const int sent = ::send(socket_, reinterpret_cast<const char*>(data + sentTotal),
                                    static_cast<int>(length - sentTotal), 0);
            if (sent == SOCKET_ERROR) {
                throwLastError("send");
            }
            if (sent == 0) {
                throw std::runtime_error("socket closed during send");
            }
            sentTotal += static_cast<std::size_t>(sent);
        }
    }

    std::vector<std::uint8_t> readExact(std::size_t length) const {
        std::vector<std::uint8_t> buffer(length);
        std::size_t receivedTotal = 0;
        while (receivedTotal < length) {
            const int received = ::recv(socket_, reinterpret_cast<char*>(buffer.data() + receivedTotal),
                                        static_cast<int>(length - receivedTotal), 0);
            if (received == SOCKET_ERROR) {
                throwLastError("recv");
            }
            if (received == 0) {
                throw std::runtime_error("socket closed during recv");
            }
            receivedTotal += static_cast<std::size_t>(received);
        }
        return buffer;
    }

    void close() {
        if (socket_ != INVALID_SOCKET) {
            ::closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
    }

private:
    SOCKET socket_;

    static void throwLastError(const char* context) {
        const int err = WSAGetLastError();
        throw std::runtime_error(std::string(context) + " failed with WSA error " + std::to_string(err));
    }
};

std::string base64Encode(const std::vector<std::uint8_t>& data) {
    std::string output;
    CryptoPP::StringSource(data.data(), data.size(), true,
                           new CryptoPP::Base64Encoder(new CryptoPP::StringSink(output), false));
    return output;
}

std::vector<std::uint8_t> base64Decode(const std::string& text) {
    std::string decoded;
    CryptoPP::StringSource(text, true,
                           new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
    return std::vector<std::uint8_t>(decoded.begin(), decoded.end());
}

using AesKey = std::array<std::uint8_t, 16>;
using PublicKey = std::array<std::uint8_t, 160>;

AesKey generateAesKey() {
    CryptoPP::AutoSeededRandomPool prng;
    AesKey key{};
    prng.GenerateBlock(key.data(), key.size());
    return key;
}

std::vector<std::uint8_t> aesTransform(bool encrypt,
                                       const AesKey& key,
                                       const std::vector<std::uint8_t>& input) {
    std::array<std::uint8_t, 16> zeroIv{};
    if (encrypt) {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), zeroIv.data(), zeroIv.size());
        std::string result;
        CryptoPP::StringSource(input.data(), input.size(), true,
                               new CryptoPP::StreamTransformationFilter(
                                   enc, new CryptoPP::StringSink(result),
                                   CryptoPP::StreamTransformationFilter::PKCS_PADDING));
        return std::vector<std::uint8_t>(result.begin(), result.end());
    }

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), zeroIv.data(), zeroIv.size());
    std::string result;
    CryptoPP::StringSource(input.data(), input.size(), true,
                           new CryptoPP::StreamTransformationFilter(
                               dec, new CryptoPP::StringSink(result),
                               CryptoPP::StreamTransformationFilter::PKCS_PADDING));
    return std::vector<std::uint8_t>(result.begin(), result.end());
}

struct KeyPair {
    PublicKey publicKey;
    std::string privateKeyBase64;
};

KeyPair generateKeyPair() {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::InvertibleRSAFunction params;
    params.Initialize(prng, 1024);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    PublicKey encoded{};
    publicKey.GetModulus().Encode(encoded.data(), 128);
    std::array<std::uint8_t, 32> exponent{};
    publicKey.GetPublicExponent().Encode(exponent.data(), exponent.size());
    std::copy(exponent.begin(), exponent.end(), encoded.begin() + 128);

    std::string der;
    CryptoPP::StringSink sink(der);
    privateKey.Save(sink);

    KeyPair pair{};
    pair.publicKey = encoded;
    pair.privateKeyBase64 = base64Encode({der.begin(), der.end()});
    return pair;
}

std::vector<std::uint8_t> rsaEncrypt(const PublicKey& wireKey, const std::vector<std::uint8_t>& plaintext) {
    CryptoPP::RSA::PublicKey key;
    CryptoPP::Integer modulus, exponent;
    modulus.Decode(wireKey.data(), 128);
    exponent.Decode(wireKey.data() + 128, 32);
    key.Initialize(modulus, exponent);

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor enc(key);
    std::vector<std::uint8_t> ciphertext(enc.CiphertextLength(plaintext.size()));
    enc.Encrypt(prng, plaintext.data(), plaintext.size(), ciphertext.data());
    return ciphertext;
}

std::vector<std::uint8_t> rsaDecrypt(const std::string& privateKeyBase64, const std::vector<std::uint8_t>& ciphertext) {
    const std::vector<std::uint8_t> der = base64Decode(privateKeyBase64);
    CryptoPP::RSA::PrivateKey key;
    CryptoPP::ArraySource source(der.data(), der.size(), true);
    key.Load(source);

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor dec(key);

    std::vector<std::uint8_t> recovered(dec.MaxPlaintextLength(ciphertext.size()));
    CryptoPP::DecodingResult result =
        dec.Decrypt(prng, ciphertext.data(), ciphertext.size(), recovered.data());
    if (!result.isValidCoding) {
        throw std::runtime_error("RSA decryption failed");
    }
    recovered.resize(result.messageLength);
    return recovered;
}

class KeyStore {
public:
    using ClientId = std::array<std::uint8_t, CLIENT_ID_LEN>;
    static bool isAscii(const std::string& text) noexcept {
        return std::all_of(text.begin(), text.end(), [](unsigned char ch) { return ch <= 0x7F; });
    }


    bool load() {
        identityLoaded_ = false;
        username_.clear();
        privateKeyBase64_.clear();

        std::ifstream file("me.info", std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        std::string username;
        std::string hexId;
        std::string privateKey;

        if (!std::getline(file, username) || !std::getline(file, hexId) || !std::getline(file, privateKey)) {
            return false;
        }

        if (username.empty() || !isAscii(username)) {
            return false;
        }
        if (hexId.size() != 32 || !isHex(hexId)) {
            return false;
        }
        if (!isAscii(privateKey)) {
            return false;
        }

        identityLoaded_ = true;
        username_ = username;
        clientId_ = fromHex(hexId);
        privateKeyBase64_ = privateKey;
        rememberClient(username_, clientId_);
        return true;
    }

    void saveIdentity(const std::string& username, const ClientId& id, const std::string& privateKeyBase64) {
        if (username.empty() || !isAscii(username)) {
            throw std::invalid_argument("username must be ASCII and non-empty");
        }
        if (!isAscii(privateKeyBase64)) {
            throw std::invalid_argument("private key must be ASCII");
        }

        std::ofstream file("me.info", std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            throw std::runtime_error("failed to open me.info");
        }

        file << username << '\n' << toHex(id) << '\n' << privateKeyBase64 << '\n';
        if (!file.good()) {
            throw std::runtime_error("failed to write me.info");
        }

        identityLoaded_ = true;
        username_ = username;
        clientId_ = id;
        privateKeyBase64_ = privateKeyBase64;
        rememberClient(username_, clientId_);
    }

    bool hasIdentity() const noexcept { return identityLoaded_; }
    const std::string& username() const noexcept { return username_; }
    const ClientId& clientId() const noexcept { return clientId_; }
    const std::string& privateKeyBase64() const noexcept { return privateKeyBase64_; }

    void rememberClient(const std::string& name, const ClientId& id) {
        if (!isAscii(name)) {
            throw std::invalid_argument("client name must be ASCII");
        }
        const std::string hex = toHex(id);
        nameToId_[name] = id;
        idToName_[hex] = name;
    }

    std::optional<ClientId> findClientId(const std::string& name) const {
        auto it = nameToId_.find(name);
        if (it == nameToId_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    std::optional<std::string> findClientName(const ClientId& id) const {
        const std::string hex = toHex(id);
        auto it = idToName_.find(hex);
        if (it == idToName_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    void rememberPublicKey(const ClientId& id, const PublicKey& key) {
        pubkeys_[toHex(id)] = key;
    }

    std::optional<PublicKey> findPublicKey(const ClientId& id) const {
        auto it = pubkeys_.find(toHex(id));
        if (it == pubkeys_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    void rememberAesKey(const ClientId& id, const AesKey& key) {
        aesKeys_[toHex(id)] = key;
    }

    std::optional<AesKey> findAesKey(const ClientId& id) const {
        auto it = aesKeys_.find(toHex(id));
        if (it == aesKeys_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

private:
    static bool isHex(const std::string& text) noexcept {
        return std::all_of(text.begin(), text.end(), [](unsigned char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
        });
    }

    static std::string toHex(const ClientId& id) {
        static constexpr char HEX[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(id.size() * 2);
        for (std::uint8_t byte : id) {
            out.push_back(HEX[(byte >> 4) & 0x0F]);
            out.push_back(HEX[byte & 0x0F]);
        }
        return out;
    }

    static ClientId fromHex(const std::string& hex) {
        ClientId id{};
        for (std::size_t i = 0; i < id.size(); ++i) {
            auto nibble = [](char ch) -> std::uint8_t {
                if (ch >= '0' && ch <= '9') {
                    return static_cast<std::uint8_t>(ch - '0');
                }
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
                return static_cast<std::uint8_t>(10 + (ch - 'A'));
            };
            id[i] = static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
        }
        return id;
    }

    bool identityLoaded_ = false;
    std::string username_;
    ClientId clientId_{};
    std::string privateKeyBase64_;

    std::unordered_map<std::string, ClientId> nameToId_;
    std::unordered_map<std::string, std::string> idToName_;
    std::unordered_map<std::string, PublicKey> pubkeys_;
    std::unordered_map<std::string, AesKey> aesKeys_;
};

struct ResponseHeader {
    std::uint8_t version{};
    std::uint16_t code{};
    std::uint32_t payloadSize{};
};

ResponseHeader parseResponseHeader(const std::uint8_t* data) {
    ResponseHeader header{};
    header.version = data[0];
    header.code = readLE16(data + 1);
    header.payloadSize = readLE32(data + 3);
    return header;
}

std::string clientIdToHex(const KeyStore::ClientId& id) {
    static constexpr char HEX[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(id.size() * 2);
    for (std::uint8_t byte : id) {
        out.push_back(HEX[(byte >> 4) & 0x0F]);
        out.push_back(HEX[byte & 0x0F]);
    }
    return out;
}

class ClientApp {
public:
    void run() {
        keyStore_.load();
        loadServerInfo();

        std::cout << "MessageU client at your service.\n";
        while (true) {
            showMenu();
            std::string choice;
            if (!std::getline(std::cin, choice)) {
                break;
            }
            if (choice == "0") {
                break;
            }
            handleChoice(choice);
        }
    }

private:
    KeyStore keyStore_;
    std::string serverHost_;
    std::uint16_t serverPort_{};

    void loadServerInfo() {
        std::ifstream file("server.info");
        if (!file.is_open()) {
            throw std::runtime_error("failed to open server.info");
        }

        std::string line;
        if (!std::getline(file, line)) {
            throw std::runtime_error("server.info is empty");
        }

        if (!KeyStore::isAscii(line)) {
            throw std::runtime_error("server.info must contain ASCII characters only");
        }

        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            throw std::runtime_error("server.info must be in IP:PORT format");
        }

        serverHost_ = line.substr(0, colon);
        const std::string portStr = line.substr(colon + 1);
        if (serverHost_.empty() || portStr.empty()) {
            throw std::runtime_error("server.info missing host or port");
        }

        int portValue = 0;
        try {
            portValue = std::stoi(portStr);
        } catch (const std::exception&) {
            throw std::runtime_error("invalid port in server.info");
        }

        if (portValue < 1 || portValue > 65535) {
            throw std::runtime_error("port in server.info out of range");
        }
        serverPort_ = static_cast<std::uint16_t>(portValue);
    }

    void showMenu() const {
        std::cout << "110) Register\n"
                  << "120) Request for clients list\n"
                  << "130) Request for public key\n"
                  << "140) Request for waiting messages\n"
                  << "150) Send a text message\n"
                  << "151) Send a request for symmetric key\n"
                  << "152) Send your symmetric key\n"
                  << "153) Send a file\n"
                  << "0)   Exit client\n"
                  << "?";
    }

    void handleChoice(const std::string& choice) {
        if (choice == "110") {
            handleRegister();
        } else if (choice == "120") {
            handleClientsList();
        } else if (choice == "130") {
            handlePublicKey();
        } else if (choice == "140") {
            handleFetchMessages();
        } else if (choice == "150") {
            handleSendText();
        } else if (choice == "151") {
            handleSendRequestKey();
        } else if (choice == "152") {
            handleSendSymmetricKey();
        } else if (choice == "153") {
            handleSendFile();
        } else {
            std::cout << "\nUnknown option.\n";
        }
    }

    void handleRegister() {
        if (keyStore_.hasIdentity()) {
            std::cout << "\nRegistration refused: identity already exists in me.info.\n";
            return;
        }

        auto usernameOpt = prompt("Please enter a username: ");
        if (!usernameOpt) {
            std::cout << "\nInvalid input.\n";
            return;
        }

        const std::string username = *usernameOpt;
        if (username.empty() || username.size() > NAME_LEN || !KeyStore::isAscii(username)) {
            std::cout << "\nUsername must be 1-255 ASCII characters.\n";
            return;
        }

        const auto keyPair = generateKeyPair();

        std::vector<std::uint8_t> payload(NAME_LEN + PUBKEY_LEN, 0);
        std::copy(username.begin(), username.end(), payload.begin());
        payload[username.size()] = 0;
        std::copy(keyPair.publicKey.begin(), keyPair.publicKey.end(), payload.begin() + NAME_LEN);

        auto response = sendRequest(REQ_REGISTER, payload);
        if (!response || response->code != RESP_REGISTER_OK || response->payload.size() != CLIENT_ID_LEN) {
            std::cout << "\nRegistration failed.\n";
            return;
        }

        KeyStore::ClientId clientId{};
        std::copy(response->payload.begin(), response->payload.end(), clientId.begin());
        keyStore_.saveIdentity(username, clientId, keyPair.privateKeyBase64);
        keyStore_.rememberClient(username, clientId);
        std::cout << "\nRegistration succeeded.\n";
    }

    void handleClientsList() {
        if (!ensureIdentity()) {
            return;
        }

        auto response = sendRequest(REQ_CLIENTS_LIST, {});
        if (!response || response->code != RESP_CLIENTS_LIST) {
            return;
        }

        if (response->payload.empty()) {
            std::cout << "\nNo other clients registered.\n";
            return;
        }

        const std::size_t blockSize = CLIENT_ID_LEN + NAME_LEN;
        if (response->payload.size() % blockSize != 0) {
            std::cout << "\nserver responded with an error\n";
            return;
        }

        std::cout << '\n';
        for (std::size_t offset = 0, idx = 1; offset < response->payload.size(); offset += blockSize, ++idx) {
            KeyStore::ClientId id{};
            std::copy(response->payload.begin() + offset,
                      response->payload.begin() + offset + CLIENT_ID_LEN,
                      id.begin());
            const std::uint8_t* nameStart = response->payload.data() + offset + CLIENT_ID_LEN;
            const std::uint8_t* nameEnd = std::find(nameStart, nameStart + NAME_LEN, 0);
            std::string name(reinterpret_cast<const char*>(nameStart), nameEnd - nameStart);
            keyStore_.rememberClient(name, id);
            std::cout << idx << ") " << name << '\n';
        }
    }

    void handlePublicKey() {
        if (!ensureIdentity()) {
            return;
        }

        auto targetOpt = prompt("Please enter the user name: ");
        if (!targetOpt || !KeyStore::isAscii(*targetOpt)) {
            std::cout << "\nName must be ASCII.\n";
            return;
        }

        auto idOpt = keyStore_.findClientId(*targetOpt);
        if (!idOpt) {
            std::cout << "\nUnknown client. Fetch the clients list first.\n";
            return;
        }

        std::vector<std::uint8_t> payload(CLIENT_ID_LEN);
        std::copy(idOpt->begin(), idOpt->end(), payload.begin());

        auto response = sendRequest(REQ_PUBLIC_KEY, payload);
        if (!response || response->code != RESP_PUBLIC_KEY ||
            response->payload.size() != CLIENT_ID_LEN + PUBKEY_LEN) {
            std::cout << "\nserver responded with an error\n";
            return;
        }

        KeyStore::ClientId clientId{};
        std::copy(response->payload.begin(), response->payload.begin() + CLIENT_ID_LEN, clientId.begin());
        PublicKey publicKey{};
        std::copy(response->payload.begin() + CLIENT_ID_LEN, response->payload.end(), publicKey.begin());

        keyStore_.rememberClient(*targetOpt, clientId);
        keyStore_.rememberPublicKey(clientId, publicKey);
        std::cout << "\nStored public key for " << *targetOpt << ".\n";
    }

    void handleFetchMessages() {
        if (!ensureIdentity()) {
            return;
        }

        auto response = sendRequest(REQ_FETCH_MESSAGES, {});
        if (!response || response->code != RESP_WAITING_MESSAGES) {
            return;
        }

        if (response->payload.empty()) {
            std::cout << "\nNo messages waiting.\n";
            return;
        }

        std::size_t offset = 0;
        while (offset < response->payload.size()) {
            if (offset + CLIENT_ID_LEN + 1 + 8 > response->payload.size()) {
                std::cout << "\nserver responded with an error\n";
                return;
            }

            KeyStore::ClientId fromId{};
            std::copy(response->payload.begin() + offset,
                      response->payload.begin() + offset + CLIENT_ID_LEN,
                      fromId.begin());
            offset += CLIENT_ID_LEN;

            std::uint32_t messageId = readLE32(response->payload.data() + offset);
            offset += 4;

            std::uint8_t type = response->payload[offset++];
            std::uint32_t size = readLE32(response->payload.data() + offset);
            offset += 4;

            if (offset + size > response->payload.size()) {
                std::cout << "\nserver responded with an error\n";
                return;
            }

            std::vector<std::uint8_t> content(response->payload.begin() + offset,
                                              response->payload.begin() + offset + size);
            offset += size;

            std::string fromName;
            if (auto nameOpt = keyStore_.findClientName(fromId)) {
                fromName = *nameOpt;
            } else {
                fromName = clientIdToHex(fromId);
            }

            if (type == MSG_TYPE_REQUEST_KEY) {
                printMessageBlock(fromName, "Request for symmetric key");
            } else if (type == MSG_TYPE_SEND_KEY) {
                try {
                    auto plaintext = rsaDecrypt(keyStore_.privateKeyBase64(), content);
                    if (plaintext.size() != AesKey{}.size()) {
                        throw std::runtime_error("unexpected AES key size");
                    }
                    AesKey aesKey{};
                    std::copy(plaintext.begin(), plaintext.end(), aesKey.begin());
                    keyStore_.rememberAesKey(fromId, aesKey);
                    printMessageBlock(fromName, "symmetric key received.");
                } catch (const std::exception&) {
                    printMessageBlock(fromName, "can't decrypt message");
                }
            } else if (type == MSG_TYPE_TEXT) {
                auto aesKeyOpt = keyStore_.findAesKey(fromId);
                if (!aesKeyOpt) {
                    printMessageBlock(fromName, "can't decrypt message");
                    continue;
                }
                try {
                    auto plaintext = aesTransform(false, *aesKeyOpt, content);
                    std::string text(plaintext.begin(), plaintext.end());
                    printMessageBlock(fromName, text);
                } catch (const std::exception&) {
                    printMessageBlock(fromName, "can't decrypt message");
                }
            } else if (type == MSG_TYPE_FILE) {
                auto aesKeyOpt = keyStore_.findAesKey(fromId);
                if (!aesKeyOpt) {
                    printMessageBlock(fromName, "can't decrypt message");
                    continue;
                }
                try {
                    auto plaintext = aesTransform(false, *aesKeyOpt, content);
                    auto saved = saveToTempFile(plaintext, messageId);
                    if (!saved) {
                        printMessageBlock(fromName, "can't decrypt message");
                        continue;
                    }
                    printMessageBlock(fromName, saved->string());
                } catch (const std::exception&) {
                    printMessageBlock(fromName, "can't decrypt message");
                }
            } else {
                printMessageBlock(fromName, "can't decrypt message");
            }
        }
    }

    void handleSendText() {
        if (!ensureIdentity()) {
            return;
        }

        auto targetOpt = prompt("Please enter the user name: ");
        if (!targetOpt || !KeyStore::isAscii(*targetOpt)) {
            std::cout << "\nName must be ASCII.\n";
            return;
        }

        auto idOpt = keyStore_.findClientId(*targetOpt);
        if (!idOpt) {
            std::cout << "\nUnknown client. Fetch the clients list first.\n";
            return;
        }

        auto aesKeyOpt = keyStore_.findAesKey(*idOpt);
        if (!aesKeyOpt) {
            std::cout << "\nNo symmetric key for this client. Request or exchange one first.\n";
            return;
        }

        auto messageOpt = prompt("Please enter the message: ");
        if (!messageOpt || !KeyStore::isAscii(*messageOpt)) {
            std::cout << "\nMessage must be ASCII.\n";
            return;
        }

        std::vector<std::uint8_t> plaintext(messageOpt->begin(), messageOpt->end());
        auto ciphertext = aesTransform(true, *aesKeyOpt, plaintext);

        std::vector<std::uint8_t> payload;
        payload.reserve(CLIENT_ID_LEN + 1 + 4 + ciphertext.size());
        payload.insert(payload.end(), idOpt->begin(), idOpt->end());
        payload.push_back(MSG_TYPE_TEXT);
        appendLE32(payload, static_cast<std::uint32_t>(ciphertext.size()));
        payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

        auto response = sendRequest(REQ_SEND_MESSAGE, payload);
        if (!response || response->code != RESP_MESSAGE_ACCEPTED) {
            return;
        }

        std::cout << "\nMessage sent.\n";
    }

    void handleSendRequestKey() {
        if (!ensureIdentity()) {
            return;
        }

        auto targetOpt = prompt("Please enter the user name: ");
        if (!targetOpt || !KeyStore::isAscii(*targetOpt)) {
            std::cout << "\nName must be ASCII.\n";
            return;
        }

        auto idOpt = keyStore_.findClientId(*targetOpt);
        if (!idOpt) {
            std::cout << "\nUnknown client. Fetch the clients list first.\n";
            return;
        }

        std::vector<std::uint8_t> payload;
        payload.reserve(CLIENT_ID_LEN + 1 + 4);
        payload.insert(payload.end(), idOpt->begin(), idOpt->end());
        payload.push_back(MSG_TYPE_REQUEST_KEY);
        appendLE32(payload, 0);

        auto response = sendRequest(REQ_SEND_MESSAGE, payload);
        if (!response || response->code != RESP_MESSAGE_ACCEPTED) {
            return;
        }

        std::cout << "\nSymmetric key request sent.\n";
    }

    void handleSendSymmetricKey() {
        if (!ensureIdentity()) {
            return;
        }

        auto targetOpt = prompt("Please enter the user name: ");
        if (!targetOpt || !KeyStore::isAscii(*targetOpt)) {
            std::cout << "\nName must be ASCII.\n";
            return;
        }

        auto idOpt = keyStore_.findClientId(*targetOpt);
        if (!idOpt) {
            std::cout << "\nUnknown client. Fetch the clients list first.\n";
            return;
        }

        auto pubKeyOpt = keyStore_.findPublicKey(*idOpt);
        if (!pubKeyOpt) {
            std::cout << "\nPublic key unknown. Request it first.\n";
            return;
        }

        const auto aesKey = generateAesKey();
        keyStore_.rememberAesKey(*idOpt, aesKey);

        std::vector<std::uint8_t> keyBytes(aesKey.begin(), aesKey.end());
        auto encrypted = rsaEncrypt(*pubKeyOpt, keyBytes);

        std::vector<std::uint8_t> payload;
        payload.reserve(CLIENT_ID_LEN + 1 + 4 + encrypted.size());
        payload.insert(payload.end(), idOpt->begin(), idOpt->end());
        payload.push_back(MSG_TYPE_SEND_KEY);
        appendLE32(payload, static_cast<std::uint32_t>(encrypted.size()));
        payload.insert(payload.end(), encrypted.begin(), encrypted.end());

        auto response = sendRequest(REQ_SEND_MESSAGE, payload);
        if (!response || response->code != RESP_MESSAGE_ACCEPTED) {
            return;
        }

        std::cout << "\nSymmetric key sent.\n";
    }

    void handleSendFile() {
        if (!ensureIdentity()) {
            return;
        }

        auto targetOpt = prompt("Please enter the user name: ");
        if (!targetOpt || !KeyStore::isAscii(*targetOpt)) {
            std::cout << "\nName must be ASCII.\n";
            return;
        }

        auto idOpt = keyStore_.findClientId(*targetOpt);
        if (!idOpt) {
            std::cout << "\nUnknown client. Fetch the clients list first.\n";
            return;
        }

        auto aesKeyOpt = keyStore_.findAesKey(*idOpt);
        if (!aesKeyOpt) {
            std::cout << "\nNo symmetric key for this client. Request or exchange one first.\n";
            return;
        }

        auto pathOpt = prompt("Please enter the file path: ");
        if (!pathOpt || pathOpt->empty() || !KeyStore::isAscii(*pathOpt)) {
            std::cout << "\nfile not found\n";
            return;
        }

        std::filesystem::path absolutePath;
        try {
            absolutePath = std::filesystem::absolute(*pathOpt);
        } catch (const std::exception&) {
            std::cout << "\nfile not found\n";
            return;
        }

        const std::string absoluteString = absolutePath.string();
        if (!KeyStore::isAscii(absoluteString)) {
            std::cout << "\nfile not found\n";
            return;
        }

        try {
            if (!std::filesystem::exists(absolutePath) || !std::filesystem::is_regular_file(absolutePath)) {
                std::cout << "\nfile not found\n";
                return;
            }
        } catch (const std::exception&) {
            std::cout << "\nfile not found\n";
            return;
        }

        std::vector<std::uint8_t> contents;
        try {
            const auto size = std::filesystem::file_size(absolutePath);
            if (size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())) {
                std::cout << "\nfile not found\n";
                return;
            }
            contents.resize(static_cast<std::size_t>(size));
            std::ifstream file(absolutePath, std::ios::binary);
            if (!file.is_open()) {
                std::cout << "\nfile not found\n";
                return;
            }
            if (!contents.empty()) {
                file.read(reinterpret_cast<char*>(contents.data()), static_cast<std::streamsize>(contents.size()));
                if (!file) {
                    std::cout << "\nfile not found\n";
                    return;
                }
            }
        } catch (const std::exception&) {
            std::cout << "\nfile not found\n";
            return;
        }

        auto ciphertext = aesTransform(true, *aesKeyOpt, contents);

        std::vector<std::uint8_t> payload;
        payload.reserve(CLIENT_ID_LEN + 1 + 4 + ciphertext.size());
        payload.insert(payload.end(), idOpt->begin(), idOpt->end());
        payload.push_back(MSG_TYPE_FILE);
        appendLE32(payload, static_cast<std::uint32_t>(ciphertext.size()));
        payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

        auto response = sendRequest(REQ_SEND_MESSAGE, payload);
        if (!response || response->code != RESP_MESSAGE_ACCEPTED) {
            return;
        }

        std::cout << "\nFile sent.\n";
    }

    bool ensureIdentity() const {
        if (!keyStore_.hasIdentity()) {
            std::cout << "\nPlease register first.\n";
            return false;
        }
        return true;
    }

    struct Response {
        std::uint16_t code{};
        std::vector<std::uint8_t> payload;
    };

    std::optional<Response> sendRequest(std::uint16_t code, const std::vector<std::uint8_t>& payload) {
        try {
            Tcp socket;
            socket.connect(serverHost_, serverPort_);

            std::vector<std::uint8_t> buffer;
            buffer.reserve(16 + 1 + 2 + 4 + payload.size());
            const auto clientId = keyStore_.hasIdentity() ? keyStore_.clientId() : KeyStore::ClientId{};
            buffer.insert(buffer.end(), clientId.begin(), clientId.end());
            buffer.push_back(CLIENT_VERSION);
            appendLE16(buffer, code);
            appendLE32(buffer, static_cast<std::uint32_t>(payload.size()));
            buffer.insert(buffer.end(), payload.begin(), payload.end());

            socket.sendAll(buffer);

            auto headerBytes = socket.readExact(7);
            auto header = parseResponseHeader(headerBytes.data());
            if (std::find(ACCEPTED_SERVER_VERSIONS.begin(), ACCEPTED_SERVER_VERSIONS.end(), header.version) ==
                ACCEPTED_SERVER_VERSIONS.end()) {
                std::cout << "\nserver responded with an error\n";
                return std::nullopt;
            }

            std::vector<std::uint8_t> responsePayload;
            if (header.payloadSize > 0) {
                responsePayload = socket.readExact(header.payloadSize);
            }

            if (header.code == RESP_ERROR) {
                std::cout << "\nserver responded with an error\n";
                return std::nullopt;
            }

            return Response{header.code, std::move(responsePayload)};
        } catch (const std::exception&) {
            std::cout << "\nserver responded with an error\n";
            return std::nullopt;
        }
    }

    static std::filesystem::path resolveTempDirectory() {
        if (const char* tmp = std::getenv("TMP")) {
            if (*tmp != '\0') {
                return std::filesystem::path(tmp);
            }
        }
        if (const char* temp = std::getenv("TEMP")) {
            if (*temp != '\0') {
                return std::filesystem::path(temp);
            }
        }
        try {
            return std::filesystem::temp_directory_path();
        } catch (const std::exception&) {
            try {
                return std::filesystem::current_path();
            } catch (const std::exception&) {
                return std::filesystem::path{"."};
            }
        }
    }

    static std::optional<std::filesystem::path> saveToTempFile(const std::vector<std::uint8_t>& data,
                                                               std::uint32_t messageId) {
        try {
            auto dir = resolveTempDirectory();
            std::ostringstream name;
            name << "MessageU_" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << messageId << ".tmp";
            auto path = dir / name.str();
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file.is_open()) {
                return std::nullopt;
            }
            if (!data.empty()) {
                file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
                if (!file) {
                    return std::nullopt;
                }
            }
            file.flush();
            if (!file) {
                return std::nullopt;
            }
            return path;
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    static void printMessageBlock(const std::string& fromName, const std::string& content) {
        std::cout << "\nFrom: " << fromName << "\nContent:\n" << content << "\n.\n.\n-----<EOM>-----\n";
    }

    static std::optional<std::string> prompt(const std::string& text) {
        std::cout << '\n' << text;
        std::string input;
        if (!std::getline(std::cin, input)) {
            return std::nullopt;
        }
        return input;
    }
};

}  // namespace messageu

int main() {
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock." << std::endl;
        return 1;
    }

    int exitCode = 0;
    try {
        messageu::ClientApp app;
        app.run();
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << std::endl;
        exitCode = 1;
    }

    WSACleanup();
    return exitCode;
}
