# MAMAN15 — Milestones 1–5 Minimal Plan

> Goal: deliver the base specification (no bonuses) with the leanest possible layout: one Python server file, one C++ client file, plus the two required config files.

---

## 0) Repo Layout & Milestones

```text
/ (repo root)
└─ src/
   ├─ server/
   │  ├─ server.py       # handlers 600–604, RAM storage, threading, pack/unpack, myport reader
   │  └─ myport.info     # ASCII port; default 1357 if unreadable
   └─ client/
      ├─ main.cpp        # Winsock client, menu 110–152, AES/RSA/Base64, me.info I/O
      └─ server.info     # ASCII "IP:PORT" (e.g., 127.0.0.1:1357)
```

`me.info` is created at runtime (after Register) and must contain username, UUID hex, Base64 private key. Do not ship an example unless the grader requests it.

### Milestones

1. Protocol & constants sealed ✅
2. Server v1 (RAM) ✅
3. Client v1 (menu 110–152) ✅
4. E2E happy path ✅
5. Negative paths & error 9000 ✅

Bonuses (SQLite persistence, file transfer 153, security analysis) are handled after this minimal base.

---

## 1) Protocol (binary over TCP, little-endian)

All numeric fields are unsigned, little-endian, > 0.

**Request header (client → server):** `<16sBHI>` (ClientID, Version, Code, PayloadSize). Client version is always **1** for milestones 1–5.

**Response header (server → client):** `<BHI>` (Version, Code, PayloadSize). Server version is always **1** in RAM mode.

### Request codes

- 600 Register → payload `Name[255 ASCII + NUL] + PublicKey[160]` (server ignores header ClientID)
- 601 Clients list → no payload
- 602 Public key → payload `ClientID[16]`
- 603 Send message → payload `ToClientID[16] + MsgType[1] + ContentSize[4] + Content`
- 604 Fetch waiting messages → no payload

### Response codes

- 2100 Register OK → payload `ClientID[16]`
- 2101 Clients list → repeated `(ClientID[16] + Name[255 ASCII + NUL])`
- 2102 Public key → payload `ClientID[16] + PublicKey[160]`
- 2103 Message accepted → payload `ToClientID[16] + MessageID[4]`
- 2104 Waiting messages → repeated `(FromID[16] + MessageID[4] + Type[1] + Size[4] + Content)`
- 9000 General error → no payload

**Zero-length payloads:** `PayloadSize` **must be permitted to be 0** for:

- 601 (Clients list request)
- 604 (Fetch waiting messages request)
- 9000 (General error response)

Update validators to accept PayloadSize=0 for these codes.

### Message types

1. Request symmetric key → content size 0
2. Send symmetric key → content is AES key encrypted with receiver’s RSA public key
3. Text message → content is AES-128-CBC ciphertext (shared key)

---

## 2) Cryptography (client-side E2E)

- Symmetric: AES-128-CBC, IV = 16 zero bytes
- Asymmetric: RSA-1024 keypair; public key on the wire is 160 bytes (128-byte modulus + 32-byte exponent)
- Library: Crypto++ (≥ 8.8)

### Key lifecycle

1. On first run, generate RSA keypair
2. Store Base64 private key (line 3 of `me.info`)
3. Publish 160-byte public key during Register

### Symmetric key exchange

- Type-1: sender requests key (empty content)
- Type-2: sender generates random 16-byte AES key, encrypts with receiver’s public key, caches result
- Type-3: encrypted text exchange using cached AES key

---

## 3) Server (Python 3.12, stdlib only)

All logic lives in `server.py`:

- constants, pack/unpack helpers, threading, RAM storage class, handlers 600–604
- reads `myport.info`; on failure logs warning and defaults to port 1357
- validates every payload (sizes, ASCII, type range, content size match)
- returns `9000` on malformed input or unknown codes; response version fixed to 1
- **exception-based error handling:** use try/except blocks; catch socket errors, struct pack/unpack errors, and validation failures; log errors and send `9000` to client or close connection gracefully on unrecoverable errors

Run with `uv run python src/server/server.py`. Lint with `uv run ruff check src/server`.

---

## 4) Client (C++17, Windows, single translation unit)

All logic lives in `main.cpp`:

- Winsock setup/teardown, LE pack/unpack helpers
- TLS-like Tcp wrapper (blocking sendAll/recvAll)
- Crypto++ AES/RSA/Base64 helpers
- `KeyStore` for `me.info` (ASCII only), caches name↔ID, public keys, AES keys
- **OOP with inheritance & polymorphism:** implement a `Command` base class with virtual `run()` method; derive concrete command classes (Register, ListClients, etc.); instantiate and invoke via polymorphic interface
- **exception-based error handling:** use try/catch blocks for socket errors, crypto failures, file I/O, and validation; terminate gracefully on unrecoverable errors with informative messages
- **Banner & menu:** print exactly:

```text
MessageU client at your service.
110) Register
120) Clients list
130) Public key
140) Fetch waiting messages
150) Send message
151) Send symmetric key request
152) Send symmetric key
153) Send a file
```

- **2104 fetch format:** for each message, print **exactly**:

  ```text
  From: <sender_username>
  Content:
  <message_content>
  .
  .
  -----<EOM>-----
  ```

  (note the two consecutive dots and final newline)
  - For Type-1: `<message_content>` = `Request for symmetric key`
  - For Type-2: `<message_content>` = `symmetric key received.`
  - For Type-3 (decryption failure): print `can't decrypt message` in place of content
  - For Type-4 (file, if implemented): print full saved temp file path instead of content
- Error responses:
  - Error on 9000: `server responded with an error`
  - Decrypt failure: `can't decrypt message`
  - File not found (153): `file not found`

Runtime files:

- `server.info` → `IP:PORT`
- `me.info` → created after Register; blocks re-register if present

CMake targets Crypto++ plus `Ws2_32` and `Bcrypt`. Build using the provided Visual Studio 2022 preset.

---

## 5) End-to-End Flow (Happy Path)

1. Client A registers → receives new ClientID and writes `me.info`
2. Client B registers → same
3. B lists clients (120), learns A’s name/ID
4. B fetches A’s public key (130)
5. B sends Type-1 message (151)
6. A fetches waiting messages (140) → sees `Request for symmetric key`
7. A fetches B’s public key (130), sends AES key (152)
8. B fetches waiting messages (140) → caches AES key and prints `symmetric key received.`
9. Both exchange text via 150/140 with AES encryption

---

## 5A) Negative Paths & Error Coverage

- Duplicate username register → server returns 9000; client prints `server responded with an error`
- `me.info` present → client refuses Register
- Malformed payload sizes, unknown codes, unsupported message types, content-size mismatch → 9000
- Missing AES key for Type-3 → client prints `can't decrypt message`
- 2104 pop semantics: after fetch, queue is empty on immediate re-fetch

---

## 5B) Tooling & Packaging Checklist

- Server: `uv venv`, `uv pip install ruff`, `uv run python src/server/server.py`
- Client: `cmake --preset windows-msvc-x64`, `cmake --build --preset windows-msvc-x64 --config Release`
- Ship only: `src/server/server.py`, `src/server/myport.info`, `src/client/main.cpp`, `src/client/server.info`, and runtime-generated `me.info` (if required by grader)
- README must stay ≤1 page and describe setup, usage, required strings, and manual test outline

This minimal baseline earns full credit for Milestones 1–5 and leaves a clean foundation for adding SQLite/file-transfer bonuses and the security analysis later.

---

## Part 2: Bonuses, File Transfer & Security Analysis (Milestones 6–9)

> **Scope:** SQLite persistence (10 pts), File transfer (10 pts), Security analysis (20%), final packaging. These add 40 points to reach 100 total.

---

## 6) Bonus A — SQLite Persistence (Server v2)

**Goal:** same behavior as RAM server, but data lives in `defensive.db`. **Server Version = 2** only when DB mode is on.

### 6.1) Minimal changes (single `server.py`)

- Add a CLI flag or env (e.g., `--sqlite`) that switches storage.

- On startup (DB mode): `sqlite3.connect("defensive.db")`; `PRAGMA foreign_keys=ON`.

- Create tables if missing:

  ```sql
  CREATE TABLE IF NOT EXISTS clients(
    ID BLOB(16) PRIMARY KEY,
    UserName CHAR(255) NOT NULL,
    PublicKey BLOB(160) NOT NULL,
    LastSeen TEXT
  );

  CREATE TABLE IF NOT EXISTS messages(
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    ToClient BLOB(16) NOT NULL,
    FromClient BLOB(16) NOT NULL,
    Type INTEGER NOT NULL,
    Content BLOB NOT NULL
  );
  ```

- Implement the same storage API you used in RAM:

  - `add_client(id, name, pubkey, last_seen)`
  - `get_client_by_name(name)`, `get_client_by_id(id)`
  - `list_clients_except(id)`
  - `add_message(to, frm, typ, content) -> msg_id`
  - `pop_all_messages_for(to)` **must delete messages after returning**.

- In DB mode, set **response header Version=2**; RAM stays **Version=1**. (Request/response codes remain identical.)

### 6.2) Acceptance (DB mode)

- First run creates `defensive.db` + both tables.

- Restart server: users/messages persist; `2104` still pops (deletes) after delivery.

---

## 7) Bonus B — File Transfer (Client v2)

**Goal:** add menu `153) Send a file`, use **Message Type = 4**, enforce ASCII path, and on receive save to `%TMP%`. **Client Version = 2** when 153 exists.

### 7.1) Minimal changes (single `main.cpp`)

- **Menu:** append exactly `153) Send a file`.

- **Version:** set request header `Version=2` (only when your build includes 153).

- **Send path (153):**

  1. Read target user name → resolve to ClientID.

  2. Read **ASCII-only** absolute path. If invalid/missing → print exactly `file not found` and return.

  3. Read bytes, **encrypt with AES key** for that peer (existing cache from 152).

  4. Send **603** with Type=4, `ContentSize=len(cipher)`, `Content=cipher`.

- **Receive path (140):** when a 2104 block has **Type=4**:

  1. Decrypt with cached AES key; if missing/invalid → print `can't decrypt message`.

  2. Otherwise write to a temp file under `%TMP%` (e.g., `MessageU_XXXX.tmp`) and **print the full saved path** instead of plaintext content.

- **Server:** no new routes needed; it already stores type and blob. Ensure `603` validator accepts Type ∈ {1,2,3,4}.

### 7.2) Acceptance (file)

- Menu shows **153** exactly.

- Bad/Unicode path → `file not found`.

- Receiver prints full temp path and file exists.

- All other strings remain **byte-exact** (error line, EOM delimiter, etc.).

---

## 8) Q2 — Security Analysis (2 pages, concise)

Deliver `research/MAMAN15_Security_Analysis.[pdf|docx]` with the following sections. For each: **Weakness → Concrete attack → Mitigation** (2–4 sentences each).

1. **No integrity (AES-CBC only)** → bit-flip/padding oracle → add **HMAC-SHA256** over header+payload or switch to **AES-GCM**.

2. **Fixed zero IV + key reuse** → pattern leakage → random per-message IV (prepend IV to ciphertext).

3. **RSA-1024** → low modern margin → upgrade to RSA-2048/3072 or X25519 KEM + AEAD.

4. **No replay protection** → duplicate 152/150/153 → include per-peer nonce/counter, reject stale.

5. **No server auth** → MITM of 602/603/604 → TLS or server-signed responses; client pinning of server key.

6. **Username enumeration** → timing/explicit errors → uniform error for register; rate limits.

7. **Resource abuse** → huge `ContentSize` flood → hard size caps, per-IP throttling, timeouts.

**Acceptance:** 1.5–2.0 pages, crisp, each item has a concrete exploit sketch and a specific fix.

---

## 9) Packaging & Dry-Run (final zip)

**Required tree:**

`src/server/server.py`, `src/server/myport.info` (ASCII port; default 1357 if unreadable), `src/client/main.cpp`, `src/client/server.info` (ASCII `IP:PORT`), `research/MAMAN15_Security_Analysis.pdf|docx`.

> **Note on `my.info` vs `me.info`:** the spec names **`my.info`** for the client file (username / UUID hex / Base64 private key). To be grader-proof, **read either** (`my.info` or `me.info`) but **write `my.info`** unless your instructor explicitly confirmed otherwise. This avoids mismatches during grading.

### 9.1) One-screen README (≤1 page)

- **Server:** Python 3.12 stdlib only.

  - RAM mode: `python server.py` (Version=1).

  - DB mode: `python server.py --sqlite` (creates `defensive.db`, Version=2).

- **Client (Windows, VS 2019/2022):** build with Crypto++ 8.8+, link `cryptlib.lib`, `Ws2_32.lib`, `Bcrypt.lib` (if needed).

- **Runtime files:** `server.info`, `my.info`.

- **Menu & exact strings**, including `-----<EOM>-----`, `server responded with an error`, `can't decrypt message`, `file not found`.

### 9.2) Final dry-run checklist

- **M1–M5:** happy path + negative paths, pop semantics verified.

- **DB mode:** restart → users/messages persist; server advertises Version=2.

- **153:** ASCII path check, temp save, full path printed, client advertises Version=2.

- **Zip:** only the allowed source files + research doc; runs clean on grader's Windows machine (VS 2019 Community).

---

### Tiny patch hints (so edits stay lean)

- **Server versioning (RAM/DB):**

  ```python
  use_sqlite = "--sqlite" in sys.argv
  RESP_VER = 2 if use_sqlite else 1
  # pack_resp(RESP_VER, code, payload)
  ```

- **Client versioning (153 present):**

  ```cpp
  constexpr uint8_t CLIENT_VERSION = 2; // set to 1 if you compile without 153
  ```

- **%TMP% path (C++):**

  ```cpp
  char* tmp = std::getenv("TMP"); if(!tmp) tmp = std::getenv("TEMP");
  // fallback to C:\Windows\Temp if both null
  ```

That's everything needed, **as lean as possible**, to add **SQLite (10 pts), File transfer (10 pts), and the Q2 analysis (20%)** while keeping all base behavior byte-accurate for grading.
