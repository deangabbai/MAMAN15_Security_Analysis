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

Bonuses (SQLite persistence, file transfer 153, security analysis) are handled **after** this minimal base.

---

## 1) Protocol (binary over TCP, little-endian)

All numeric fields are **unsigned, little-endian**.
**PayloadSize may be 0** where specified below.

**Request header (client → server):** `<16sBHI>` (ClientID, Version, Code, PayloadSize). Client version is always **1** for milestones 1–5.

**Response header (server → client):** `<BHI>` (Version, Code, PayloadSize). Server version is always **1** in RAM mode.

### Request codes

* **600 Register** → payload `Name[255 ASCII + NUL] + PublicKey[160]` (server ignores header ClientID)
* **601 Clients list** → **no payload** (`PayloadSize = 0`)
* **602 Public key** → payload `ClientID[16]`
* **603 Send message** → payload `ToClientID[16] + MsgType[1] + ContentSize[4] + Content`
* **604 Fetch waiting messages** → **no payload** (`PayloadSize = 0`)

### Response codes

* **2100 Register OK** → payload `ClientID[16]`
* **2101 Clients list** → repeated `(ClientID[16] + Name[255 ASCII + NUL])`
* **2102 Public key** → payload `ClientID[16] + PublicKey[160]`
* **2103 Message accepted** → payload `ToClientID[16] + MessageID[4]`
* **2104 Waiting messages** → repeated `(FromID[16] + MessageID[4] + Type[1] + Size[4] + Content)`
* **9000 General error** → **no payload** (`PayloadSize = 0`)

### Message types (M1–M5)

1. **Request symmetric key** → `ContentSize = 0`
2. **Send symmetric key** → content is AES key encrypted with receiver’s RSA public key
3. **Text message** → content is AES-128-CBC ciphertext (shared key)

---

## 2) Cryptography (client-side E2E)

* Symmetric: **AES-128-CBC**, IV = 16 zero bytes
* Asymmetric: **RSA-1024** keypair; public key on the wire is **160 bytes** (128-byte modulus + 32-byte exponent)
* Library: **Crypto++ ≥ 8.8**

### Key lifecycle

1. On first run, generate RSA keypair
2. Store Base64 private key (line 3 of `me.info`)
3. Publish 160-byte public key during Register

### Symmetric key exchange

* Type-1: sender requests key (empty content)
* Type-2: sender generates random 16-byte AES key, encrypts with receiver’s public key, caches result
* Type-3: encrypted text exchange using cached AES key

---

## 3) Server (Python 3.12, stdlib only)

All logic lives in `server.py`:

* constants, pack/unpack helpers, threading, RAM storage class, handlers 600–604
* reads `myport.info`; on failure logs warning and defaults to port **1357**
* validates every payload (sizes, ASCII, type range, content size match)
* returns **9000** on malformed input or unknown codes; response **Version=1**
* **exception-based error handling:** try/except around socket I/O, struct pack/unpack, and validators; log and send **9000**, or close gracefully on unrecoverable errors

Run: `uv run python src/server/server.py`
Lint: `uv run ruff check src/server`

---

## 4) Client (C++17, Windows, single translation unit)

All logic lives in `main.cpp`:

* Winsock setup/teardown, LE pack/unpack helpers
* Blocking `sendAll/recvAll` TCP wrapper
* Crypto++ AES/RSA/Base64 helpers
* `KeyStore` for `me.info` (ASCII only), caches name↔ID, public keys, AES keys
* **OOP with inheritance & polymorphism:** `Command` base with virtual `run()`; derived commands (Register, ListClients, etc.) invoked polymorphically
* **exception-based error handling:** try/catch for socket, crypto, file I/O, validation; friendly termination on unrecoverables

**Banner & menu (M1–M5, Version=1):**

```text
MessageU client at your service.
110) Register
120) Clients list
130) Public key
140) Fetch waiting messages
150) Send message
151) Send symmetric key request
152) Send symmetric key
```

**2104 print format (for each message):**

```text
From: <sender_username>
Content:
<message_content>
.
.
-----<EOM>-----
```

* Type-1 → `Request for symmetric key`
* Type-2 → `symmetric key received.`
* Type-3 decrypt failure → `can't decrypt message`

Error responses:

* On 9000 → `server responded with an error`
* Decrypt failure → `can't decrypt message`

**Runtime files:**
`server.info` (ASCII `IP:PORT`)
`me.info` (created after Register; blocks re-register if present)

CMake links Crypto++ plus `Ws2_32` and `Bcrypt`.

---

## 5) End-to-End Flow (Happy Path)

1. Client A registers → receives new ClientID and writes `me.info`
2. Client B registers → same
3. B lists clients (120) → learns A’s name/ID
4. B fetches A’s public key (130)
5. B sends Type-1 message (151)
6. A fetches waiting messages (140) → sees `Request for symmetric key`
7. A fetches B’s public key (130), sends AES key (152)
8. B fetches waiting messages (140) → caches AES key and prints `symmetric key received.`
9. Both exchange text via 150/140 with AES encryption

---

## 5A) Negative Paths & Error Coverage

* Duplicate username register → server returns **9000**; client prints `server responded with an error`
* `me.info` present → client refuses Register
* Malformed payload sizes, unknown codes, unsupported message types, content-size mismatch → **9000**
* Missing AES key for Type-3 → client prints `can't decrypt message`
* **2104 pop semantics:** after fetch, queue is empty on immediate re-fetch

---

## 5B) Tooling & Packaging Checklist

* Server: `uv venv`, `uv pip install ruff`, `uv run python src/server/server.py`
* Client: `cmake --preset windows-msvc-x64`, `cmake --build --preset windows-msvc-x64 --config Release`
* **Ship only:** `src/server/server.py`, `src/server/myport.info`, `src/client/main.cpp`, `src/client/server.info` (and runtime-generated `me.info` only if the grader explicitly asks)
* README ≤1 page: setup, usage, exact strings, manual test outline

This minimal baseline earns full credit for **Milestones 1–5** and leaves a clean foundation for bonuses.

---

## Part 2: Bonuses, File Transfer & Security Analysis (Milestones 6–9)

> Scope: SQLite persistence (10 pts), File transfer (10 pts), Security analysis (20%).

### 6) Bonus A — SQLite Persistence (Server v2)

**Goal:** same behavior as RAM server, but data lives in `defensive.db`. **Server Version = 2** only when DB mode is on.

* Flag/env `--sqlite` toggles storage
* `sqlite3.connect("defensive.db")`; `PRAGMA foreign_keys=ON`
* Tables:

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

* Storage API mirrors RAM: `add_client`, `get_client_by_*`, `list_clients_except`, `add_message -> id`, `pop_all_messages_for(to)` (**delete after return**)
* In DB mode: set response **Version=2**; codes unchanged
* Acceptance: first run creates DB; restart persists; `2104` still pops

### 7) Bonus B — File Transfer (Client v2)

**Goal:** add `153) Send a file`, use **Message Type = 4**, enforce ASCII path, save to `%TMP%`. **Client Version = 2** when 153 exists.

* Menu: append exactly `153) Send a file`
* Version: request header **Version=2** when 153 compiled in
* Send (153): resolve user → absolute ASCII path → if bad print `file not found`; encrypt bytes with AES key; send **603** with `Type=4`, `ContentSize=len(cipher)`
* Receive (140, Type=4): decrypt or print `can't decrypt message`; else write under `%TMP%` (e.g., `MessageU_XXXX.tmp`) and **print full saved path**
* Server validator for 603 in bonus build: allow `Type ∈ {1,2,3,4}`

### 8) Q2 — Security Analysis (2 pages)

Each item: **Weakness → Concrete attack → Mitigation** (2–4 sentences).

1. No integrity (CBC only) → bit-flip/padding oracle → HMAC-SHA256 over header+payload or AES-GCM
2. Fixed zero IV + reuse → pattern leakage → random per-message IV (prepend IV)
3. RSA-1024 → low margin → RSA-2048/3072 or X25519 KEM + AEAD
4. No replay protection → duplicate 152/150/153 → per-peer counter/nonce, reject stale
5. No server auth → MITM on 602/603/604 → TLS or server-signed responses; client pinning
6. Username enumeration → timing/explicit errors → uniform errors + rate limits
7. Resource abuse → huge `ContentSize` → hard caps, throttling, timeouts

### 9) Packaging & Dry-Run (final zip)

**Required tree:**

```text
src/server/server.py
src/server/myport.info
src/client/main.cpp
src/client/server.info
research/MAMAN15_Security_Analysis.pdf|docx
```

**README (≤1 page):**

* **Server:** Python 3.12 stdlib only

  * RAM: `python server.py` (Version=1)
  * DB:  `python server.py --sqlite` (creates `defensive.db`, Version=2)
* **Client (Windows, VS 2019/2022):** Crypto++ 8.8+, link `cryptlib.lib`, `Ws2_32.lib`, `Bcrypt.lib`
* **Runtime files:** `server.info`, **`me.info`**
* **Exact strings:** `-----<EOM>-----`, `server responded with an error`, `can't decrypt message`, `file not found` (153 only)

### Dry-run Checklist

* **M1–M5:** happy path + negatives; pop semantics verified
* **DB mode:** restart persists; server advertises Version=2
* **153 (bonus build):** ASCII path check, temp save, full path printed, Version=2
* **Zip:** only allowed source files + research doc; runs clean on grader’s Windows machine

---

**Status:** All mandatory edits are applied (zero-length payloads, 153 deferred to bonuses with Version=2, `me.info` only). This is ready.
