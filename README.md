# MessageU Milestones 1–7 (Minimal + Bonuses)

This repository contains the lean implementation that satisfies MessageU milestones 1–7:
RAM server, SQLite persistence, and the file-transfer bonus. Only the required source and
configuration files are shipped.

## Layout

```text
src/
├─ server/
│  ├─ server.py       # handlers 600–604, RAM/SQLite storage, CLI --sqlite flag
│  └─ myport.info     # ASCII port (defaults to 1357 if unreadable)
└─ client/
   ├─ main.cpp        # Winsock client, menu 110–153, AES/RSA/Base64, file transfer
   └─ server.info     # ASCII "IP:PORT" (e.g., 127.0.0.1:1357)
```

`me.info` is generated after the first successful Register (110) and must contain:

1. Username (ASCII)
2. 32-character uppercase hex ClientID
3. Base64 private key

## Server (Python 3.12, stdlib only)

```bash
uv venv
uv pip install ruff
# RAM mode (Version=1)
uv run python src/server/server.py
# SQLite mode (Version=2, persists to defensive.db)
uv run python src/server/server.py --sqlite
```

- Reads `myport.info`; default port 1357 if the file is missing or invalid.
- Validates every payload and responds with 9000 on malformed input.
- `--sqlite` enables persistent storage with the schema mandated by the assignment (queues pop on fetch).
- Lint with `uv run ruff check src/server` and format with `uv run ruff format src/server`.

## Client (Windows, VS 2022, Crypto++)

```powershell
cmake --preset windows-msvc-x64
cmake --build --preset windows-msvc-x64 --config Release
```

- Single translation unit performing Winsock networking, LE packing, AES-128-CBC (IV=0),
  RSA-1024, Base64, and menu actions 110–153.
- Runtime files: `server.info`, `me.info` (created after register).
- Emits the exact strings required by the spec: `server responded with an error`,
  `Request for symmetric key`, `symmetric key received.`, `can't decrypt message`,
  `file not found`, and the delimiter `-----<EOM>-----`.
- File transfer (153) encrypts with the cached AES key, uploads via message type 4, and saves
  incoming files under `%TMP%/MessageU_XXXXXXXX.tmp`, printing the absolute path.

## Quickstart

### Core (RAM server, text messaging)

1. Start the server (port from `src/server/myport.info`, defaults to 1357):

   ```powershell
   python src/server/server.py
   ```

2. Build the client (once):

   ```powershell
   cmake --preset windows-msvc-x64
   cmake --build --preset windows-msvc-x64 --config Release
   ```

3. Prepare two client folders and copy `MessageUClient.exe` and `server.info`:

   ```powershell
   New-Item -ItemType Directory build\runA, build\runB | Out-Null
   Copy-Item build\msvc-x64\Release\MessageUClient.exe build\runA\
   Copy-Item build\msvc-x64\Release\MessageUClient.exe build\runB\
   Copy-Item src\client\server.info build\runA\
   Copy-Item src\client\server.info build\runB\
   ```

4. Run Client A (register Alice → 110):

   ```powershell
   cd build\runA
   ./MessageUClient.exe
   # 110 → Alice → 0
   ```

5. Run Client B (register Bob → 110; list → 120; get Alice key → 130; request key → 151):

   ```powershell
   cd ..\runB
   ./MessageUClient.exe
   # 110 → Bob
   # 120
   # 130 → Alice
   # 151 → Alice
   # 0
   ```

6. Back on Client A, fetch (140) to see: `Request for symmetric key`; then `130 → Bob`, `152 → Bob`.

7. On Client B, fetch (140) to see: `symmetric key received.`; send text (150 → Alice) and on A fetch (140) to read it.

Notes:

- Without a cached key, text decryption prints `can't decrypt message` as required.
- Server errors surface as `server responded with an error`.

### Bonuses

#### A) SQLite persistence (Server Version=2)

1. Start server with SQLite (persists to `src/server/defensive.db`):

   ```powershell
   python src/server/server.py --sqlite
   ```

2. Point clients to the server port in their local `server.info` and repeat the core flow.
3. Stop and restart the server; verify clients list (120) persists across restarts.

#### B) File transfer (153)

Prereq: A cached AES key between the two users (perform 151/152 first).

1. On sender, choose `153) Send a file`, input receiver username and an ASCII path to a regular file.
   - Bad path prints `file not found`.
2. On receiver, fetch (140). For Type-4, client prints the full saved path under `%TMP%`.

## Manual Test Checklist (M1–M7)

1. Register two fresh clients (110) → each creates `me.info` with a unique ID.
2. Client B lists clients (120) → requester excluded, mappings cached.
3. Client B retrieves Client A public key (130).
4. Client B sends Type-1 request (151); Client A fetches (140) and sees `Request for symmetric key`.
5. Client A fetches B’s key (130), sends Type-2 key (152); Client B fetches (140) and prints `symmetric key received.`.
6. Exchange encrypted text (150/140); without a cached key the client prints `can't decrypt message`.
7. Run the server with `--sqlite`, repeat register/list/send, restart, and verify data persists.
8. Exchange a file (153/140) with a cached AES key → sender prints `File sent.`, receiver prints the saved temp path.
9. Negative paths: duplicate username, malformed payload sizes, unknown IDs, wrong sizes → server replies 9000 and the client
   prints `server responded with an error`; decrypt failures show `can't decrypt message`; bad file paths show `file not found`.
