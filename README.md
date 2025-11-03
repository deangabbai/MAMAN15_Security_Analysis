# MessageU Milestones 1-5 (Minimal)

This repository contains the leanest implementation that satisfies Milestones 1–5 of the MessageU assignment.
Only two source files and two configuration files are needed for the base spec.

## Layout

```
src/
├─ server/
│  ├─ server.py       # all protocol logic, RAM storage, handlers 600–604
│  └─ myport.info     # ASCII port (defaults to 1357 if unreadable)
└─ client/
   ├─ main.cpp        # Winsock client, menu 110–152, AES/RSA/Base64, me.info I/O
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
uv run python src/server/server.py
```

* Reads `myport.info` (falls back to 1357 with a warning if missing/malformed).
* Implements request/response packing, threading per connection, RAM storage, and handlers 600–604.
* Always responds with Version=1.
* Lint with `uv run ruff check src/server`.

## Client (Windows, VS 2022, Crypto++)

```powershell
cmake --preset windows-msvc-x64
cmake --build --preset windows-msvc-x64 --config Release
```

* Single translation unit (`src/client/main.cpp`) performing Winsock networking, LE packing,
  AES-128-CBC (IV=0), RSA-1024, Base64, and menu actions 110–152.
* Runtime files: `server.info`, `me.info` (created on first register).
* Exact strings required by the spec are emitted, including
  `server responded with an error`, `Request for symmetric key`, `symmetric key received.`,
  `can't decrypt message`, and the delimiter `-----<EOM>-----`.

## Manual Test Checklist (M1–M5)

1. Register two fresh clients (110) → each creates `me.info` and receives unique IDs.
2. Client B lists clients (120) → requester excluded, cache mappings.
3. Client B retrieves Client A public key (130).
4. Client B sends Type-1 request (151); Client A fetches (140) and sees `Request for symmetric key`.
5. Client A fetches B’s key (130), sends Type-2 key (152); Client B fetches (140) and prints `symmetric key received.`.
6. Exchange encrypted text (150/140) successfully; missing keys trigger `can't decrypt message`.
7. Negative paths: duplicate username, malformed payload sizes, unknown IDs, wrong sizes → server replies 9000 and client prints `server responded with an error`.

This baseline is intentionally compact so that later milestones (SQLite persistence, file transfer, security analysis) can build on top of it without undoing excess structure.
