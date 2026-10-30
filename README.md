# CCP-1.0 — Python Client–Server Communication System

**A socket-based messaging prototype exploring custom application protocols, concurrent networking, persistence, and peer-to-peer file transfer.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Overview

CCP-1.0 is a command-line communication application built in Python. It demonstrates how a central server can coordinate multiple clients using **TCP sockets**, while **UDP** carries lightweight typing notifications and direct **TCP peer-to-peer connections** transfer files between clients.

The project uses a custom text-based protocol (`CCP/1.0`) and SQLite to manage user accounts and group memberships. It is a learning and portfolio project, **not a production-ready or encrypted messaging platform**.

## Features

- **Multi-client server:** A separate thread handles each incoming TCP client connection.
- **User accounts:** Sign in or create an account, with credentials checked against SQLite-stored password hashes.
- **Messaging:** Route direct, group, and broadcast messages through the server.
- **Group membership:** Join, leave, and list groups; membership is stored in SQLite.
- **User discovery:** Request online-user lists and user details with `WHOIS`.
- **UDP notifications:** Relay lightweight typing notifications to connected clients.
- **Peer-to-peer file transfer:** The server coordinates a file request; the sender then connects directly to the recipient over TCP.
- **Terminal interface:** Timestamped, colour-coded command-line output.

> **Implementation status:** Some user-interface and protocol behaviours are still prototype-level. The numbered recipient menu currently contains placeholder entries, and the client does not yet provide a complete interactive workflow for every server-supported command. See [Known limitations](#known-limitations-and-future-improvements).

## Tech stack

| Technology | Purpose |
| --- | --- |
| Python | Application logic |
| TCP sockets (`socket`) | Client–server messaging and direct file transfers |
| UDP sockets | Lightweight notifications |
| `threading` | Concurrent client connections and receiver loops |
| SQLite (`sqlite3`) | User and group data |
| `hashlib` | Basic password hashing in this prototype |
| `colorama` | Coloured terminal output |
| `keyboard` | Client keyboard event handling |

## Architecture

```text
                  +-----------------------+
                  |    CCP-1.0 Server     |
                  | TCP 12345 / UDP 12346|
                  |                       |
                  | - Authentication      |
                  | - Message routing     |
                  | - Group membership    |
                  | - File coordination   |
                  +-----------+-----------+
                              |
                         SQLite DB
                              |
           TCP messages       |        TCP messages
    +-------------------------+-------------------------+
    |                                                   |
+---+----------------+                       +----------+---------+
| Client A           |                       | Client B           |
| - TCP messaging    |                       | - TCP messaging    |
| - UDP notifications|                       | - UDP notifications|
| - P2P TCP listener |<--- direct TCP ----->| - P2P TCP listener |
+--------------------+   file transfer       +--------------------+
```

The server authenticates clients and coordinates messaging. Each client opens its own UDP socket and peer-to-peer TCP listener. A separate database module stores persistent account and group information.

## Repository structure

```text
CCP-1.0/
├── client.py              # Terminal client, messaging, UDP and P2P transfers
├── server.py              # Concurrent TCP server and UDP relay
├── protocol.py            # CCP/1.0 message encoding and parsing helpers
├── database.py            # SQLite schema and data-access operations
├── session_manager.py     # Active session management
├── seed_users.py          # Optional demo-account setup
├── chat_app.db            # Included SQLite database (development data)
├── Technical Reflection.pdf
└── LICENSE
```

## Getting started

### Requirements

- Python 3.8 or newer (the client uses assignment expressions)
- A terminal and network access between client and server
- Python packages: `colorama`, `keyboard`

### Installation

```bash
git clone https://github.com/cibanesandiswa4-arc/CCP-1.0.git
cd CCP-1.0
python -m pip install colorama keyboard
```

### Start the server

In one terminal, run:

```bash
python server.py
```

The server listens on **TCP port 12345** and **UDP port 12346**. It creates any missing database tables when started.

### Start clients

Open another terminal (and additional terminals for multiple clients):

```bash
python client.py
```

Enter a username, the server IP address (`127.0.0.1` for local testing), and a password. New usernames are automatically registered by the server. For testing across devices, use the server machine's LAN IP and allow the relevant ports through the firewall.

**Optional demo accounts:** Run `python seed_users.py` before starting the server to add sample users. The script prints their demo credentials. Do not use these accounts in a public deployment.

> **Testing note:** This is a prototype. Some client interactions may require further implementation or debugging, particularly the placeholder recipient menu and file-request initiation.

## CCP/1.0 protocol

The application defines a simple text-based message format with a command/status line, headers, a blank line, and an optional body. Commands implemented on the server include `LOGIN`, `REGISTER`, `LIST_USERS`, `LIST_GROUPS`, `JOIN_GROUP`, `LEAVE_GROUP`, `WHOIS`, and `FILE_REQUEST`; messages use `DATA MESSAGE`.

The `protocol.py` module provides helpers to build responses and receive framed messages. **Framing is not yet fully consistent:** some manually constructed messages use `Length`, while the helper emits `Content-Length`. Standardising framing and handling partial or coalesced TCP reads are important next steps.

## Engineering skills demonstrated

- **Network programming:** Working with TCP and UDP sockets and client–server communication.
- **Concurrency:** Coordinating multiple client sessions with Python threads.
- **Protocol design:** Defining and parsing custom application-level commands and headers.
- **Data persistence:** Modelling users and group membership in a relational SQLite database.
- **Modular design:** Separating client, server, protocol, database, and session responsibilities.
- **Systems thinking:** Combining central coordination with direct peer-to-peer data transfer.

## Known limitations and future improvements

This project intentionally documents areas that would need attention before production use:

1. **Security:** Passwords are currently hashed with unsalted SHA-256, and messages/files are not encrypted. Adopt a password-specific KDF (such as Argon2id) and authenticated transport encryption.
2. **Protocol reliability:** Standardise length headers, use byte lengths, and robustly handle TCP fragmentation, multiple frames, malformed requests, and disconnects.
3. **Client completeness:** Replace placeholder recipient lists with parsed server responses and add usable commands for joining groups, looking up users, and requesting files.
4. **Session safety:** Protect shared session state against concurrent modifications and handle reconnects and duplicate usernames.
5. **File transfers:** Add explicit acceptance, filenames and metadata, size limits, integrity checks, and failure recovery.
6. **Testing and delivery:** Add automated tests, dependency pinning, structured logging, and CI checks.

## Project documentation

For additional background and reflection on the implementation, see [Technical Reflection.pdf](Technical%20Reflection.pdf).

## Author

**Sandiswa Cibane**  
[GitHub profile](https://github.com/cibanesandiswa4-arc)

## License

Distributed under the [MIT License](LICENSE).
