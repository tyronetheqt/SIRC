# Secure Command-Line Chat Application

## Overview

This project implements a basic client-server chat application with a focus on secure communication using cryptographic principles. It features RSA for secure key exchange and AES-256 GCM for encrypted session communication. Users interact with the server via a command-line interface, sending commands and private messages.

## Features

* **Client-Server Architecture:** A dedicated server application manages connections and message routing for multiple clients.
* **Secure Key Exchange:** Utilizes **RSA asymmetric encryption** (2048-bit keys) for clients to securely exchange a symmetric session key with the server.
* **Authenticated Encryption:** All subsequent client-server communication is encrypted and authenticated using **AES-256 in GCM (Galois/Counter Mode)**, providing both confidentiality and integrity/authenticity.
* **Multi-threaded Design:**
    * The server spawns a new thread for each connected client, allowing it to handle multiple concurrent connections efficiently.
    * The client application uses separate threads for sending commands and continuously receiving messages from the server, ensuring a responsive user experience.
* **Basic Command Set:** Supports a variety of text-based commands:
    * `PING`: Checks server responsiveness.
    * `TIME`: Retrieves the current server time.
    * `STATUS`: Gets the server's operational status.
    * `ECHO <message>`: Server echoes back the provided message.
    * `RANDOM`: Generates a random number (1-100).
    * `MOTD`: Displays a "Message of the Day."
    * `UPTIME`: Shows how long the server has been running.
    * `ONLINE` / `USERS`: Lists currently connected users.
    * `MSG <username> <message>`: Sends a private message to a specific online user.
    * `CMDS` / `COMMANDS`: Lists all available commands.
* **Robust Error Handling:** Includes basic error handling for network operations and cryptographic failures.

## Technologies Used

* **Crypto++ Library:** For all cryptographic operations (RSA, AES-GCM, key generation, encoding/decoding).

## How to Build

This project requires the **Crypto++ library**. Ensure you have it installed and configured for your compiler. The networking code is specifically written for **Windows** using Winsock.

1.  **Install Crypto++:** Download and build Crypto++ according to its official documentation. You'll need its `.lib` files (or static `.a` files) and header files.
2.  **Compiler:** A C++17 compliant compiler (e.g., MSVC, MinGW with g++).
3.  **Project Setup:**
    * Create a new C++ project in your IDE (e.g., Visual Studio).
    * Add `server.cpp`, `client.cpp`, and `common.h` to your project.
    * Configure your project settings to link against the Crypto++ library and Winsock (`ws2_32.lib` for MSVC).
    * Ensure the Crypto++ header directories are included in your compiler's include paths.

**Example (Visual Studio Linker Settings):**

* **Additional Dependencies:** `ws2_32.lib;cryptlib.lib;` (replace `cryptlib.lib` with your Crypto++ library name if different)
* **Additional Library Directories:** Path to your Crypto++ `.lib` folder.
* **Additional Include Directories:** Path to your Crypto++ header folder.

## How to Run

1.  **Compile:** Build both the server and client executables.
2.  **Start the Server:**
    ```bash
    ./server.exe <port_number>
    ```
    Example: `.\server.exe 12345`
    The server will start listening for incoming connections.
3.  **Start Clients:**
    Open one or more separate command prompts/terminals for clients.
    ```bash
    ./client.exe <server_ip_address> <port_number> <your_username>
    ```
    Example: `.\client.exe 127.0.0.1 12345 Alice`
    The client will attempt to connect, perform key exchange, and then prompt for commands.

## Future Improvements

* **Cross-Platform Support:** Refactor networking code to use a cross-platform library (e.g., Boost.Asio, plain POSIX sockets for Linux/macOS).
* **Group Chat:** Implement a feature for public messages to all connected users.
* **User Management:** Add features like user registration, login, and password hashing.
* **Command Autocompletion/History:** Enhance the client-side user interface.
* **File Transfer:** Securely transfer files between clients.
* **Error Reporting:** More detailed and user-friendly error messages.

## License

This project is open-source and is GPL v3.0.
