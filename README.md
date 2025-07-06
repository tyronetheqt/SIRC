# SIRC - shitty irc (internet relay chat)

## Overview

This project implements a basic client-server chat application with a focus on secure communication using cryptographic principles. It features RSA for secure key exchange and AES-256 GCM for encrypted session communication. Users interact with the server via a command-line interface, sending commands and private messages.

## Features

* **Client-Server Architecture:** A dedicated server + client application in one compiled binary.
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
   * `JOIN <channel_name>`: Joins or creates a channel.
   * `LEAVE [<channel_name>]`: Leaves a specific channel, or your current channel if none is specified.
   * `LIST`: Lists all active channels.
   * `WHO <channel_name>`: Lists users in a specified channel.
   * `MSG #<channel_name> <message>`: Sends a message to a specific channel.
   * `CMDS` / `COMMANDS`: Lists all available commands.

## Technologies Used

* **Crypto++ Library:** For all cryptographic operations (RSA, AES-GCM, key generation, encoding/decoding).
* * **Boost.Asio:** For all low level network connections.

## How to Build

This project uses **CMake** as its build system and **vcpkg** for managing C++ dependencies (Crypto++ and Boost.Asio).

### Prerequisites

1.  **C++17 Compliant Compiler:**
    * **Windows:** MSVC (Visual Studio 2017 or newer), MinGW (g++ 7 or newer).
    * **Linux/macOS:** GCC (g++ 7 or newer), Clang (Clang 5 or newer).
2.  **CMake:** Version 3.15 or newer.
    * Download from [cmake.org](https://cmake.org/download/).
3.  **Vcpkg:** A C++ package manager.
    * **Clone vcpkg:**
        ```bash
        git clone [https://github.com/microsoft/vcpkg.git](https://github.com/microsoft/vcpkg.git)
        ```
    * **Bootstrap vcpkg:**
        ```bash
        cd vcpkg
        ./bootstrap-vcpkg.sh   # On Linux/macOS
        .\bootstrap-vcpkg.bat # On Windows
        ```
    * **Integrate vcpkg (optional but recommended for convenience):**
        This step allows CMake to automatically find vcpkg without manually specifying the toolchain file for every project.
        ```bash
        ./vcpkg integrate install
        ```

### Building the Project

1.  **Install Dependencies via Vcpkg:**
    Navigate to your `vcpkg` directory and install the required libraries.
    ```bash
    cd /path/to/your/vcpkg
    vcpkg install cryptopp boost-asio
    ```
    * For 64-bit builds (recommended): `vcpkg install cryptopp:x64-windows boost-asio:x64-windows` (Windows) or `vcpkg install cryptopp boost-asio` (Linux/macOS, it will default to appropriate triplet).
    * For static linking, add `-static` to the triplet, e.g., `cryptopp:x64-windows-static`.

2.  **Generate Build Files with CMake:**
    Navigate to the root of your project (where `CMakeLists.txt` is located).
    Create a `build` directory and run CMake from there.

    ```bash
    cd /path/to/your/project
    mkdir build
    cd build
    cmake .. -DCMAKE_TOOLCHAIN_FILE=/path/to/your/vcpkg/scripts/buildsystems/vcpkg.cmake
    ```
    * **Note:** Replace `/path/to/your/vcpkg` with the actual path to your vcpkg installation.
    * If you ran `vcpkg integrate install`, you might be able to omit `-DCMAKE_TOOLCHAIN_FILE` for some IDEs (like Visual Studio) or if vcpkg is in a default location. However, explicitly providing it is robust.

3.  **Build the Project:**
    After CMake has generated the build files, compile the project.

    ```bash
    cmake --build .
    ```
    This command will build the executables (e.g., `SIRC_Server` and `SIRC_Client` or similar, depending on your `CMakeLists.txt`).

Your executables will be located in the `build` directory (or a subdirectory like `build/Debug` or `build/Release` depending on your build type and platform).

## How to Run

1.  **Compile:** Build both the server and client executables.
2.  **Start the Server:**
    ```bash
    ./binary.exe server
    ```
    Example: `.\binary.exe server`
    The server will start listening for incoming connections.
3.  **Start Clients:**
    Open one or more separate command prompts/terminals for clients.
    ```bash
    ./binary.exe <server_ip_address> <your_username>
    ```
    Example: `.\binary.exe 127.0.0.1 Alice`
    The client will attempt to connect, perform key exchange, and then prompt for commands.

## Future Improvements

* **Cross-Platform Support:** Refactor networking code to use a cross-platform library (e.g., Boost.Asio, plain POSIX sockets for Linux/macOS).
* **Group Chat:** Implement a feature for public messages to all connected users.
* **User Management:** Add features like user registration, login, and password hashing.
* **Command Autocompletion/History:** Enhance the client-side user interface.
* **File Transfer:** Securely transfer files between clients.
* **Error Reporting:** More detailed and user-friendly error messages.

## License

This project is open-source and is licensed under GPL v3.0.
