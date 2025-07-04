#define NOMINMAX
#include "common.h"
#include "server/server.h"
#include "client/client.h"
#include <limits>

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    int iresult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iresult != 0) {
        std::cerr << "main: WSAStartup failed: " << iresult << std::endl;
        return 1;
    }

    int app_result = 0;

    if (argc < 2) {
        std::cerr << "usage:" << std::endl;
        std::cerr << "  " << argv[0] << " server" << std::endl;
        std::cerr << "  " << argv[0] << " client <server_ip_address> <username>" << std::endl;
        app_result = 1;
    }
    else {
        std::string mode = argv[1];

        if (mode == "server") {
            if (argc != 2) {
                std::cerr << "usage for server: " << argv[0] << " server" << std::endl;
                app_result = 1;
            }
            else {
                app_result = runServer(port);
            }
        }
        else if (mode == "client") {
            if (argc != 4) {
                std::cerr << "usage for client: " << argv[0] << " client <server_ip_address> <username>" << std::endl;
                std::cerr << "  example: " << argv[0] << " client 127.0.0.1 Alice" << std::endl;
                app_result = 1;
            }
            else {
                std::string serverIp = argv[2];
                std::string clientUsername = argv[3];
                app_result = runClient(serverIp, port, clientUsername);
                if (app_result == 0) {
                    std::cout << "\nPress enter to exit the client application...";
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    std::cin.get();
                }
            }
        }
        else {
            std::cerr << "unknown mode: " << mode << std::endl;
            std::cerr << "usage:" << std::endl;
            std::cerr << "  " << argv[0] << " server" << std::endl;
            std::cerr << "  " << argv[0] << " client <server_ip_address> <username>" << std::endl;
            app_result = 1;
        }
    }

    std::cout << "main: cleaning up winsock..." << std::endl;
    WSACleanup();

    return app_result;
}