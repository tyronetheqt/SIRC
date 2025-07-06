#include "common.h"
#include "server/server.h"
#include "client/client.h"
#include <iostream>
#include <string>
#include <limits>

std::mutex console_mutex;
std::queue<std::string> incoming_messages_queue;
std::mutex incoming_messages_mutex;
std::condition_variable incoming_messages_cv;

int main(int argc, char* argv[]) {
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

    std::cout << "main: application exiting..." << std::endl;

    return app_result;
}