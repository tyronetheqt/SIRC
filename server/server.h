#pragma once

int runServer(const std::string& port);

void handleClient(SOCKET clientSocket);