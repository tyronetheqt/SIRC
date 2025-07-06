# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(SIRC CXX) # Using 'SIRC' as your main project name

# Find Boost and Crypto++
find_package(Boost 1.70 COMPONENTS system asio REQUIRED)
find_package(cryptopp REQUIRED) # Assumes vcpkg installed Crypto++

# --- Single Combined Executable (Server & Client in one binary) ---
# IMPORTANT: List ALL .cpp files that make up your entire application here.
# This includes 'main.cpp', client-related .cpp files, and server-related .cpp files.
add_executable(${PROJECT_NAME}
    main.cpp
    client/client.cpp   # Assuming client.cpp is in a 'client' subdirectory
    server/server.cpp   # Assuming server.cpp is in a 'server' subdirectory
    # Add any other .cpp files that are part of your single binary here.
    # For example, if you have:
    #   - client_logic.cpp
    #   - server_handlers.cpp
    #   - shared_utils.cpp
    # you would add them here with their correct paths.
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Boost::system
    Boost::asio
    cryptopp::cryptopp # Link Crypto++ to the single binary
)

# Apply compiler settings for the single combined target
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_EXTENSIONS OFF)
if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
elseif (UNIX)
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Werror)
endif()
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    if (MSVC)
        target_compile_options(${PROJECT_NAME} PRIVATE /Zi)
        target_link_options(${PROJECT_NAME} PRIVATE /DEBUG)
    elseif (UNIX)
        target_compile_options(${PROJECT_NAME} PRIVATE -g)
    endif()
endif()