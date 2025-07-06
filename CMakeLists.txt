cmake_minimum_required(VERSION 3.10)
project(SIRC CXX)

find_package(Boost 1.70 COMPONENTS system asio REQUIRED)
find_package(cryptopp REQUIRED)

add_executable(${PROJECT_NAME}
    main.cpp
    client/client.cpp
    server/server.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Boost::system
    Boost::asio
    cryptopp::cryptopp
)

set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 17)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_EXTENSIONS OFF)
if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4)
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