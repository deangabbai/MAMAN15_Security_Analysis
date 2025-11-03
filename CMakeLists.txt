cmake_minimum_required(VERSION 3.24)
project(MessageUClient LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(MessageUClient src/client/main.cpp)

find_package(cryptopp CONFIG REQUIRED)

target_link_libraries(MessageUClient PRIVATE cryptopp::cryptopp Ws2_32 Bcrypt)
