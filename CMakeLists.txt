cmake_minimum_required(VERSION 3.6)
project(4vpn)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp unp.h error_check.cpp 4over6_server.cpp 4over6_util.h 4over6_util.cpp keep_alive_thread.cpp  tundemo.cpp test_server_nat.cpp test_server_nat.h )
add_executable(4vpn ${SOURCE_FILES})