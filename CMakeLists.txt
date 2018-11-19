cmake_minimum_required(VERSION 3.12)
project(wifi-killer)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(TINS_LIBRARY tins)
find_library(PTHREAD_LIBRARY pthread)
set(SOURCE_FILES main.cpp DeauthSender.cpp DeauthSender.h)


add_executable(wifi-killer ${SOURCE_FILES})

target_link_libraries(wifi-killer "${PTHREAD_LIBRARY}")
target_link_libraries(wifi-killer "${TINS_LIBRARY}")
