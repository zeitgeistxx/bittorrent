cmake_minimum_required(VERSION 3.13)

project(bittorrent-starter-cpp)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(CURL REQUIRED)

file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

add_executable(bittorrent ${SOURCE_FILES})

target_link_libraries(bittorrent PRIVATE CURL::libcurl)
