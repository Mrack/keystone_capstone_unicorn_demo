cmake_minimum_required(VERSION 3.1)
project(unicorn_demo)

set(CMAKE_CXX_STANDARD 20)


include_directories(
        include
)
add_executable(unicorn_demo main.cpp)
target_link_libraries(unicorn_demo
        ..\\lib\\unicorn_static.lib
        ..\\lib\\capstone.lib
        ..\\lib\\keystone.lib)