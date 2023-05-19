cmake_minimum_required(VERSION 3.10)
project(kcertifier)

set(CMAKE_CXX_STANDARD 11)
# set(CMAKE_CXX_STANDARD_REQUIRED YES)

# Build the executable
include_directories("./include")
file(GLOB srcs ./srcs/*/*.c ./srcs/*/*.cpp ./srcs/*/*/*.c)
add_executable(kcertifier ${srcs} keystone_api.cc)
