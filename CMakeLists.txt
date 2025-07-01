cmake_minimum_required(VERSION 3.10)
project(pe_dumper_linux)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(pedumper src/pedumper.cpp)