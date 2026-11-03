cmake_minimum_required(VERSION 3.16)
project(cfgparse VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "Emit compile_commands.json")

add_library(cfgparse STATIC
  src/config_parser.cpp
)

target_include_directories(cfgparse PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(cfgparse PRIVATE -Wall -Wextra)
endif()
