cmake_minimum_required(VERSION 3.16)
project(tlvlib VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "Emit compile_commands.json")

add_library(tlv STATIC
  src/tlv_decode.c
  src/tlv_record.c
  src/tlv_reader.c
)

target_include_directories(tlv
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(tlv PRIVATE -Wall -Wextra)
endif()
