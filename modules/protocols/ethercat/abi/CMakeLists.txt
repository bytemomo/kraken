cmake_minimum_required(VERSION 3.10)
project(kraken_ethercat_modules C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

get_filename_component(ABI_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../kraken/pkg/moduleabi" ABSOLUTE)

add_library(ecat_inject SHARED ecat_inject.c)
target_include_directories(ecat_inject PRIVATE ${ABI_INCLUDE_DIR})

add_library(ecat_dos SHARED ecat_dos.c)
target_include_directories(ecat_dos PRIVATE ${ABI_INCLUDE_DIR})

add_library(ecat_mitm SHARED ecat_mitm.c)
target_include_directories(ecat_mitm PRIVATE ${ABI_INCLUDE_DIR})
