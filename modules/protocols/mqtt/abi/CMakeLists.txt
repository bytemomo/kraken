cmake_minimum_required(VERSION 3.16)
project(kraken_mqtt_modules C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_subdirectory(mqtt_acl_probe)
add_subdirectory(mqtt_auth_check)
add_subdirectory(mqtt_replay)
add_subdirectory(mqtt_sys_disclosure)
