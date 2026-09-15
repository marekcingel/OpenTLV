cmake_minimum_required(VERSION 3.16)
project(test_package LANGUAGES C)

find_package(OpenTLV REQUIRED CONFIG)

add_executable(test_package_c test_package.c)
target_link_libraries(test_package_c PRIVATE OpenTLV::tlv)

if(TARGET OpenTLV::tlvpp)
    enable_language(CXX)
    add_executable(test_package_cpp test_package.cpp)
    target_link_libraries(test_package_cpp PRIVATE OpenTLV::tlvpp)
endif()
