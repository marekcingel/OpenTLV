cmake_minimum_required(VERSION 3.16)

project(tlv++ LANGUAGES CXX)

opentlv_check_compiler()

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME} INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(${PROJECT_NAME} INTERFACE
    tlv
)

target_compile_features(${PROJECT_NAME} INTERFACE
    cxx_std_11
)
