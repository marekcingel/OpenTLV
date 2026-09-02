cmake_minimum_required(VERSION 3.16)

project(tlv LANGUAGES C)

add_library(${PROJECT_NAME}
    src/reader.c
    src/writer.c
    src/error.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(${PROJECT_NAME} PUBLIC
    c_std_99
)
