cmake_minimum_required(VERSION 3.16)

project(test-tlv++ LANGUAGES CXX)

set(HEADERS
)

set(SOURCES
    src/test_tlvpp.cpp
)

add_executable(${PROJECT_NAME}
    ${HEADERS}
    ${SOURCES}
)

target_compile_features(${PROJECT_NAME} PRIVATE
    cxx_std_23
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    tlv++
)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
