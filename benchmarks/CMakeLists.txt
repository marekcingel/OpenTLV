cmake_minimum_required(VERSION 3.16)

project(benchmark-tlv LANGUAGES CXX)

include(FetchContent)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    googlebenchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.9.4
)
FetchContent_MakeAvailable(googlebenchmark)

add_executable(${PROJECT_NAME}
    src/tlv_benchmarks.cpp
)

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_11)

target_link_libraries(${PROJECT_NAME} PRIVATE
    tlv
    benchmark::benchmark_main
)

opentlv_configure_compiler(${PROJECT_NAME})
