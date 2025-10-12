cmake_minimum_required(VERSION 3.20)

project(ChanceCode LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(chancecode_core
    src/backend.c
    src/bytecode.c
    src/diagnostics.c
    src/loader.c
)

target_include_directories(chancecode_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_library(chancecode_backends
    backends/backend_x86.c
    backends/builtins.c
)

target_link_libraries(chancecode_backends
    PUBLIC
        chancecode_core
)

target_include_directories(chancecode_backends
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(chancecodec
    src/cli.c
)

target_link_libraries(chancecodec
    PRIVATE
        chancecode_core
        chancecode_backends
)

install(TARGETS chancecodec RUNTIME DESTINATION bin)

option(CHANCECODE_BUILD_TESTS "Build ChanceCode tests" ON)

if (CHANCECODE_BUILD_TESTS)
    include(CTest)
    add_subdirectory(tests)
endif()
