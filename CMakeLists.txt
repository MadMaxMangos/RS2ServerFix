cmake_minimum_required(VERSION 3.24)

project(RS2ServerFix LANGUAGES CXX)

if(NOT MSVC)
  message(FATAL_ERROR "RS2ServerFix Stage 0 requires the MSVC toolchain")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include(CTest)

function(rs2_configure_target target)
  target_compile_definitions(${target} PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX)
  target_compile_options(${target} PRIVATE
    /W4
    /WX
    /permissive-
    /Zc:__cplusplus)
  target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
endfunction()

add_executable(rs2_core_tests
  src/companion/build_identity.cpp
  tests/core_tests.cpp)
rs2_configure_target(rs2_core_tests)

add_test(NAME core COMMAND rs2_core_tests)
