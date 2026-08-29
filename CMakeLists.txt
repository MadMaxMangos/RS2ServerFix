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

set(RS2_PR1_BASELINE_PATH "" CACHE FILEPATH
  "Preserved PR1 stock executable used by verification tests")
set(RS2_CURRENT_STOCK_PATH "" CACHE FILEPATH
  "Current stock executable used by verification tests")

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

function(rs2_configure_hardened_dll target output_name)
  rs2_configure_target(${target})
  set_target_properties(${target} PROPERTIES
    OUTPUT_NAME "${output_name}")
  target_link_options(${target} PRIVATE
    /DYNAMICBASE
    /NXCOMPAT
    /HIGHENTROPYVA)
endfunction()

add_library(rs2_server_fix_companion SHARED
  src/companion/RS2ServerFix.def
  src/companion/build_identity.cpp
  src/companion/companion_init.cpp
  src/companion/companion_main.cpp
  src/companion/marker.cpp
  src/companion/sha256.cpp
  src/shared/path_identity.cpp)
rs2_configure_hardened_dll(
  rs2_server_fix_companion RS2ServerFix)
target_link_libraries(rs2_server_fix_companion PRIVATE bcrypt)

add_library(rs2_faultrep_bootstrap SHARED
  src/bootstrap/bootstrap_main.cpp
  src/bootstrap/companion_loader.cpp
  src/bootstrap/faultrep.def
  src/bootstrap/forwarder.cpp
  src/bootstrap/genuine_resolver.cpp
  src/shared/path_identity.cpp)
rs2_configure_hardened_dll(rs2_faultrep_bootstrap faultrep)

add_executable(rs2_core_tests
  src/bootstrap/companion_loader.cpp
  src/bootstrap/forwarder.cpp
  src/bootstrap/genuine_resolver.cpp
  src/companion/build_identity.cpp
  src/companion/companion_init.cpp
  src/companion/marker.cpp
  src/companion/sha256.cpp
  src/shared/path_identity.cpp
  tests/core_tests.cpp)
rs2_configure_target(rs2_core_tests)
target_link_libraries(rs2_core_tests PRIVATE bcrypt)
add_dependencies(
  rs2_core_tests
  rs2_faultrep_bootstrap
  rs2_server_fix_companion)

if(BUILD_TESTING)
  if(RS2_PR1_BASELINE_PATH STREQUAL "" OR
     RS2_CURRENT_STOCK_PATH STREQUAL "")
    message(FATAL_ERROR
      "BUILD_TESTING requires RS2_PR1_BASELINE_PATH and RS2_CURRENT_STOCK_PATH")
  endif()
  target_compile_definitions(rs2_core_tests PRIVATE
    RS2_PR1_BASELINE_PATH=L\"${RS2_PR1_BASELINE_PATH}\"
    RS2_CURRENT_STOCK_PATH=L\"${RS2_CURRENT_STOCK_PATH}\")
endif()

add_test(NAME core COMMAND rs2_core_tests)

add_executable(rs2_pe_contract
  tools/pe_contract.cpp
  tools/pe_reader.cpp)
rs2_configure_target(rs2_pe_contract)
target_include_directories(rs2_pe_contract PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/tools)

add_test(NAME pe_bootstrap_contract
  COMMAND rs2_pe_contract
          bootstrap
          $<TARGET_FILE:rs2_faultrep_bootstrap>)
add_test(NAME pe_companion_contract
  COMMAND rs2_pe_contract
          companion
          $<TARGET_FILE:rs2_server_fix_companion>)

add_executable(rs2_static_import_harness
  src/shared/path_identity.cpp
  tests/static_import_harness.cpp)
rs2_configure_target(rs2_static_import_harness)
set(_rs2_windows_kits_roots
  "$ENV{ProgramFiles\(x86\)}/Windows Kits/10"
  "$ENV{ProgramFiles}/Windows Kits/10")
find_library(RS2_SYSTEM_FAULTREP_IMPORT_LIBRARY
  NAMES FaultRep
  PATHS ${_rs2_windows_kits_roots}
  PATH_SUFFIXES
    "Lib/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/um/x64"
  NO_DEFAULT_PATH
  REQUIRED)
target_link_libraries(rs2_static_import_harness PRIVATE
  "${RS2_SYSTEM_FAULTREP_IMPORT_LIBRARY}")
target_link_options(rs2_static_import_harness PRIVATE
  /DYNAMICBASE
  /NXCOMPAT
  /HIGHENTROPYVA)

add_executable(rs2_static_import_runner
  tests/static_import_runner.cpp)
rs2_configure_target(rs2_static_import_runner)
add_dependencies(
  rs2_static_import_runner
  rs2_static_import_harness
  rs2_faultrep_bootstrap
  rs2_server_fix_companion)

add_test(NAME pe_harness_contract
  COMMAND rs2_pe_contract
          harness
          $<TARGET_FILE:rs2_static_import_harness>)
add_test(NAME static_import_cases
  COMMAND rs2_static_import_runner
          $<TARGET_FILE:rs2_static_import_harness>
          $<TARGET_FILE:rs2_faultrep_bootstrap>
          $<TARGET_FILE:rs2_server_fix_companion>)

add_executable(rs2_deployment_preflight
  tools/deployment_preflight.cpp
  tools/pe_reader.cpp)
rs2_configure_target(rs2_deployment_preflight)
target_include_directories(rs2_deployment_preflight PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/tools)

add_executable(rs2_preflight_fixture_test
  tests/preflight_fixture_test.cpp)
rs2_configure_target(rs2_preflight_fixture_test)
add_dependencies(
  rs2_preflight_fixture_test
  rs2_deployment_preflight
  rs2_static_import_harness)

add_test(NAME preflight_fixture
  COMMAND rs2_preflight_fixture_test
          $<TARGET_FILE:rs2_deployment_preflight>
          $<TARGET_FILE:rs2_static_import_harness>)
