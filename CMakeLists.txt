cmake_minimum_required(VERSION 3.24)
project(RS2ServerFix LANGUAGES CXX RC ASM_MASM)
if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "RS2ServerFix requires the AMD64 MSVC toolchain")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
include(CTest)

set(RS2_PR1_BASELINE_PATH "" CACHE FILEPATH "Preserved PR1 stock input; never executed")
set(RS2_CURRENT_STOCK_PATH "" CACHE FILEPATH "Preserved PR3 stock input; never executed")
set(RS2_CURRENT_FULLDUMP_PATH "" CACHE FILEPATH "Preserved approved PR3 full-dump input; never executed")
set(RS2_DOCUMENTATION_ROOT "" CACHE PATH "Optional external archive root containing docs/evidence for qualification audits")

function(rs2_configure_target target)
  target_compile_definitions(${target} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4;/WX;/permissive-;/Zc:__cplusplus>)
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/tools")
  target_link_options(${target} PRIVATE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /INCREMENTAL:NO)
endfunction()

function(rs2_resource target description filename type)
  set(RS2_RESOURCE_DESCRIPTION "${description}")
  set(RS2_RESOURCE_FILENAME "${filename}")
  set(RS2_RESOURCE_NAME "${target}")
  set(RS2_RESOURCE_FILETYPE "${type}")
  configure_file(src/shared/version.rc.in "${CMAKE_CURRENT_BINARY_DIR}/resources/${target}.rc" @ONLY)
  target_sources(${target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/resources/${target}.rc")
endfunction()

set(RS2_BOOTSTRAP_SOURCES
  src/bootstrap/bootstrap_main.cpp src/bootstrap/companion_loader.cpp
  src/bootstrap/genuine_resolver.cpp src/bootstrap/forwarder.cpp
  src/bootstrap/x3daudio.def src/shared/path_identity.cpp
  src/shared/thread_error_mode.cpp src/shared/startup_profile.cpp)
set(RS2_COMPANION_SOURCES
  src/companion/companion_main.cpp src/companion/companion_init.cpp
  src/companion/RS2ServerFix.def src/companion/build_identity.cpp
  src/companion/recon_fix.cpp src/companion/recon_types.cpp
  src/companion/sha256.cpp src/companion/host_hash.cpp
  src/companion/marker.cpp src/companion/console_status.cpp
  src/shared/digest.cpp src/shared/path_identity.cpp src/shared/startup_profile.cpp)

function(rs2_bootstrap target directory description)
  add_library(${target} SHARED ${RS2_BOOTSTRAP_SOURCES})
  rs2_configure_target(${target})
  set_target_properties(${target} PROPERTIES OUTPUT_NAME X3DAudio1_7
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${directory}/$<CONFIG>"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${directory}/$<CONFIG>")
  rs2_resource(${target} "${description}" "X3DAudio1_7.dll" VFT_DLL)
endfunction()
function(rs2_companion target directory description)
  add_library(${target} SHARED ${RS2_COMPANION_SOURCES})
  rs2_configure_target(${target})
  target_link_libraries(${target} PRIVATE bcrypt)
  set_target_properties(${target} PROPERTIES OUTPUT_NAME RS2ServerFix
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${directory}/$<CONFIG>"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${directory}/$<CONFIG>")
  rs2_resource(${target} "${description}" "RS2ServerFix.dll" VFT_DLL)
endfunction()

rs2_bootstrap(rs2_x3daudio_bootstrap production/bootstrap "RS2ServerFix X3Audio Startup Bootstrap")
rs2_companion(rs2_server_fix_companion production/passive "RS2ServerFix M1R Passive Companion")
rs2_companion(rs2_server_fix_companion_active production/active "RS2ServerFix M2 Active Companion")
target_compile_definitions(rs2_server_fix_companion_active PRIVATE RS2_RECON_ACTIVE)
rs2_bootstrap(rs2_missing_genuine_bootstrap test-invalid-genuine
  "RS2ServerFix Test Fixture Missing Genuine Bootstrap")
target_compile_definitions(rs2_missing_genuine_bootstrap PRIVATE
  RS2_TEST_SYSTEM_X3AUDIO_LEAF=L"RS2TestMissingGenuineX3Audio_6B8D4B4E.dll")

add_library(rs2_evidence STATIC
  tools/pe_reader.cpp tools/tool_paths.cpp tools/genuine_manifest.cpp
  tools/file_evidence.cpp tools/pe_contract_lib.cpp
  src/shared/digest.cpp src/companion/sha256.cpp)
rs2_configure_target(rs2_evidence)
target_link_libraries(rs2_evidence PUBLIC bcrypt version wintrust)

add_executable(rs2_pe_contract tools/pe_contract.cpp)
rs2_configure_target(rs2_pe_contract)
target_link_libraries(rs2_pe_contract PRIVATE rs2_evidence)
add_test(NAME pe_bootstrap_contract COMMAND rs2_pe_contract --kind bootstrap --file $<TARGET_FILE:rs2_x3daudio_bootstrap>)
add_test(NAME pe_companion_contract COMMAND rs2_pe_contract --kind companion-passive --file $<TARGET_FILE:rs2_server_fix_companion>)
add_test(NAME pe_active_companion_contract COMMAND rs2_pe_contract --kind companion-active --file $<TARGET_FILE:rs2_server_fix_companion_active>)

# This import library has named exports, not SDK ordinals, and is independent
# of all DLL targets. The startup EXE cannot depend on its profile-consuming DLLs.
set(RS2_NAMED_IMPORT_LIB "${CMAKE_CURRENT_BINARY_DIR}/named-import/$<CONFIG>/x3daudio_named.lib")
add_custom_command(OUTPUT "${RS2_NAMED_IMPORT_LIB}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/named-import/$<CONFIG>"
  COMMAND "${CMAKE_AR}" /nologo /machine:x64
    "/def:${CMAKE_CURRENT_SOURCE_DIR}/tests/x3daudio_named.def" "/out:${RS2_NAMED_IMPORT_LIB}"
  DEPENDS tests/x3daudio_named.def VERBATIM)
add_custom_target(rs2_named_import DEPENDS "${RS2_NAMED_IMPORT_LIB}")

add_executable(rs2_startup_fixture tests/startup_fixture.cpp tests/startup_fixture.asm tests/startup_fixture.def)
rs2_configure_target(rs2_startup_fixture)
target_link_libraries(rs2_startup_fixture PRIVATE "${RS2_NAMED_IMPORT_LIB}")
target_link_options(rs2_startup_fixture PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/tests/startup_fixture.def")
add_dependencies(rs2_startup_fixture rs2_named_import)
add_custom_command(TARGET rs2_startup_fixture PRE_BUILD
  COMMAND "${CMAKE_COMMAND}" -E make_directory
    "${CMAKE_CURRENT_BINARY_DIR}/rs2_startup_fixture.dir/$<CONFIG>/tests" VERBATIM)
set_target_properties(rs2_startup_fixture PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-startup/host/$<CONFIG>")
rs2_resource(rs2_startup_fixture "RS2ServerFix Test Fixture Startup Host" "rs2_startup_fixture.exe" VFT_APP)
add_test(NAME pe_startup_fixture_contract COMMAND rs2_pe_contract --kind startup-fixture --file $<TARGET_FILE:rs2_startup_fixture>)

add_executable(rs2_startup_profile_generator tools/startup_profile_generator.cpp)
rs2_configure_target(rs2_startup_profile_generator)
target_link_libraries(rs2_startup_profile_generator PRIVATE rs2_evidence)
set(RS2_FIXTURE_PROFILE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-fixture/$<CONFIG>")
set(RS2_FIXTURE_PROFILE "${RS2_FIXTURE_PROFILE_DIR}/fixture_profile.h")
add_custom_command(OUTPUT "${RS2_FIXTURE_PROFILE}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${RS2_FIXTURE_PROFILE_DIR}"
  COMMAND $<TARGET_FILE:rs2_startup_profile_generator>
    $<TARGET_FILE:rs2_startup_fixture> "${RS2_FIXTURE_PROFILE}"
  DEPENDS rs2_startup_fixture "$<TARGET_FILE:rs2_startup_fixture>"
    rs2_startup_profile_generator "$<TARGET_FILE:rs2_startup_profile_generator>"
  VERBATIM)
add_custom_target(rs2_fixture_profiles DEPENDS "${RS2_FIXTURE_PROFILE}")
rs2_bootstrap(rs2_fixture_bootstrap test-startup/bootstrap "RS2ServerFix Test Fixture Bootstrap")
rs2_companion(rs2_fixture_passive test-startup/passive "RS2ServerFix Test Fixture M1R Passive Companion")
rs2_companion(rs2_fixture_active test-startup/active "RS2ServerFix Test Fixture M2 Active Companion")
target_compile_definitions(rs2_fixture_active PRIVATE RS2_RECON_ACTIVE)
foreach(target rs2_fixture_bootstrap rs2_fixture_passive rs2_fixture_active)
  target_compile_definitions(${target} PRIVATE RS2_STARTUP_TEST_PROFILE)
  target_include_directories(${target} PRIVATE "${RS2_FIXTURE_PROFILE_DIR}")
  target_sources(${target} PRIVATE "${RS2_FIXTURE_PROFILE}")
  add_dependencies(${target} rs2_fixture_profiles)
endforeach()

add_executable(rs2_static_import_harness tests/static_import_harness.cpp
  src/shared/path_identity.cpp src/companion/sha256.cpp src/shared/digest.cpp)
rs2_configure_target(rs2_static_import_harness)
target_link_libraries(rs2_static_import_harness PRIVATE bcrypt "${RS2_NAMED_IMPORT_LIB}")
add_dependencies(rs2_static_import_harness rs2_named_import)
rs2_resource(rs2_static_import_harness "RS2ServerFix X3Audio Static Import Harness"
  "rs2_static_import_harness.exe" VFT_APP)
add_executable(rs2_static_import_runner tests/static_import_runner.cpp src/shared/path_identity.cpp)
rs2_configure_target(rs2_static_import_runner)
target_link_libraries(rs2_static_import_runner PRIVATE rs2_evidence)
add_dependencies(rs2_static_import_runner rs2_static_import_harness rs2_x3daudio_bootstrap
  rs2_server_fix_companion rs2_missing_genuine_bootstrap)
add_test(NAME pe_harness_contract COMMAND rs2_pe_contract --kind harness
  --file $<TARGET_FILE:rs2_static_import_harness>)
add_test(NAME static_import_cases COMMAND rs2_static_import_runner
  --harness $<TARGET_FILE:rs2_static_import_harness>
  --bootstrap $<TARGET_FILE:rs2_x3daudio_bootstrap>
  --missing-genuine-bootstrap $<TARGET_FILE:rs2_missing_genuine_bootstrap>
  --companion $<TARGET_FILE:rs2_server_fix_companion>
  --genuine-manifest "${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest")

foreach(target rs2_normal_import_fixture rs2_delay_import_fixture)
  add_executable(${target} tests/import_fixture.cpp)
  rs2_configure_target(${target})
  target_link_libraries(${target} PRIVATE "${RS2_NAMED_IMPORT_LIB}")
  add_dependencies(${target} rs2_named_import)
endforeach()
target_link_options(rs2_delay_import_fixture PRIVATE /DELAYLOAD:X3DAudio1_7.dll)
target_link_libraries(rs2_delay_import_fixture PRIVATE delayimp)

add_executable(rs2_deployment_preflight tools/deployment_preflight.cpp src/shared/path_identity.cpp
  src/companion/build_identity.cpp)
rs2_configure_target(rs2_deployment_preflight)
target_link_libraries(rs2_deployment_preflight PRIVATE rs2_evidence advapi32)
add_executable(rs2_runtime_inventory tools/runtime_inventory_main.cpp tools/runtime_inventory.cpp
  tools/deployment_preflight.cpp src/shared/path_identity.cpp src/companion/build_identity.cpp)
rs2_configure_target(rs2_runtime_inventory)
target_compile_definitions(rs2_runtime_inventory PRIVATE RS2_PREFLIGHT_NO_MAIN)
target_link_libraries(rs2_runtime_inventory PRIVATE rs2_evidence advapi32)

add_executable(rs2_preflight_fixture_test tests/preflight_fixture_test.cpp
  tools/deployment_preflight.cpp src/shared/path_identity.cpp src/companion/build_identity.cpp)
rs2_configure_target(rs2_preflight_fixture_test)
target_compile_definitions(rs2_preflight_fixture_test PRIVATE RS2_PREFLIGHT_NO_MAIN)
target_link_libraries(rs2_preflight_fixture_test PRIVATE rs2_evidence advapi32)
add_dependencies(rs2_preflight_fixture_test rs2_deployment_preflight rs2_x3daudio_bootstrap rs2_server_fix_companion)
add_test(NAME preflight_fixture COMMAND rs2_preflight_fixture_test
  $<TARGET_FILE:rs2_deployment_preflight> "${RS2_CURRENT_STOCK_PATH}"
  $<TARGET_FILE:rs2_x3daudio_bootstrap> $<TARGET_FILE:rs2_server_fix_companion>
  "${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest")

add_executable(rs2_core_tests tests/core_tests.cpp tests/resolver_tests.cpp tests/loader_tests.cpp
  tests/path_tests.cpp tests/companion_tests.cpp tests/host_hash_tests.cpp
  tests/pe_reader_tests.cpp tests/manifest_tests.cpp tests/runtime_inventory_test.cpp
  src/bootstrap/genuine_resolver.cpp src/bootstrap/forwarder.cpp src/bootstrap/companion_loader.cpp
  src/shared/path_identity.cpp src/shared/thread_error_mode.cpp
  src/companion/build_identity.cpp src/companion/recon_types.cpp src/companion/marker.cpp
  src/companion/console_status.cpp src/companion/host_hash.cpp
  tools/runtime_inventory.cpp tools/deployment_preflight.cpp
  tests/startup_context_tests.cpp src/companion/companion_init.cpp
  src/companion/recon_fix.cpp src/shared/startup_profile.cpp)
rs2_configure_target(rs2_core_tests)
target_compile_definitions(rs2_core_tests PRIVATE RS2_PREFLIGHT_NO_MAIN
  RS2_PR1_BASELINE_PATH=L"${RS2_PR1_BASELINE_PATH}"
  RS2_CURRENT_STOCK_PATH=L"${RS2_CURRENT_STOCK_PATH}"
  RS2_SOURCE_DIR=L"${CMAKE_CURRENT_SOURCE_DIR}"
  RS2_GENUINE_MANIFEST_PATH=L"${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest"
  RS2_PE_CONTRACT_PATH=L"$<TARGET_FILE:rs2_pe_contract>"
  RS2_NORMAL_IMPORT_FIXTURE_PATH=L"$<TARGET_FILE:rs2_normal_import_fixture>"
  RS2_DELAY_IMPORT_FIXTURE_PATH=L"$<TARGET_FILE:rs2_delay_import_fixture>")
target_link_libraries(rs2_core_tests PRIVATE rs2_evidence advapi32)
if(RS2_DOCUMENTATION_ROOT)
  target_compile_definitions(rs2_core_tests PRIVATE RS2_DOCUMENTATION_ROOT=L"${RS2_DOCUMENTATION_ROOT}")
endif()
add_dependencies(rs2_core_tests rs2_pe_contract rs2_normal_import_fixture rs2_delay_import_fixture)
add_test(NAME core COMMAND rs2_core_tests)

add_executable(rs2_recon_tests tests/recon_test_main.cpp tests/recon_tests.cpp
  src/companion/recon_fix.cpp src/companion/recon_types.cpp src/companion/host_hash.cpp
  src/shared/startup_profile.cpp)
rs2_configure_target(rs2_recon_tests)
target_link_libraries(rs2_recon_tests PRIVATE rs2_evidence)
add_test(NAME recon_transaction COMMAND rs2_recon_tests)

add_executable(rs2_image_protection_probe tools/image_protection_probe.cpp
  src/companion/host_hash.cpp "${RS2_FIXTURE_PROFILE}")
rs2_configure_target(rs2_image_protection_probe)
target_include_directories(rs2_image_protection_probe PRIVATE "${RS2_FIXTURE_PROFILE_DIR}")
target_link_libraries(rs2_image_protection_probe PRIVATE rs2_evidence)
add_dependencies(rs2_image_protection_probe rs2_fixture_profiles)
add_test(NAME image_protection_probe COMMAND rs2_image_protection_probe
  --image $<TARGET_FILE:rs2_startup_fixture>)

add_executable(rs2_startup_runner tests/startup_runner.cpp src/shared/path_identity.cpp)
rs2_configure_target(rs2_startup_runner)
target_link_libraries(rs2_startup_runner PRIVATE rs2_evidence)
add_dependencies(rs2_startup_runner rs2_startup_fixture rs2_fixture_bootstrap
  rs2_fixture_passive rs2_fixture_active rs2_x3daudio_bootstrap)
add_test(NAME startup_cases COMMAND rs2_startup_runner
  --host $<TARGET_FILE:rs2_startup_fixture>
  --bootstrap $<TARGET_FILE:rs2_fixture_bootstrap>
  --passive $<TARGET_FILE:rs2_fixture_passive>
  --active $<TARGET_FILE:rs2_fixture_active>
  --genuine-manifest "${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest"
  --production-bootstrap $<TARGET_FILE:rs2_x3daudio_bootstrap>)

add_executable(rs2_profile_evidence_tests tests/profile_test_main.cpp tests/production_profile_tests.cpp)
rs2_configure_target(rs2_profile_evidence_tests)
target_link_libraries(rs2_profile_evidence_tests PRIVATE rs2_evidence)
target_compile_definitions(rs2_profile_evidence_tests PRIVATE
  RS2_CURRENT_FULLDUMP_PATH=L"${RS2_CURRENT_FULLDUMP_PATH}"
  RS2_CURRENT_STOCK_PATH=L"${RS2_CURRENT_STOCK_PATH}"
  RS2_SOURCE_DIR=L"${CMAKE_CURRENT_SOURCE_DIR}")
add_test(NAME production_profile_evidence COMMAND rs2_profile_evidence_tests)
