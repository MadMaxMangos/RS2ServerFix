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

# Only this translation unit uses Windows aligned payload release stores.
# Pin MSVC's ordering contract; all sequence/latch operations stay interlocked.
set_source_files_properties(src/companion/steam_reporting_status.cpp
  PROPERTIES COMPILE_OPTIONS "/volatile:ms")

set(RS2_PR1_BASELINE_PATH "" CACHE FILEPATH "Preserved PR1 stock input; never executed")
set(RS2_CURRENT_STOCK_PATH "" CACHE FILEPATH "Preserved PR3 stock input; never executed")
set(RS2_CURRENT_FULLDUMP_PATH "" CACHE FILEPATH "Preserved approved PR3 full-dump input; never executed")
set(RS2_DOCUMENTATION_ROOT "" CACHE PATH "Optional external archive root containing docs/evidence for qualification audits")
set(RS2_OBSERVER_SDK_BASELINE_PATH "" CACHE FILEPATH "Operator-matched SDK 1.57 input; read as data, never executed")

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
  set(RS2_RESOURCE_VERSION_ASCII "0.2.0.0")
  set(RS2_RESOURCE_VERSION_QUAD "0,2,0,0")
  if(ARGC GREATER 4)
    set(RS2_RESOURCE_VERSION_ASCII "${ARGV4}")
    set(RS2_RESOURCE_VERSION_QUAD "${ARGV5}")
    target_compile_definitions(${target} PRIVATE
      RS2FIX_VERSION_ASCII="${RS2_RESOURCE_VERSION_ASCII}"
      RS2FIX_VERSION_QUAD=${RS2_RESOURCE_VERSION_QUAD})
  endif()
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
  src/companion/build_identity.cpp
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
  set(companion_def src/companion/RS2ServerFix.def)
  if(ARGC GREATER 5)
    set(companion_def "${ARGV5}")
  endif()
  add_library(${target} SHARED ${RS2_COMPANION_SOURCES} "${companion_def}")
  rs2_configure_target(${target})
  target_link_libraries(${target} PRIVATE bcrypt)
  set_target_properties(${target} PROPERTIES OUTPUT_NAME RS2ServerFix
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${directory}/$<CONFIG>"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${directory}/$<CONFIG>")
  if(ARGC GREATER 4)
    rs2_resource(${target} "${description}" "RS2ServerFix.dll" VFT_DLL "${ARGV3}" "${ARGV4}")
  else()
    rs2_resource(${target} "${description}" "RS2ServerFix.dll" VFT_DLL)
  endif()
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

add_executable(rs2_profile_evidence_tests tests/profile_test_main.cpp tests/production_profile_tests.cpp
  tests/steam_observer_profile_tests.cpp src/companion/steam_observer_profile.cpp
  src/companion/host_hash.cpp src/shared/startup_profile.cpp src/shared/path_identity.cpp)
rs2_configure_target(rs2_profile_evidence_tests)
target_link_libraries(rs2_profile_evidence_tests PRIVATE rs2_evidence)
target_compile_definitions(rs2_profile_evidence_tests PRIVATE
  RS2_OBSERVER_FILES_ONLY
  RS2_OBSERVER_HOST_PATH=L"${RS2_CURRENT_FULLDUMP_PATH}"
  RS2_OBSERVER_SDK_PATH=L"${RS2_OBSERVER_SDK_BASELINE_PATH}"
  RS2_CURRENT_FULLDUMP_PATH=L"${RS2_CURRENT_FULLDUMP_PATH}"
  RS2_CURRENT_STOCK_PATH=L"${RS2_CURRENT_STOCK_PATH}"
  RS2_SOURCE_DIR=L"${CMAKE_CURRENT_SOURCE_DIR}")
add_test(NAME production_profile_evidence COMMAND rs2_profile_evidence_tests)

# Observer is a separate companion artifact. Ordinary recon source/import/version
# contracts stay unchanged; fake SDK imports exist only in explicitly test targets.
set(RS2_OBSERVER_SOURCES src/companion/steam_observer.cpp
  src/companion/steam_observer_profile.cpp src/companion/steam_observer_dispatch.cpp
  src/companion/steam_observer_thunks.asm src/companion/steam_observer_log.cpp)
rs2_companion(rs2_server_fix_companion_observer production/observer
  "RS2ServerFix Active Recon Steam Observer Companion" "0.3.0.0" "0,3,0,0")
target_sources(rs2_server_fix_companion_observer PRIVATE ${RS2_OBSERVER_SOURCES})
target_compile_definitions(rs2_server_fix_companion_observer PRIVATE RS2_RECON_ACTIVE RS2_STEAM_OBSERVER)
target_link_libraries(rs2_server_fix_companion_observer PRIVATE advapi32)
add_test(NAME pe_observer_companion_contract COMMAND rs2_pe_contract
  --kind companion-observer --file $<TARGET_FILE:rs2_server_fix_companion_observer>)

add_library(rs2_test_steam_api SHARED tests/steam_api_fixture.cpp tests/steam_api_fixture.def)
rs2_configure_target(rs2_test_steam_api)
set_target_properties(rs2_test_steam_api PROPERTIES OUTPUT_NAME rs2_test_steam_api
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-observer/sdk/$<CONFIG>")
set(RS2_STEAM_TEST_IMPORT_LIB "${CMAKE_CURRENT_BINARY_DIR}/named-import/$<CONFIG>/steam_test_named.lib")
add_custom_command(OUTPUT "${RS2_STEAM_TEST_IMPORT_LIB}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/named-import/$<CONFIG>"
  COMMAND "${CMAKE_AR}" /nologo /machine:x64
    "/def:${CMAKE_CURRENT_SOURCE_DIR}/tests/steam_api_named.def" "/out:${RS2_STEAM_TEST_IMPORT_LIB}"
  DEPENDS tests/steam_api_named.def VERBATIM)
add_custom_target(rs2_steam_test_import DEPENDS "${RS2_STEAM_TEST_IMPORT_LIB}")
add_executable(rs2_observer_startup_fixture tests/startup_fixture.cpp tests/startup_fixture.asm
  tests/observer_startup_fixture.def)
rs2_configure_target(rs2_observer_startup_fixture)
target_compile_definitions(rs2_observer_startup_fixture PRIVATE RS2_OBSERVER_FIXTURE)
target_link_libraries(rs2_observer_startup_fixture PRIVATE "${RS2_NAMED_IMPORT_LIB}" "${RS2_STEAM_TEST_IMPORT_LIB}")
target_link_options(rs2_observer_startup_fixture PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/tests/observer_startup_fixture.def")
add_dependencies(rs2_observer_startup_fixture rs2_named_import rs2_steam_test_import)
add_custom_command(TARGET rs2_observer_startup_fixture PRE_BUILD
  COMMAND "${CMAKE_COMMAND}" -E make_directory
    "${CMAKE_CURRENT_BINARY_DIR}/rs2_observer_startup_fixture.dir/$<CONFIG>/tests" VERBATIM)
set_target_properties(rs2_observer_startup_fixture PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-observer/host/$<CONFIG>")
rs2_resource(rs2_observer_startup_fixture "RS2ServerFix Test Fixture Steam Observer Startup Host"
  "rs2_observer_startup_fixture.exe" VFT_APP)
add_test(NAME pe_observer_fixture_contract COMMAND rs2_pe_contract
  --kind observer-startup-fixture --file $<TARGET_FILE:rs2_observer_startup_fixture>)

set(RS2_OBSERVER_FIXTURE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-observer/$<CONFIG>")
set(RS2_OBSERVER_FIXTURE_PROFILE "${RS2_OBSERVER_FIXTURE_DIR}/fixture_profile.h")
add_custom_command(OUTPUT "${RS2_OBSERVER_FIXTURE_PROFILE}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${RS2_OBSERVER_FIXTURE_DIR}"
  COMMAND $<TARGET_FILE:rs2_startup_profile_generator>
    $<TARGET_FILE:rs2_observer_startup_fixture> "${RS2_OBSERVER_FIXTURE_PROFILE}"
    --observer-sdk $<TARGET_FILE:rs2_test_steam_api>
  DEPENDS rs2_observer_startup_fixture rs2_test_steam_api rs2_startup_profile_generator
    "$<TARGET_FILE:rs2_observer_startup_fixture>" "$<TARGET_FILE:rs2_test_steam_api>"
    "$<TARGET_FILE:rs2_startup_profile_generator>" VERBATIM)
add_custom_target(rs2_observer_fixture_profiles DEPENDS "${RS2_OBSERVER_FIXTURE_PROFILE}")
rs2_bootstrap(rs2_observer_fixture_bootstrap test-observer/bootstrap "RS2ServerFix Test Fixture Bootstrap")
rs2_companion(rs2_observer_fixture_companion test-observer/companion
  "RS2ServerFix Test Fixture Steam Observer Companion" "0.3.0.0" "0,3,0,0")
target_sources(rs2_observer_fixture_companion PRIVATE ${RS2_OBSERVER_SOURCES})
target_compile_definitions(rs2_observer_fixture_companion PRIVATE RS2_RECON_ACTIVE RS2_STEAM_OBSERVER)
target_link_libraries(rs2_observer_fixture_companion PRIVATE advapi32)
foreach(target rs2_observer_fixture_bootstrap rs2_observer_fixture_companion)
  target_compile_definitions(${target} PRIVATE RS2_STARTUP_TEST_PROFILE)
  target_include_directories(${target} PRIVATE "${RS2_OBSERVER_FIXTURE_DIR}")
  target_sources(${target} PRIVATE "${RS2_OBSERVER_FIXTURE_PROFILE}")
  add_dependencies(${target} rs2_observer_fixture_profiles)
endforeach()
add_test(NAME pe_observer_fixture_companion_contract COMMAND rs2_pe_contract
  --kind fixture-companion-observer --file $<TARGET_FILE:rs2_observer_fixture_companion>)
add_executable(rs2_observer_startup_runner tests/observer_startup_runner.cpp src/shared/path_identity.cpp)
rs2_configure_target(rs2_observer_startup_runner)
target_link_libraries(rs2_observer_startup_runner PRIVATE rs2_evidence)
add_dependencies(rs2_observer_startup_runner rs2_observer_startup_fixture
  rs2_observer_fixture_bootstrap rs2_observer_fixture_companion rs2_test_steam_api)
add_test(NAME observer_startup_cases COMMAND rs2_observer_startup_runner
  --host $<TARGET_FILE:rs2_observer_startup_fixture>
  --bootstrap $<TARGET_FILE:rs2_observer_fixture_bootstrap>
  --companion $<TARGET_FILE:rs2_observer_fixture_companion>
  --sdk $<TARGET_FILE:rs2_test_steam_api> --expected-companion-version 0.3.0.0
  --genuine-manifest "${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest")

add_executable(rs2_observer_tests tests/steam_observer_test_main.cpp
  tests/steam_observer_dispatch_tests.cpp tests/steam_observer_abi_fixture.asm
  tests/steam_observer_log_tests.cpp tests/steam_observer_transaction_tests.cpp
  tests/steam_observer_profile_tests.cpp
  ${RS2_OBSERVER_SOURCES} src/companion/host_hash.cpp src/companion/console_status.cpp
  src/companion/marker.cpp src/companion/recon_types.cpp src/companion/build_identity.cpp
  src/shared/path_identity.cpp src/shared/startup_profile.cpp)
rs2_configure_target(rs2_observer_tests)
target_compile_definitions(rs2_observer_tests PRIVATE RS2_OBSERVER_TESTING)
target_link_libraries(rs2_observer_tests PRIVATE rs2_evidence advapi32)
add_test(NAME observer_core COMMAND rs2_observer_tests)
add_test(NAME observer_collector COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
  -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/steam_observer_collector_tests.ps1")

# Reporting foundations are inert: this target exercises owned data only and
# cannot load the game/SDK or publish runtime hooks. Legacy artifacts stay intact.
add_executable(rs2_reporting_tests tests/steam_reporting_test_main.cpp
  tests/steam_reporting_config_tests.cpp tests/steam_reporting_state_tests.cpp
  tests/steam_reporting_json_tests.cpp tests/steam_reporting_profile_tests.cpp
  tests/steam_reporting_source_tests.cpp
  tests/steam_reporting_status_tests.cpp tests/steam_reporting_ancestry_tests.cpp
  tests/steam_reporting_prepared_tests.cpp
  tests/steam_reporting_capture_tests.cpp tests/steam_reporting_record_tests.cpp
  tests/steam_reporting_task_tests.cpp tests/steam_reporting_client_tests.cpp
  tests/steam_reporting_log_tests.cpp
  tests/steam_reporting_runtime_tests.cpp
  tests/steam_reporting_forward_tests.cpp
  src/companion/steam_reporting_types.cpp src/companion/steam_reporting_config.cpp
  src/companion/steam_reporting_state.cpp src/companion/steam_reporting_json.cpp
  src/companion/steam_reporting_profile.cpp src/shared/startup_profile.cpp
  src/companion/steam_reporting_source.cpp
  src/companion/steam_reporting_status.cpp src/companion/steam_reporting_ancestry.cpp
  src/companion/steam_reporting_prepared.cpp
  src/companion/steam_reporting_capture.cpp src/companion/steam_reporting_records.cpp
  src/companion/steam_reporting_task.cpp src/companion/steam_reporting_client.cpp
  src/companion/steam_reporting_runtime.cpp
  src/companion/steam_reporting_forward.cpp
  ${RS2_OBSERVER_SOURCES} src/companion/console_status.cpp
  src/companion/marker.cpp src/companion/recon_types.cpp src/companion/build_identity.cpp
  src/companion/host_hash.cpp
  src/shared/path_identity.cpp)
rs2_configure_target(rs2_reporting_tests)
target_compile_definitions(rs2_reporting_tests PRIVATE RS2_REPORTING_TESTING RS2_STEAM_REPORTING RS2_OBSERVER_TESTING)
target_link_libraries(rs2_reporting_tests PRIVATE rs2_evidence advapi32)
add_test(NAME reporting_core COMMAND rs2_reporting_tests)

set(RS2_REPORTING_SOURCES
  src/companion/steam_reporting.cpp src/companion/steam_reporting_types.cpp
  src/companion/steam_reporting_config.cpp src/companion/steam_reporting_state.cpp
  src/companion/steam_reporting_json.cpp src/companion/steam_reporting_profile.cpp
  src/companion/steam_reporting_source.cpp src/companion/steam_reporting_status.cpp
  src/companion/steam_reporting_ancestry.cpp src/companion/steam_reporting_prepared.cpp
  src/companion/steam_reporting_capture.cpp src/companion/steam_reporting_records.cpp
  src/companion/steam_reporting_task.cpp src/companion/steam_reporting_client.cpp
  src/companion/steam_reporting_runtime.cpp src/companion/steam_reporting_forward.cpp)
rs2_companion(rs2_server_fix_companion_reporting production/reporting
  "RS2ServerFix Active Recon Steam Reporting Companion" "0.4.1.0" "0,4,1,0"
  src/companion/RS2ServerFixReporting.def)
target_sources(rs2_server_fix_companion_reporting PRIVATE ${RS2_OBSERVER_SOURCES} ${RS2_REPORTING_SOURCES})
target_compile_definitions(rs2_server_fix_companion_reporting PRIVATE
  RS2_RECON_ACTIVE RS2_STEAM_OBSERVER RS2_STEAM_REPORTING)
target_link_libraries(rs2_server_fix_companion_reporting PRIVATE advapi32)
add_test(NAME pe_reporting_companion_contract COMMAND rs2_pe_contract
  --kind companion-reporting --file $<TARGET_FILE:rs2_server_fix_companion_reporting>)

# Own-code reporting startup route. No VNGame/Steam/EOS binary is a dependency
# or execution input; generated identities bind only these separate fixtures.
add_library(rs2_reporting_test_client SHARED tests/steam_client_fixture.cpp tests/steam_client_fixture.def)
rs2_configure_target(rs2_reporting_test_client)
set_target_properties(rs2_reporting_test_client PROPERTIES OUTPUT_NAME rs2_test_steam_client
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-reporting/client/$<CONFIG>"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-reporting/client/$<CONFIG>")
add_library(rs2_reporting_test_api SHARED tests/steam_api_fixture.cpp tests/steam_reporting_api_fixture.def)
rs2_configure_target(rs2_reporting_test_api)
target_compile_definitions(rs2_reporting_test_api PRIVATE RS2_REPORTING_FIXTURE)
set_target_properties(rs2_reporting_test_api PROPERTIES OUTPUT_NAME rs2_test_steam_api
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-reporting/sdk/$<CONFIG>"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-reporting/sdk/$<CONFIG>")
set(RS2_REPORTING_TEST_IMPORT_LIB "${CMAKE_CURRENT_BINARY_DIR}/named-import/$<CONFIG>/steam_reporting_named.lib")
add_custom_command(OUTPUT "${RS2_REPORTING_TEST_IMPORT_LIB}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/named-import/$<CONFIG>"
  COMMAND "${CMAKE_AR}" /nologo /machine:x64
    "/def:${CMAKE_CURRENT_SOURCE_DIR}/tests/steam_reporting_api_named.def" "/out:${RS2_REPORTING_TEST_IMPORT_LIB}"
  DEPENDS tests/steam_reporting_api_named.def VERBATIM)
add_custom_target(rs2_reporting_test_import DEPENDS "${RS2_REPORTING_TEST_IMPORT_LIB}")
add_executable(rs2_reporting_startup_fixture tests/startup_fixture.cpp tests/startup_fixture.asm
  tests/steam_reporting_startup_fixture.cpp tests/steam_reporting_startup_fixture.asm
  tests/steam_reporting_startup_fixture.def)
rs2_configure_target(rs2_reporting_startup_fixture)
target_compile_definitions(rs2_reporting_startup_fixture PRIVATE RS2_OBSERVER_FIXTURE RS2_REPORTING_FIXTURE)
target_link_options(rs2_reporting_startup_fixture PRIVATE
  "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/tests/steam_reporting_startup_fixture.def")
target_link_libraries(rs2_reporting_startup_fixture PRIVATE "${RS2_NAMED_IMPORT_LIB}" "${RS2_REPORTING_TEST_IMPORT_LIB}")
add_dependencies(rs2_reporting_startup_fixture rs2_named_import rs2_reporting_test_import)
set_target_properties(rs2_reporting_startup_fixture PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/test-reporting/host/$<CONFIG>")
add_custom_command(TARGET rs2_reporting_startup_fixture PRE_BUILD
  COMMAND "${CMAKE_COMMAND}" -E make_directory
    "${CMAKE_CURRENT_BINARY_DIR}/rs2_reporting_startup_fixture.dir/$<CONFIG>/tests" VERBATIM)
rs2_resource(rs2_reporting_startup_fixture "RS2ServerFix Test Fixture Steam Reporting Startup Host"
  "rs2_reporting_startup_fixture.exe" VFT_APP)
add_test(NAME pe_reporting_fixture_contract COMMAND rs2_pe_contract
  --kind reporting-startup-fixture --file $<TARGET_FILE:rs2_reporting_startup_fixture>)

set(RS2_REPORTING_FIXTURE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-reporting/$<CONFIG>")
set(RS2_REPORTING_FIXTURE_PROFILE "${RS2_REPORTING_FIXTURE_DIR}/fixture_profile.h")
add_custom_command(OUTPUT "${RS2_REPORTING_FIXTURE_PROFILE}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${RS2_REPORTING_FIXTURE_DIR}"
  COMMAND $<TARGET_FILE:rs2_startup_profile_generator>
    $<TARGET_FILE:rs2_reporting_startup_fixture> "${RS2_REPORTING_FIXTURE_PROFILE}"
    --reporting-sdk $<TARGET_FILE:rs2_reporting_test_api>
    --reporting-client $<TARGET_FILE:rs2_reporting_test_client>
  DEPENDS rs2_reporting_startup_fixture rs2_reporting_test_api rs2_reporting_test_client rs2_startup_profile_generator
    "$<TARGET_FILE:rs2_reporting_startup_fixture>" "$<TARGET_FILE:rs2_reporting_test_api>"
    "$<TARGET_FILE:rs2_reporting_test_client>" "$<TARGET_FILE:rs2_startup_profile_generator>" VERBATIM)
add_custom_target(rs2_reporting_fixture_profiles DEPENDS "${RS2_REPORTING_FIXTURE_PROFILE}")
rs2_bootstrap(rs2_reporting_fixture_bootstrap test-reporting/bootstrap "RS2ServerFix Test Fixture Bootstrap")
rs2_companion(rs2_reporting_fixture_companion test-reporting/companion
  "RS2ServerFix Test Fixture Steam Reporting Companion" "0.4.1.0" "0,4,1,0"
  src/companion/RS2ServerFixReporting.def)
target_sources(rs2_reporting_fixture_companion PRIVATE ${RS2_OBSERVER_SOURCES} ${RS2_REPORTING_SOURCES})
target_compile_definitions(rs2_reporting_fixture_companion PRIVATE RS2_RECON_ACTIVE RS2_STEAM_OBSERVER RS2_STEAM_REPORTING)
target_link_libraries(rs2_reporting_fixture_companion PRIVATE advapi32)
foreach(target rs2_reporting_fixture_bootstrap rs2_reporting_fixture_companion)
  target_compile_definitions(${target} PRIVATE RS2_STARTUP_TEST_PROFILE)
  target_include_directories(${target} PRIVATE "${RS2_REPORTING_FIXTURE_DIR}")
  target_sources(${target} PRIVATE "${RS2_REPORTING_FIXTURE_PROFILE}")
  add_dependencies(${target} rs2_reporting_fixture_profiles)
endforeach()
add_test(NAME pe_reporting_fixture_companion_contract COMMAND rs2_pe_contract
  --kind fixture-companion-reporting --file $<TARGET_FILE:rs2_reporting_fixture_companion>)
add_executable(rs2_reporting_startup_runner tests/steam_reporting_startup_runner.cpp src/shared/path_identity.cpp)
rs2_configure_target(rs2_reporting_startup_runner)
target_link_libraries(rs2_reporting_startup_runner PRIVATE rs2_evidence)
add_dependencies(rs2_reporting_startup_runner rs2_reporting_startup_fixture
  rs2_reporting_fixture_bootstrap rs2_reporting_fixture_companion rs2_reporting_test_api rs2_reporting_test_client)
add_test(NAME reporting_startup_cases COMMAND rs2_reporting_startup_runner
  --host $<TARGET_FILE:rs2_reporting_startup_fixture>
  --bootstrap $<TARGET_FILE:rs2_reporting_fixture_bootstrap>
  --companion $<TARGET_FILE:rs2_reporting_fixture_companion>
  --sdk $<TARGET_FILE:rs2_reporting_test_api> --client $<TARGET_FILE:rs2_reporting_test_client>
  --expected-companion-version 0.4.1.0
  --genuine-manifest "${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest")
add_test(NAME reporting_timing_calibration COMMAND rs2_reporting_startup_runner
  --host $<TARGET_FILE:rs2_reporting_startup_fixture>
  --bootstrap $<TARGET_FILE:rs2_reporting_fixture_bootstrap>
  --companion $<TARGET_FILE:rs2_reporting_fixture_companion>
  --sdk $<TARGET_FILE:rs2_reporting_test_api> --client $<TARGET_FILE:rs2_reporting_test_client>
  --expected-companion-version 0.4.1.0
  --genuine-manifest "${CMAKE_CURRENT_SOURCE_DIR}/config/qualified_x3audio_genuine.manifest"
  --calibration-only)
# The runner's 900-second owned-child timeout must precede the enclosing test.
set_tests_properties(reporting_timing_calibration PROPERTIES TIMEOUT 1500)
add_test(NAME reporting_collector COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
  -File "${CMAKE_CURRENT_SOURCE_DIR}/tests/steam_reporting_collector_tests.ps1")
