# Included only by non-Android builds. These tests do not establish Android
# inherited seccomp policy, app permissions, guest execution or lifecycle safety.
if(ANDROID)
    message(FATAL_ERROR "host_tests.cmake must not enter the Android build.")
endif()
if(CMAKE_SIZEOF_VOID_P LESS 8)
    message(FATAL_ERROR "Native checks require a 64-bit host.")
endif()
if(WIN32 AND NOT MSVC)
    message(FATAL_ERROR "Windows native checks currently require MSVC with C11 atomics.")
endif()

function(sucrune_host_target target)
    target_compile_features(${target} PRIVATE c_std_11)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /Od)
    else()
        target_compile_definitions(${target} PRIVATE _GNU_SOURCE)
        target_compile_options(${target} PRIVATE
            "$<$<COMPILE_LANGUAGE:C>:-Wall;-Wextra;-Werror;-Wconversion;-Wshadow>")
    endif()
endfunction()

add_executable(sucrune_guest_space_tests guest_space.c guest_space_tests.c)
sucrune_host_target(sucrune_guest_space_tests)
if(WIN32)
    target_compile_definitions(sucrune_guest_space_tests PRIVATE SUCRUNE_SPACE_TEST_BACKEND)
endif()
add_test(NAME guest_space_invariants COMMAND sucrune_guest_space_tests)
set_tests_properties(guest_space_invariants PROPERTIES TIMEOUT 60 LABELS "host;memory")

add_executable(sucrune_guest_signals_tests guest_signals.c guest_signals_tests.c)
sucrune_host_target(sucrune_guest_signals_tests)
add_test(NAME guest_signal_model COMMAND sucrune_guest_signals_tests)
set_tests_properties(guest_signal_model PROPERTIES TIMEOUT 30 LABELS "host;model")

# Linux's original test target is retained; Windows needs the portable table only.
if(NOT TARGET sucrune_guest_fds_tests)
    add_executable(sucrune_guest_fds_tests guest_fds.c guest_fds_tests.c)
    sucrune_host_target(sucrune_guest_fds_tests)
    add_test(NAME guest_fd_ownership COMMAND sucrune_guest_fds_tests)
endif()
set_tests_properties(guest_fd_ownership PROPERTIES TIMEOUT 30 LABELS "host;model")

add_executable(sucrune_guest_gates_tests guest_gates.c guest_gates_tests.c)
sucrune_host_target(sucrune_guest_gates_tests)
if(WIN32)
    target_compile_options(sucrune_guest_gates_tests PRIVATE /experimental:c11atomics)
    target_compile_definitions(sucrune_guest_gates_tests PRIVATE SUCRUNE_GATE_HOST_TEST)
else()
    target_link_libraries(sucrune_guest_gates_tests PRIVATE Threads::Threads)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
        target_sources(sucrune_guest_gates_tests PRIVATE signal_gate.S)
    endif()
endif()
add_test(NAME guest_gate_registry COMMAND sucrune_guest_gates_tests)
set_tests_properties(guest_gate_registry PROPERTIES TIMEOUT 90 LABELS "host;concurrency")

set(FILTER_HEADER "${CMAKE_CURRENT_BINARY_DIR}/linux_filter_generated.h")
add_custom_command(OUTPUT "${FILTER_HEADER}"
    COMMAND "${CMAKE_COMMAND}"
        "-DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/shell_runtime.c"
        "-DOUTPUT=${FILTER_HEADER}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/extract-linux-filter.cmake"
    DEPENDS shell_runtime.c ../scripts/extract-linux-filter.cmake VERBATIM)
add_executable(sucrune_linux_filter_tests linux_filter_tests.c "${FILTER_HEADER}")
sucrune_host_target(sucrune_linux_filter_tests)
target_include_directories(sucrune_linux_filter_tests PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
add_test(NAME linux_filter_interpreter COMMAND sucrune_linux_filter_tests)
set_tests_properties(linux_filter_interpreter PROPERTIES TIMEOUT 30 LABELS "host;model")

add_executable(sucrune_network_probe_address_tests network_probe.c network_probe_address_tests.c)
sucrune_host_target(sucrune_network_probe_address_tests)
target_compile_definitions(sucrune_network_probe_address_tests PRIVATE SUCRUNE_NETWORK_PROBE_CODEC_ONLY)
add_test(NAME network_probe_loopback_addresses COMMAND sucrune_network_probe_address_tests)
set_tests_properties(network_probe_loopback_addresses PROPERTIES TIMEOUT 30 LABELS "host;codec")

if(WIN32)
    message(STATUS "Windows checks: space adapter, signal model, FD ownership, gate registry, BPF interpreter, loopback address codec")
    message(STATUS "Not run on Windows: Linux local I/O, ARM64 thread entry, ELF parser, kernel seccomp and Android lifecycle")
    return()
endif()

add_executable(sucrune_guest_local_io_tests guest_local_io.c guest_fds.c guest_local_io_tests.c)
sucrune_host_target(sucrune_guest_local_io_tests)
target_link_libraries(sucrune_guest_local_io_tests PRIVATE Threads::Threads)
add_test(NAME guest_local_io_kernel COMMAND sucrune_guest_local_io_tests)
set_tests_properties(guest_local_io_kernel PROPERTIES TIMEOUT 30 LABELS "linux;kernel")

add_executable(sucrune_guest_threads_tests guest_threads.c guest_threads_tests.c
    guest_thread_entry.S guest_gates.c signal_gate.S guest_entry.S)
sucrune_host_target(sucrune_guest_threads_tests)
target_link_libraries(sucrune_guest_threads_tests PRIVATE Threads::Threads)
add_test(NAME guest_threads_arm64 COMMAND sucrune_guest_threads_tests)
set_tests_properties(guest_threads_arm64 PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77 LABELS "linux;arm64")

add_executable(sucrune_linux_loader_tests linux_elf.c guest_space.c linux_loader_tests.c)
sucrune_host_target(sucrune_linux_loader_tests)
set(SUCRUNE_LINUX_TEST_ROOTFS
    "${CMAKE_CURRENT_SOURCE_DIR}/../android/probeapp/src/androidTest/assets/linux-rootfs/files"
    CACHE PATH "Prepared official Linux ARM64 fixtures; parser reads bytes without executing them")
set(PARSER_FIXTURES "${SUCRUNE_LINUX_TEST_ROOTFS}/usr/bin/hello"
    "${SUCRUNE_LINUX_TEST_ROOTFS}/lib/ld-linux-aarch64.so.1"
    "${SUCRUNE_LINUX_TEST_ROOTFS}/lib/aarch64-linux-gnu/libc.so.6"
    "${SUCRUNE_LINUX_TEST_ROOTFS}/usr/bin/node")
set(PARSER_FIXTURES_PRESENT TRUE)
foreach(fixture IN LISTS PARSER_FIXTURES)
    if(NOT EXISTS "${fixture}")
        set(PARSER_FIXTURES_PRESENT FALSE)
    endif()
endforeach()
if(PARSER_FIXTURES_PRESENT)
    add_test(NAME linux_elf_parser_boundaries COMMAND sucrune_linux_loader_tests ${PARSER_FIXTURES})
    set_tests_properties(linux_elf_parser_boundaries PROPERTIES TIMEOUT 60 LABELS "linux;parser")
else()
    message(STATUS "Linux ELF parser target built; test not registered because official rootfs fixtures are absent")
endif()
