cmake_minimum_required(VERSION 3.22)
project(sucrune_probe LANGUAGES C)

# Windows builds only portable native checks, never the Linux syscall probe.
# Keep ASM and the production Android branch unchanged on their supported hosts.
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT ANDROID)
    enable_testing()
    include(host_tests.cmake)
    return()
endif()
enable_language(ASM)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
    message(FATAL_ERROR "The syscall probe must run under an Android or Linux kernel.")
endif()

find_package(Threads REQUIRED)

set(PROBE_SOURCES probe.c trap.S)
if(ANDROID)
    add_library(sucrune_probe SHARED ${PROBE_SOURCES} jni.c elf_loader.c loader_tests.c elf_probe.c guest_entry.S
        shell_runtime.c workspace_broker.c guest_landlock.c workspace_locks.c workspace_links.c workspace_links_recover.c runtime_jni.c guest_memory.c guest_fds.c signal_gate.S program_catalog.c
        guest_space.c linux_elf.c guest_gates.c linux_runner.c guest_signals.c guest_threads.c guest_thread_entry.S guest_local_io.c guest_sockets.c
        broker_transport.c network_broker.c guest_network.c process_probe.c dns_proxy.c)
    target_link_libraries(sucrune_probe PRIVATE dl android)
    target_sources(sucrune_probe PRIVATE network_probe.c pty_probe.c pty_runtime.c guest_processes.c project_scope.c guest_fork_child.c guest_fork_entry.S)
    # Packaged as a native library so Android installs it into nativeLibraryDir,
    # but built as a PIE executable with a fresh Bionic process and no ART/Go.
    add_executable(sucrune_runner linux_runner.c shell_runtime.c elf_loader.c loader_tests.c
        guest_entry.S signal_gate.S guest_memory.c guest_fds.c guest_space.c guest_gates.c
        linux_elf.c program_catalog.c guest_signals.c guest_threads.c guest_thread_entry.S guest_local_io.c guest_sockets.c
        broker_transport.c network_broker.c guest_network.c process_probe.c)
    set_target_properties(sucrune_runner PROPERTIES OUTPUT_NAME "libsucrune_runner.so")
    target_sources(sucrune_probe PRIVATE guest_exec_receive.c pty_child.c pty_broker.c pty_session.c guest_proc.c)
    target_sources(sucrune_runner PRIVATE guest_exec_receive.c pty_child.c pty_session.c guest_proc.c)
    target_sources(sucrune_runner PRIVATE pty_runtime.c guest_processes.c project_scope.c guest_fork_child.c guest_fork_entry.S)
    target_compile_definitions(sucrune_runner PRIVATE SUCRUNE_RUNNER_EXECUTABLE _GNU_SOURCE)
    target_compile_features(sucrune_runner PRIVATE c_std_11)
    target_compile_options(sucrune_runner PRIVATE
        "$<$<COMPILE_LANGUAGE:C>:-Wall;-Wextra;-Werror;-Wconversion;-Wshadow;-fvisibility=hidden>")
    target_link_libraries(sucrune_runner PRIVATE Threads::Threads)
    target_link_options(sucrune_runner PRIVATE "-Wl,-z,max-page-size=16384")
    set(RUNNER_PACKAGE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.build/android-runners/${ANDROID_ABI}")
    add_custom_command(TARGET sucrune_runner POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${RUNNER_PACKAGE_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:sucrune_runner>" "${RUNNER_PACKAGE_DIR}/libsucrune_runner.so"
        VERBATIM)
    add_dependencies(sucrune_probe sucrune_runner)
    if(ANDROID_ABI STREQUAL "arm64-v8a")
        set(SUCRUNE_HELLO_ELF "${CMAKE_CURRENT_BINARY_DIR}/sucrune-hello.elf")
        add_custom_command(OUTPUT "${SUCRUNE_HELLO_ELF}"
            COMMAND "${CMAKE_C_COMPILER}" --target=aarch64-linux-android29
                -nostdlib -static -fuse-ld=lld
                -Wl,-pie,-Bsymbolic,--no-dynamic-linker,--build-id=none,-z,max-page-size=16384
                "-Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/guest/hello.ld"
                "${CMAKE_CURRENT_SOURCE_DIR}/guest/hello.S" -o "${SUCRUNE_HELLO_ELF}"
            DEPENDS guest/hello.S guest/hello.ld VERBATIM)
        configure_file(guest/embed.S.in "${CMAKE_CURRENT_BINARY_DIR}/guest_embed.S" @ONLY)
        set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/guest_embed.S"
            PROPERTIES OBJECT_DEPENDS "${SUCRUNE_HELLO_ELF}")
        target_sources(sucrune_probe PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/guest_embed.S")
        set(SUCRUNE_SHELL_ELF "${CMAKE_CURRENT_BINARY_DIR}/sucrune-sh.elf")
        add_custom_command(OUTPUT "${SUCRUNE_SHELL_ELF}"
            COMMAND "${CMAKE_C_COMPILER}" --target=aarch64-linux-android29
                -std=c11 -O2 -ffreestanding -fno-builtin -fno-stack-protector -ffixed-x18 -fPIC
                -Wall -Wextra -Werror -nostdlib -static -fuse-ld=lld
                -Wl,-pie,-Bsymbolic,--no-dynamic-linker,--build-id=none,-z,max-page-size=16384
                "-Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/shell/shell.ld"
                "${CMAKE_CURRENT_SOURCE_DIR}/shell/start.S" "${CMAKE_CURRENT_SOURCE_DIR}/shell/shell.c"
                -o "${SUCRUNE_SHELL_ELF}"
            DEPENDS shell/start.S shell/shell.c shell/shell.ld VERBATIM)
        configure_file(shell/embed.S.in "${CMAKE_CURRENT_BINARY_DIR}/shell_embed.S" @ONLY)
        set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/shell_embed.S"
            PROPERTIES OBJECT_DEPENDS "${SUCRUNE_SHELL_ELF}")
        target_sources(sucrune_probe PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/shell_embed.S")
        get_filename_component(SUCRUNE_MUSL_SMOKE_ELF
            "${CMAKE_CURRENT_SOURCE_DIR}/../.build/linux-programs/sucrune-musl-smoke.elf" ABSOLUTE)
        if(NOT EXISTS "${SUCRUNE_MUSL_SMOKE_ELF}")
            message(FATAL_ERROR "Trusted musl fixture is missing. Run scripts/build-linux-programs.ps1 -Zig <path-to-Zig-0.17.1> before Gradle/CMake, or use scripts/build-android.ps1 -Zig <path>.")
        endif()
        configure_file(programs/embed.S.in "${CMAKE_CURRENT_BINARY_DIR}/musl_smoke_embed.S" @ONLY)
        set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/musl_smoke_embed.S"
            PROPERTIES OBJECT_DEPENDS "${SUCRUNE_MUSL_SMOKE_ELF}")
        target_sources(sucrune_probe PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/musl_smoke_embed.S")
        get_filename_component(SUCRUNE_LUA_ELF
            "${CMAKE_CURRENT_SOURCE_DIR}/../.build/linux-programs/sucrune-lua.elf" ABSOLUTE)
        if(NOT EXISTS "${SUCRUNE_LUA_ELF}")
            message(FATAL_ERROR "Trusted Lua interpreter is missing. Run scripts/build-linux-programs.ps1 -Zig <path-to-Zig-0.17.1> before Gradle/CMake, or use scripts/build-android.ps1 -Zig <path>.")
        endif()
        configure_file(programs/lua_embed.S.in "${CMAKE_CURRENT_BINARY_DIR}/lua_embed.S" @ONLY)
        set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/lua_embed.S"
            PROPERTIES OBJECT_DEPENDS "${SUCRUNE_LUA_ELF}")
        target_sources(sucrune_probe PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/lua_embed.S")
        target_sources(sucrune_runner PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/shell_embed.S"
            "${CMAKE_CURRENT_BINARY_DIR}/musl_smoke_embed.S" "${CMAKE_CURRENT_BINARY_DIR}/lua_embed.S")
    endif()
    target_link_options(sucrune_probe PRIVATE "-Wl,-z,max-page-size=16384")
else()
    add_executable(sucrune_probe_cli ${PROBE_SOURCES} cli.c)
endif()

if(ANDROID)
    set(PROBE_TARGET sucrune_probe)
else()
    set(PROBE_TARGET sucrune_probe_cli)
endif()
target_compile_features(${PROBE_TARGET} PRIVATE c_std_11)
target_compile_definitions(${PROBE_TARGET} PRIVATE _GNU_SOURCE)
target_compile_options(${PROBE_TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:-Wall;-Wextra;-Werror;-Wconversion;-Wshadow;-fvisibility=hidden>")
target_link_libraries(${PROBE_TARGET} PRIVATE Threads::Threads)

if(NOT ANDROID)
    enable_testing()
    add_executable(sucrune_shell_tests shell/tests_host.c)
    target_compile_features(sucrune_shell_tests PRIVATE c_std_11)
    target_compile_options(sucrune_shell_tests PRIVATE -Wall -Wextra -Werror -O0)
    add_test(NAME shell_parser_and_builtins COMMAND sucrune_shell_tests)
    add_executable(sucrune_project_scope_tests project_scope.c project_scope_tests.c)
    target_compile_definitions(sucrune_project_scope_tests PRIVATE _GNU_SOURCE)
    target_compile_options(sucrune_project_scope_tests PRIVATE -Wall -Wextra -Werror -Wconversion -Wshadow)
    target_link_libraries(sucrune_project_scope_tests PRIVATE Threads::Threads)
    add_test(NAME project_process_scope COMMAND sucrune_project_scope_tests)
    add_executable(sucrune_guest_fds_tests guest_fds.c guest_fds_tests.c)
    target_compile_features(sucrune_guest_fds_tests PRIVATE c_std_11)
    target_compile_options(sucrune_guest_fds_tests PRIVATE -Wall -Wextra -Werror -Wconversion -Wshadow)
    add_test(NAME guest_fd_ownership COMMAND sucrune_guest_fds_tests)
    add_executable(sucrune_workspace_broker_tests workspace_broker.c guest_landlock.c workspace_locks.c workspace_links.c workspace_links_recover.c workspace_broker_tests.c guest_fds.c
        broker_transport.c network_broker.c guest_sockets.c dns_proxy.c pty_runtime.c pty_broker.c)
    target_compile_features(sucrune_workspace_broker_tests PRIVATE c_std_11)
    target_compile_definitions(sucrune_workspace_broker_tests PRIVATE _GNU_SOURCE)
    target_compile_options(sucrune_workspace_broker_tests PRIVATE -Wall -Wextra -Werror -Wconversion -Wshadow)
    target_link_libraries(sucrune_workspace_broker_tests PRIVATE Threads::Threads)
    add_test(NAME workspace_broker_boundaries COMMAND sucrune_workspace_broker_tests)
    add_executable(sucrune_link_recovery_tests workspace_links_recover.c workspace_link_recovery_tests.c)
    target_compile_definitions(sucrune_link_recovery_tests PRIVATE _GNU_SOURCE)
    target_compile_options(sucrune_link_recovery_tests PRIVATE -Wall -Wextra -Werror -Wconversion -Wshadow)
    add_test(NAME workspace_link_recovery COMMAND sucrune_link_recovery_tests)
    set_tests_properties(workspace_broker_boundaries PROPERTIES TIMEOUT 15)
    foreach(network_test IN ITEMS network_broker broker_transport)
        add_executable(sucrune_${network_test}_tests ${network_test}_tests.c workspace_broker.c guest_landlock.c workspace_locks.c workspace_links.c workspace_links_recover.c
            network_broker.c broker_transport.c guest_network.c guest_sockets.c guest_fds.c dns_proxy.c pty_runtime.c pty_broker.c)
        target_compile_features(sucrune_${network_test}_tests PRIVATE c_std_11)
        target_compile_definitions(sucrune_${network_test}_tests PRIVATE _GNU_SOURCE)
        target_compile_options(sucrune_${network_test}_tests PRIVATE -Wall -Wextra -Werror -Wconversion -Wshadow)
        target_link_libraries(sucrune_${network_test}_tests PRIVATE Threads::Threads)
        add_test(NAME ${network_test}_invariants COMMAND sucrune_${network_test}_tests)
        set_tests_properties(${network_test}_invariants PROPERTIES TIMEOUT 20)
    endforeach()
    add_executable(sucrune_elf_loader_tests elf_loader.c loader_tests.c)
    target_compile_features(sucrune_elf_loader_tests PRIVATE c_std_11)
    target_compile_definitions(sucrune_elf_loader_tests PRIVATE _GNU_SOURCE SUCRUNE_ELF_TEST_MAIN)
    target_compile_options(sucrune_elf_loader_tests PRIVATE -Wall -Wextra -Werror -Wconversion -Wshadow)
    add_test(NAME elf_parser_boundaries COMMAND sucrune_elf_loader_tests)
    add_test(NAME seccomp_signal_round_trip COMMAND sucrune_probe_cli)
    set_tests_properties(seccomp_signal_round_trip PROPERTIES TIMEOUT 10)
    include(host_tests.cmake)
endif()
