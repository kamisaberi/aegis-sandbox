# tests/CMakeLists.txt
# Security Integration & Unit Test Configuration for aegis-sandbox
# Author: Kamran Saberifard
# License: Apache 2.0

message(STATUS "[aegis-sandbox] Configuring Security & Unit Integration Tests")

enable_testing()

# ------------------------------------------------------------------------------
# Test 1: eBPF Kernel Syscall & Anti-SSRF Blocking Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_ebpf_blocking.cpp")
    add_executable(test_ebpf_blocking test_ebpf_blocking.cpp)
    target_link_libraries(test_ebpf_blocking PRIVATE aegis_core Threads::Threads)
    add_test(NAME eBPFBlockingTest COMMAND test_ebpf_blocking)
endif()

# ------------------------------------------------------------------------------
# Test 2: YAML/JSON Security Policy Engine Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_policy_engine.cpp")
    add_executable(test_policy_engine test_policy_engine.cpp)
    target_link_libraries(test_policy_engine PRIVATE aegis_core Threads::Threads)
    add_test(NAME PolicyEngineTest COMMAND test_policy_engine)
endif()

# ------------------------------------------------------------------------------
# Test 3: Sandbox Escape & Penetration Security Test
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_sandbox_escape.cpp")
    add_executable(test_sandbox_escape test_sandbox_escape.cpp)
    target_link_libraries(test_sandbox_escape PRIVATE aegis_core Threads::Threads)
    add_test(NAME SandboxEscapeTest COMMAND test_sandbox_escape)
endif()