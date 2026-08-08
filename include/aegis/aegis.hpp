/**
 * @file aegis.hpp
 * @brief Master Header & Global Definitions for aegis-sandbox Runtime
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <exception>
#include <span>
#include <format>
#include <chrono>

// -----------------------------------------------------------------------------
// Versioning & Metadata
// -----------------------------------------------------------------------------
#define AEGIS_VERSION_MAJOR 0
#define AEGIS_VERSION_MINOR 1
#define AEGIS_VERSION_PATCH 0
#define AEGIS_VERSION_STRING "0.1.0"

// -----------------------------------------------------------------------------
// Symbol Visibility Macros (Shared Library Exports)
// -----------------------------------------------------------------------------
#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(AEGIS_BUILD_INTERNAL)
        #define AEGIS_API __declspec(dllexport)
    #else
        #define AEGIS_API __declspec(dllimport)
    #endif
#else
    #if __GNUC__ >= 4 || defined(__clang__)
        #define AEGIS_API __attribute__((visibility("default")))
    #else
        #define AEGIS_API
    #endif
#endif

namespace aegis {

/**
 * @brief System-wide status codes for aegis-sandbox operations.
 */
enum class Status : uint32_t {
    Success                     = 0,
    ErrMicroVMBootFailed        = 1,
    ErrSnapshotRestoreFailed    = 2,
    ErrEBPFProbeLoadFailed      = 3,
    ErrSyscallBlocked           = 4,
    ErrNetworkEgressBlocked     = 5,
    ErrAgentExecutionTimeout    = 6,
    ErrPolicyViolation          = 7,
    ErrCgroupQuotaExceeded      = 8,
    ErrInvalidSandboxID         = 9,
    ErrTAPInterfaceCreationFailed= 10,
    ErrUnknown                  = 999
};

/**
 * @brief Converts a Status code into a human-readable string_view.
 */
[[nodiscard]] constexpr std::string_view status_to_string(Status status) noexcept {
    switch (status) {
        case Status::Success:                      return "Success";
        case Status::ErrMicroVMBootFailed:         return "Error: Firecracker MicroVM Boot Failed";
        case Status::ErrSnapshotRestoreFailed:     return "Error: MicroVM Memory Snapshot Restore Failed";
        case Status::ErrEBPFProbeLoadFailed:       return "Error: eBPF Kernel Probe Loading Failed";
        case Status::ErrSyscallBlocked:            return "Security Alert: Syscall Blocked by eBPF Policy";
        case Status::ErrNetworkEgressBlocked:      return "Security Alert: Network Egress Blocked by eBPF Policy";
        case Status::ErrAgentExecutionTimeout:     return "Error: Agent Execution Timeout Reached";
        case Status::ErrPolicyViolation:           return "Error: Security Policy Constraints Violated";
        case Status::ErrCgroupQuotaExceeded:       return "Error: Cgroups v2 Resource Quota Exceeded";
        case Status::ErrInvalidSandboxID:          return "Error: Invalid or Non-Existent Sandbox ID";
        case Status::ErrTAPInterfaceCreationFailed:return "Error: TAP Network Interface Creation Failed";
        default:                                   return "Error: Unknown Runtime Failure";
    }
}

/**
 * @brief Base exception class for aegis-sandbox runtime failures.
 */
class AEGIS_API AegisException : public std::exception {
public:
    explicit AegisException(Status status, std::string_view message)
        : m_status(status), m_message(std::format("[AEGIS-{}] {}", static_cast<uint32_t>(status), message)) {}

    [[nodiscard]] const char* what() const noexcept override {
        return m_message.c_str();
    }

    [[nodiscard]] Status status() const noexcept {
        return m_status;
    }

private:
    Status m_status;
    std::string m_message;
};

/**
 * @brief Target agent runtime environment type.
 */
enum class RuntimeEnvironment : uint32_t {
    Unspecified = 0,
    Python311   = 1,
    Bash        = 2,
    NodeJS      = 3
};

/**
 * @brief Active status state of a microVM sandbox instance.
 */
enum class SandboxState : uint32_t {
    Initializing = 0,
    Prewarmed    = 1,
    Running      = 2,
    Terminating  = 3,
    Terminated   = 4,
    Violated     = 5
};

/**
 * @brief Struct holding runtime metadata for an active microVM sandbox.
 */
struct AEGIS_API SandboxMetadata {
    std::string sandbox_id;
    RuntimeEnvironment environment{RuntimeEnvironment::Unspecified};
    SandboxState state{SandboxState::Initializing};
    uint32_t vcpus{1};
    uint32_t memory_mb{512};
    uint32_t vram_mb{0};
    double boot_time_ms{0.0};
    std::string guest_ip;
    std::string tap_device_name;
    std::chrono::system_clock::time_point created_at{std::chrono::system_clock::now()};
};

/**
 * @brief Struct representing version details.
 */
struct Version {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;

    [[nodiscard]] std::string to_string() const {
        return std::format("{}.{}.{}", major, minor, patch);
    }
};

/**
 * @brief Returns the runtime version of the aegis-sandbox core library.
 */
[[nodiscard]] inline Version get_version() noexcept {
    return Version{AEGIS_VERSION_MAJOR, AEGIS_VERSION_MINOR, AEGIS_VERSION_PATCH};
}

// -----------------------------------------------------------------------------
// Sub-namespace Forward Declarations
// -----------------------------------------------------------------------------
namespace runtime {}
namespace ebpf {}
namespace policy {}
namespace utils {}

} // namespace aegis