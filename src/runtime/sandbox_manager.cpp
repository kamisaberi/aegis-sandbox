/**
 * @file sandbox_manager.cpp
 * @brief Firecracker MicroVM Sandbox Manager & Orchestrator Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <aegis/runtime/sandbox_manager.hpp>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <net/if.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_tun.h>

#include <fstream>
#include <sstream>
#include <iostream>
#include <format>
#include <cstring>
#include <chrono>
#include <thread>

namespace aegis::runtime {

namespace {

// Helper function to send HTTP PUT requests over a UNIX domain socket to Firecracker API
bool send_unix_http_put(const std::filesystem::path& socket_path, std::string_view endpoint, std::string_view json_payload) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) return false;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock_fd);
        return false;
    }

    std::string http_request = std::format(
        "PUT {} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n\r\n"
        "{}",
        endpoint, json_payload.size(), json_payload
    );

    ssize_t bytes_sent = write(sock_fd, http_request.data(), http_request.size());
    
    char response_buf[1024];
    ssize_t bytes_read = read(sock_fd, response_buf, sizeof(response_buf) - 1);
    close(sock_fd);

    if (bytes_sent <= 0 || bytes_read <= 0) return false;
    response_buf[bytes_read] = '\0';

    // Verify 2xx status code response
    return (std::string_view(response_buf).find("HTTP/1.1 2") != std::string_view::npos);
}

} // anonymous namespace

SandboxManager::SandboxManager(
    std::shared_ptr<ebpf::EBPFLoader> ebpf_loader,
    std::shared_ptr<policy::PolicyEngine> policy_engine,
    std::filesystem::path base_runtime_dir
) : m_ebpf_loader(std::move(ebpf_loader)),
    m_policy_engine(std::move(policy_engine)),
    m_base_runtime_dir(std::move(base_runtime_dir)) {

    m_cgroup_manager = std::make_unique<CgroupManager>();
    std::error_code ec;
    std::filesystem::create_directories(m_base_runtime_dir, ec);
}

SandboxManager::~SandboxManager() {
    terminate_all();
}

Status SandboxManager::create_sandbox(const SandboxConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (config.sandbox_id.empty() || m_sandboxes.contains(config.sandbox_id)) {
        return Status::ErrInvalidSandboxID;
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    // 1. Prepare runtime directory for sandbox socket files
    std::filesystem::path sbx_dir = m_base_runtime_dir / config.sandbox_id;
    std::error_code ec;
    std::filesystem::create_directories(sbx_dir, ec);

    SandboxInstance instance{};
    instance.config = config;
    instance.socket_path = sbx_dir / "firecracker.socket";
    instance.guest_vsock_path = sbx_dir / "guest_agent.socket";

    instance.metadata.sandbox_id = config.sandbox_id;
    instance.metadata.environment = config.environment;
    instance.metadata.vcpus = config.resource_limits.cpu_cores;
    instance.metadata.memory_mb = config.resource_limits.memory_mb;
    instance.metadata.vram_mb = config.resource_limits.vram_mb;
    instance.metadata.state = SandboxState::Initializing;

    // 2. Create Linux Cgroups v2 Resource Restrictions
    Status status = m_cgroup_manager->create_cgroup(config.sandbox_id, config.resource_limits);
    if (status != Status::Success) {
        std::filesystem::remove_all(sbx_dir, ec);
        return status;
    }

    // 3. Create TAP Network Interface
    status = setup_tap_interface(instance);
    if (status != Status::Success) {
        m_cgroup_manager->destroy_cgroup(config.sandbox_id);
        std::filesystem::remove_all(sbx_dir, ec);
        return status;
    }

    // 4. Spawn Firecracker MicroVM Process
    status = spawn_firecracker_process(instance);
    if (status != Status::Success) {
        if (instance.tap_fd >= 0) close(instance.tap_fd);
        m_cgroup_manager->destroy_cgroup(config.sandbox_id);
        std::filesystem::remove_all(sbx_dir, ec);
        return status;
    }

    // 5. Attach Firecracker Process to Cgroups v2
    m_cgroup_manager->attach_pid(config.sandbox_id, instance.firecracker_pid);

    // 6. Configure MicroVM via REST API or Restore Pre-Warmed Memory Snapshot
    if (config.use_snapshot_restore && std::filesystem::exists(config.snapshot_dir_path)) {
        status = restore_firecracker_snapshot(instance);
    } else {
        status = configure_firecracker_api(instance);
    }

    if (status != Status::Success) {
        terminate_sandbox(config.sandbox_id, true);
        return status;
    }

    // 7. Apply eBPF Kernel Security Policies
    status = apply_ebpf_policies(instance);
    if (status != Status::Success) {
        terminate_sandbox(config.sandbox_id, true);
        return status;
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    instance.metadata.boot_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    instance.metadata.state = SandboxState::Running;
    instance.is_active = true;

    m_sandboxes.insert_or_assign(config.sandbox_id, std::move(instance));
    return Status::Success;
}

Status SandboxManager::spawn_firecracker_process(SandboxInstance& instance) {
    if (std::filesystem::exists(instance.socket_path)) {
        std::filesystem::remove(instance.socket_path);
    }

    pid_t pid = fork();
    if (pid < 0) {
        return Status::ErrMicroVMBootFailed;
    }

    if (pid == 0) {
        // Child Process: Exec Firecracker binary
        std::string bin_path = instance.config.firecracker_bin_path.string();
        std::string sock_path = instance.socket_path.string();

        char* argv[] = {
            const_cast<char*>(bin_path.c_str()),
            const_cast<char*>("--api-sock"),
            const_cast<char*>(sock_path.c_str()),
            nullptr
        };

        // Redirect stdio to /dev/null for quiet background operation
        int dev_null = open("/dev/null", O_RDWR);
        if (dev_null >= 0) {
            dup2(dev_null, STDIN_FILENO);
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        execv(bin_path.c_str(), argv);
        _exit(1); // Exec failed
    }

    // Parent Process: Wait for Firecracker UNIX Domain Socket to become available
    instance.firecracker_pid = pid;
    for (int i = 0; i < 50; ++i) { // Poll socket for up to 500ms
        if (std::filesystem::exists(instance.socket_path)) {
            return Status::Success;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return Status::ErrMicroVMBootFailed;
}

Status SandboxManager::configure_firecracker_api(const SandboxInstance& instance) {
    // 1. Set Boot Source Kernel
    std::string boot_payload = std::format(
        R"({{"kernel_image_path":"{}","boot_args":"console=ttyS0 reboot=k panic=1 pci=off ip=172.16.0.2::172.16.0.1:255.255.255.0::eth0:off"}})",
        instance.config.kernel_image_path.string()
    );
    if (!send_unix_http_put(instance.socket_path, "/boot-source", boot_payload)) {
        return Status::ErrMicroVMBootFailed;
    }

    // 2. Set Rootfs Drive
    std::string drive_payload = std::format(
        R"({{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":false}})",
        instance.config.rootfs_image_path.string()
    );
    if (!send_unix_http_put(instance.socket_path, "/drives/rootfs", drive_payload)) {
        return Status::ErrMicroVMBootFailed;
    }

    // 3. Set Machine Configuration (vCPUs & RAM)
    std::string machine_payload = std::format(
        R"({{"vcpu_count":{},"mem_size_mib":{}}})",
        instance.config.resource_limits.cpu_cores,
        instance.config.resource_limits.memory_mb
    );
    if (!send_unix_http_put(instance.socket_path, "/machine-config", machine_payload)) {
        return Status::ErrMicroVMBootFailed;
    }

    // 4. Start MicroVM Instance
    std::string action_payload = R"({"action_type":"InstanceStart"})";
    if (!send_unix_http_put(instance.socket_path, "/actions", action_payload)) {
        return Status::ErrMicroVMBootFailed;
    }

    return Status::Success;
}

Status SandboxManager::restore_firecracker_snapshot(const SandboxInstance& instance) {
    std::filesystem::path mem_file = instance.config.snapshot_dir_path / "mem.snap";
    std::filesystem::path state_file = instance.config.snapshot_dir_path / "state.snap";

    std::string snapshot_payload = std::format(
        R"({{"snapshot_path":"{}","mem_file_path":"{}","resume_vm":true}})",
        state_file.string(), mem_file.string()
    );

    if (!send_unix_http_put(instance.socket_path, "/snapshot/load", snapshot_payload)) {
        return Status::ErrSnapshotRestoreFailed;
    }

    return Status::Success;
}

Status SandboxManager::setup_tap_interface(SandboxInstance& instance) {
    int tap_fd = open("/dev/net/tun", O_RDWR);
    if (tap_fd < 0) {
        return Status::ErrTAPInterfaceCreationFailed;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::string tap_name = std::format("tap_{}", instance.config.sandbox_id.substr(0, 8));
    std::strncpy(ifr.ifr_name, tap_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(tap_fd, TUNSETIFF, &ifr) < 0) {
        close(tap_fd);
        return Status::ErrTAPInterfaceCreationFailed;
    }

    instance.tap_fd = tap_fd;
    instance.metadata.tap_device_name = tap_name;
    instance.metadata.guest_ip = "172.16.0.2";

    return Status::Success;
}

Status SandboxManager::apply_ebpf_policies(const SandboxInstance& instance) {
    if (!m_ebpf_loader || !m_policy_engine) {
        return Status::Success; // eBPF monitoring optional if not provided
    }

    uint64_t cgroup_id = m_cgroup_manager->get_cgroup_id(instance.config.sandbox_id);
    if (cgroup_id == 0) {
        return Status::ErrCgroupQuotaExceeded;
    }

    // 1. Enable eBPF Cgroup monitoring
    m_ebpf_loader->set_cgroup_monitored(cgroup_id, true);

    // 2. Fetch and apply security policy rules
    auto policy_opt = m_policy_engine->get_policy(instance.config.security_policy_name);
    if (policy_opt.has_value()) {
        const auto& policy = *policy_opt;

        // Load whitelisted/blacklisted syscall rules
        for (uint32_t sys_nr : policy.syscall_rule.blocked_syscalls) {
            m_ebpf_loader->set_syscall_policy(sys_nr, 1); // Block / SIGKILL
        }

        // Load network egress rules
        if (policy.network_rule.block_cloud_metadata) {
            uint32_t metadata_ip = inet_addr("169.254.169.254");
            m_ebpf_loader->set_blocked_ip(metadata_ip, true);
        }
    }

    return Status::Success;
}

ExecutionResult SandboxManager::execute_code(std::string_view sandbox_id, std::string_view code_payload) {
    std::lock_guard<std::mutex> lock(m_mutex);

    ExecutionResult result{};
    result.sandbox_id = std::string(sandbox_id);

    auto it = m_sandboxes.find(result.sandbox_id);
    if (it == m_sandboxes.end() || !it->second.is_active) {
        result.exit_code = -1;
        result.stderr_output = "Error: Invalid or inactive sandbox ID.";
        return result;
    }

    auto exec_start = std::chrono::high_resolution_clock::now();

    // Communicate with Guest Agent inside MicroVM over vsock / UNIX domain socket
    int agent_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (agent_sock >= 0) {
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, it->second.guest_vsock_path.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(agent_sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) >= 0) {
            write(agent_sock, code_payload.data(), code_payload.size());

            char response_buf[8192];
            ssize_t bytes = read(agent_sock, response_buf, sizeof(response_buf) - 1);
            if (bytes > 0) {
                response_buf[bytes] = '\0';
                result.stdout_output = response_buf;
                result.exit_code = 0;
            }
        }
        close(agent_sock);
    }

    auto exec_end = std::chrono::high_resolution_clock::now();
    result.execution_time_ms = std::chrono::duration<double, std::milli>(exec_end - exec_start).count();
    result.boot_time_ms = it->second.metadata.boot_time_ms;

    return result;
}

Status SandboxManager::terminate_sandbox(std::string_view sandbox_id, bool /* force_wipe */) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string sbx_id(sandbox_id);
    auto it = m_sandboxes.find(sbx_id);
    if (it == m_sandboxes.end()) {
        return Status::ErrInvalidSandboxID;
    }

    // 1. Terminate Firecracker Process
    if (it->second.firecracker_pid > 0) {
        kill(it->second.firecracker_pid, SIGKILL);
        int status_val;
        waitpid(it->second.firecracker_pid, &status_val, WNOHANG);
    }

    // 2. Close TAP Device Descriptor
    if (it->second.tap_fd >= 0) {
        close(it->second.tap_fd);
    }

    // 3. Disable eBPF Cgroup Monitoring
    if (m_ebpf_loader) {
        uint64_t cgroup_id = m_cgroup_manager->get_cgroup_id(sbx_id);
        if (cgroup_id > 0) {
            m_ebpf_loader->set_cgroup_monitored(cgroup_id, false);
        }
    }

    // 4. Remove Cgroup Directory
    m_cgroup_manager->destroy_cgroup(sbx_id);

    // 5. Remove Runtime Socket Files
    std::error_code ec;
    std::filesystem::remove_all(m_base_runtime_dir / sbx_id, ec);

    m_sandboxes.erase(it);
    return Status::Success;
}

std::optional<SandboxMetadata> SandboxManager::get_metadata(std::string_view sandbox_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_sandboxes.find(std::string(sandbox_id));
    if (it != m_sandboxes.end()) {
        return it->second.metadata;
    }
    return std::nullopt;
}

void SandboxManager::terminate_all() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::error_code ec;
    for (auto& [id, instance] : m_sandboxes) {
        if (instance.firecracker_pid > 0) {
            kill(instance.firecracker_pid, SIGKILL);
            int status_val;
            waitpid(instance.firecracker_pid, &status_val, WNOHANG);
        }
        if (instance.tap_fd >= 0) {
            close(instance.tap_fd);
        }
        m_cgroup_manager->destroy_cgroup(id);
        std::filesystem::remove_all(m_base_runtime_dir / id, ec);
    }
    m_sandboxes.clear();
}

} // namespace aegis::runtime