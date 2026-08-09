/**
 * @file main.cpp
 * @brief Command Line Interface (CLI) Executable for aegis-sandbox
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <aegis/aegis.hpp>
#include <aegis/runtime/sandbox_manager.hpp>
#include <aegis/policy/policy_engine.hpp>
#include <aegis/ebpf/ebpf_loader.hpp>

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <format>
#include <chrono>
#include <csignal>
#include <cstdlib>

namespace {

// Global manager pointer for signal handler teardown
aegis::runtime::SandboxManager* g_sandbox_manager = nullptr;

void signal_handler(int signal) {
    if (g_sandbox_manager) {
        std::cout << "\n\033[1;33m[AEGIS-CLI] Signal " << signal 
                  << " received. Wiping active sandboxes...\033[0m\n";
        g_sandbox_manager->terminate_all();
    }
    std::exit(signal);
}

void print_header() {
    std::cout << "\033[1;36m"
              << "   ___   _______ ____ ______   _____ ___   _  ______  ___  OX\n"
              << "  / _ \\ / __/ _ /  _/ __/  | / / _ / _ \\/ |/ / _ \\/ _ \\\n"
              << " / __ |/ _// __// // _// /| |/ __ / // /    / // / // /\n"
              << "/_/ |_/___/_/  /___/___/_/ |_/_/ |_/____/_/|_/____/____/\n"
              << "\033[0m"
              << "\033[1;32mSub-10ms MicroVM & eBPF Isolation Engine for AI Agents (v" 
              << aegis::AEGIS_VERSION_STRING << ")\033[0m\n\n";
}

void print_usage(const char* prog_name) {
    print_header();
    std::cout << "Usage:\n"
              << "  " << prog_name << " <command> [options]\n\n"
              << "Commands:\n"
              << "  create    Create and boot a new isolated Firecracker microVM sandbox\n"
              << "  exec      Execute untrusted AI agent code (Python/Bash) inside a sandbox\n"
              << "  terminate Destroy and wipe an active sandbox instance\n"
              << "  status    Display metadata for active sandboxes and eBPF enforcement maps\n"
              << "  version   Display version details and build information\n\n"
              << "Options:\n"
              << "  --id <string>         Sandbox ID (default: sbx-demo)\n"
              << "  --policy <string>     Security policy name (default: strict_python)\n"
              << "  --code <string>       Code payload string to execute\n"
              << "  --cpus <int>          vCPU core count limit (default: 1)\n"
              << "  --mem <int>           RAM limit in Megabytes (default: 512)\n\n"
              << "Examples:\n"
              << "  " << prog_name << " create --id sbx-test --policy strict_python --cpus 2 --mem 1024\n"
              << "  " << prog_name << " exec --id sbx-test --code \"print('Hello from aegis microVM')\"\n"
              << "  " << prog_name << " terminate --id sbx-test\n";
}

} // anonymous namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "version" || command == "--version" || command == "-v") {
        print_header();
        return 0;
    }

    // Default arguments
    std::string sandbox_id = "sbx-demo";
    std::string policy_name = "strict_python";
    std::string code_payload = "print('Hello from Aegis Isolated MicroVM!')";
    uint32_t cpus = 1;
    uint32_t memory_mb = 512;

    // CLI argument parsing
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--id" && i + 1 < argc) sandbox_id = argv[++i];
        else if (arg == "--policy" && i + 1 < argc) policy_name = argv[++i];
        else if (arg == "--code" && i + 1 < argc) code_payload = argv[++i];
        else if (arg == "--cpus" && i + 1 < argc) cpus = static_cast<uint32_t>(std::atoi(argv[++i]));
        else if (arg == "--mem" && i + 1 < argc) memory_mb = static_cast<uint32_t>(std::atoi(argv[++i]));
    }

    try {
        // Instantiate security and runtime components
        auto ebpf_loader = std::make_shared<aegis::ebpf::EBPFLoader>();
        auto policy_engine = std::make_shared<aegis::policy::PolicyEngine>();
        
        aegis::runtime::SandboxManager manager(ebpf_loader, policy_engine);
        g_sandbox_manager = &manager;

        if (command == "create") {
            print_header();
            std::cout << std::format("\033[1;34m[AEGIS-CLI] Booting MicroVM Sandbox [{}]...\033[0m\n", sandbox_id);

            aegis::runtime::SandboxConfig config{};
            config.sandbox_id = sandbox_id;
            config.security_policy_name = policy_name;
            config.resource_limits.cpu_cores = cpus;
            config.resource_limits.memory_mb = memory_mb;
            config.use_snapshot_restore = true; // Enables sub-10ms snapshot boot

            aegis::Status status = manager.create_sandbox(config);
            if (status == aegis::Status::Success) {
                auto meta = manager.get_metadata(sandbox_id);
                std::cout << "\033[1;32m[AEGIS-CLI] Sandbox Created Successfully!\033[0m\n"
                          << std::format("  • Sandbox ID  : {}\n", sandbox_id)
                          << std::format("  • Boot Time   : {:.2f} ms (Snapshot Restore)\n", meta ? meta->boot_time_ms : 0.0)
                          << std::format("  • vCPUs / RAM : {} Core(s) / {} MB\n", cpus, memory_mb)
                          << std::format("  • Policy      : {} (eBPF Active)\n", policy_name);
            } else {
                std::cerr << std::format("\033[1;31m[AEGIS-CLI] Failed to create sandbox: {}\033[0m\n", 
                                          aegis::status_to_string(status));
                return 1;
            }

        } else if (command == "exec") {
            std::cout << std::format("\033[1;34m[AEGIS-CLI] Executing code in Sandbox [{}]...\033[0m\n", sandbox_id);

            auto result = manager.execute_code(sandbox_id, code_payload);
            std::cout << "\n\033[1;36m--- [Execution Output] ---\033[0m\n"
                      << result.stdout_output << "\n"
                      << "\033[1;36m--------------------------\033[0m\n"
                      << std::format("  • Exit Code      : {}\n", result.exit_code)
                      << std::format("  • Execution Time : {:.2f} ms\n", result.execution_time_ms)
                      << std::format("  • eBPF Violations: {}\n", result.security_violation_triggered ? "YES (Blocked)" : "None (Clean)");

        } else if (command == "terminate") {
            std::cout << std::format("\033[1;33m[AEGIS-CLI] Terminating Sandbox [{}]...\033[0m\n", sandbox_id);
            aegis::Status status = manager.terminate_sandbox(sandbox_id, true);
            if (status == aegis::Status::Success) {
                std::cout << "\033[1;32m[AEGIS-CLI] Sandbox Terminated & Memory Wiped.\033[0m\n";
            } else {
                std::cerr << std::format("\033[1;31m[AEGIS-CLI] Termination failed: {}\033[0m\n", 
                                          aegis::status_to_string(status));
                return 1;
            }

        } else if (command == "status") {
            print_header();
            std::cout << "\033[1;34m[AEGIS-CLI] Querying Active Sandbox Status...\033[0m\n";
            auto meta = manager.get_metadata(sandbox_id);
            if (meta.has_value()) {
                std::cout << std::format("Active Sandbox: {} | Boot: {:.2f}ms | State: Running\n", 
                                          meta->sandbox_id, meta->boot_time_ms);
            } else {
                std::cout << "No active sandboxes found.\n";
            }

        } else {
            std::cerr << "\033[1;31m[AEGIS-CLI] Unknown command: " << command << "\033[0m\n\n";
            print_usage(argv[0]);
            return 1;
        }

        g_sandbox_manager = nullptr;
        return 0;

    } catch (const aegis::AegisException& ex) {
        std::cerr << std::format("\033[1;31m[AEGIS-FATAL] Runtime Exception: {}\033[0m\n", ex.what());
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << std::format("\033[1;31m[AEGIS-FATAL] Standard Exception: {}\033[0m\n", ex.what());
        return 1;
    }
}