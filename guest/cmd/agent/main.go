// guest/cmd/agent/main.go
// MicroVM Guest Init Agent for aegis-sandbox
// Author: Kamran Saberifard
// License: Apache 2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	socketPath    = "/run/aegis-guest.sock"
	scriptTempDir = "/tmp"
	defaultTimeout = 15 * time.Second
)

// ExecutionRequest represents the JSON payload sent from the host SandboxManager.
type ExecutionRequest struct {
	CodePayload string            `json:"code_payload"`
	CLIArgs     []string          `json:"cli_args"`
	Environment map[string]string `json:"environment"`
	TimeoutSec  int               `json:"timeout_sec"`
}

// ExecutionResponse represents the JSON response returned to the host.
type ExecutionResponse struct {
	ExitCode    int     `json:"exit_code"`
	Stdout      string  `json:"stdout"`
	Stderr      string  `json:"stderr"`
	DurationMS  float64 `json:"duration_ms"`
	ErrorString string  `json:"error_string,omitempty"`
}

func main() {
	log.Println("[AEGIS-GUEST-AGENT] Initializing guest init agent inside microVM...")

	// Remove any stale socket file inside guest rootfs
	_ = os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("[AEGIS-GUEST-FATAL] Failed to listen on UNIX socket %s: %v", socketPath, err)
	}
	defer listener.Close()

	// Ensure full read/write permissions on the guest socket
	_ = os.Chmod(socketPath, 0777)

	log.Printf("[AEGIS-GUEST-AGENT] Ready. Listening on UNIX socket %s", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[AEGIS-GUEST-ERROR] Failed to accept socket connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req ExecutionRequest
	if err := decoder.Decode(&req); err != nil {
		resp := ExecutionResponse{
			ExitCode:    -1,
			ErrorString: fmt.Sprintf("Failed to decode JSON execution request: %v", err),
		}
		_ = encoder.Encode(resp)
		return
	}

	startTime := time.Now()

	// 1. Write Code Payload to a temporary script file inside /tmp
	scriptPath := filepath.Join(scriptTempDir, fmt.Sprintf("agent_script_%d.py", time.Now().UnixNano()))
	if err := os.WriteFile(scriptPath, []byte(req.CodePayload), 0600); err != nil {
		resp := ExecutionResponse{
			ExitCode:    -1,
			ErrorString: fmt.Sprintf("Failed to write temporary python script: %v", err),
		}
		_ = encoder.Encode(resp)
		return
	}
	defer os.Remove(scriptPath) // Wipe script immediately after execution

	// 2. Configure execution timeout context
	timeout := defaultTimeout
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 3. Prepare Python 3.11 execution command
	args := append([]string{scriptPath}, req.CLIArgs...)
	cmd := exec.CommandContext(ctx, "python3", args...)

	// Pass custom environment variables if specified
	cmd.Env = os.Environ()
	for k, v := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// 4. Execute script inside guest environment
	err := cmd.Run()
	duration := time.Since(startTime).Seconds() * 1000.0 // Duration in milliseconds

	exitCode := 0
	errorStr := ""

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			exitCode = 124 // Timeout exit code
			errorStr = "Execution timed out inside guest microVM"
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
			errorStr = err.Error()
		}
	}

	// 5. Send ExecutionResponse JSON back to the host SandboxManager
	resp := ExecutionResponse{
		ExitCode:    exitCode,
		Stdout:      stdoutBuf.String(),
		Stderr:      stderrBuf.String(),
		DurationMS:  duration,
		ErrorString: errorStr,
	}

	_ = encoder.Encode(resp)
}