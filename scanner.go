package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type PortEntry struct {
	PID      int
	Port     int
	Protocol string
	Process  string
	State    string
}

func ScanPorts() ([]PortEntry, error) {
	if runtime.GOOS == "windows" {
		return scanPortsWindows()
	}
	return scanPortsUnix()
}

func scanPortsUnix() ([]PortEntry, error) {
	// lsof -iTCP -sTCP:LISTEN -n -P
	cmd := exec.Command("lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 1 {
				return []PortEntry{}, nil // Exit code 1 means no matching files, which is ok
			}
		}
		return nil, fmt.Errorf("failed to run lsof: %v", err)
	}

	lines := strings.Split(out.String(), "\n")
	entries := make(map[string]PortEntry)

	// Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		process := fields[0]
		pidStr := fields[1]
		protocol := fields[7] // e.g., TCP

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// Port is in the NAME field, usually the 9th field, e.g. 127.0.0.53:53 (LISTEN)
		// Let's find the field containing :<port>
		nameField := ""
		for j := len(fields) - 1; j >= 0; j-- {
			if strings.Contains(fields[j], ":") {
				nameField = fields[j]
				break
			}
		}

		parts := strings.Split(nameField, ":")
		if len(parts) < 2 {
			continue
		}
		portStr := parts[len(parts)-1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		state := "LISTEN"
		if len(fields) >= 10 && strings.Contains(fields[len(fields)-1], "(LISTEN)") {
			state = "LISTEN"
		}

		key := fmt.Sprintf("%d-%d-%s", pid, port, protocol)
		if _, exists := entries[key]; !exists {
			entries[key] = PortEntry{
				PID:      pid,
				Port:     port,
				Protocol: protocol,
				Process:  process,
				State:    state,
			}
		}
	}

	return deduplicateAndSort(entries), nil
}

func scanPortsWindows() ([]PortEntry, error) {
	// netstat -ano
	cmd := exec.Command("netstat", "-ano")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run netstat: %v", err)
	}

	// tasklist /FO CSV
	taskCmd := exec.Command("tasklist", "/FO", "CSV")
	var taskOut bytes.Buffer
	taskCmd.Stdout = &taskOut
	if err := taskCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to run tasklist: %v", err)
	}

	// Parse tasklist output
	pidToProcess := make(map[int]string)
	taskLines := strings.Split(taskOut.String(), "\n")
	for i, line := range taskLines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\",\"")
		if len(parts) >= 2 {
			procName := strings.Trim(parts[0], "\"")
			pidStr := strings.Trim(parts[1], "\"")
			pid, _ := strconv.Atoi(pidStr)
			pidToProcess[pid] = procName
		}
	}

	entries := make(map[string]PortEntry)
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "TCP") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		protocol := fields[0]
		localAddress := fields[1]
		state := fields[3]
		pidStr := fields[4]

		if state != "LISTENING" {
			continue
		}
		state = "LISTEN"

		pid, _ := strconv.Atoi(pidStr)
		
		parts := strings.Split(localAddress, ":")
		if len(parts) < 2 {
			continue
		}
		portStr := parts[len(parts)-1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		procName := "Unknown"
		if name, ok := pidToProcess[pid]; ok {
			procName = name
		}

		key := fmt.Sprintf("%d-%d-%s", pid, port, protocol)
		if _, exists := entries[key]; !exists {
			entries[key] = PortEntry{
				PID:      pid,
				Port:     port,
				Protocol: protocol,
				Process:  procName,
				State:    state,
			}
		}
	}

	return deduplicateAndSort(entries), nil
}

func deduplicateAndSort(entries map[string]PortEntry) []PortEntry {
	var result []PortEntry
	for _, v := range entries {
		result = append(result, v)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Port < result[j].Port
	})

	return result
}
