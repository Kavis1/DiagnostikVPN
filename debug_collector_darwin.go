//go:build darwin

package main

import (
	"os/exec"
	"time"
)

func platformDebugCommands() []debugCmd {
	return []debugCmd{
		{"ifconfig", "ifconfig"},
		{"netstat -nr (маршруты)", "netstat -nr"},
		{"netstat -an (открытые порты)", "netstat -an"},
		{"scutil --dns", "scutil --dns"},
		{"scutil --proxy", "scutil --proxy"},
		{"sw_vers (версия macOS)", "sw_vers"},
		{"system_profiler SPSoftwareDataType", "system_profiler SPSoftwareDataType"},
		{"system_profiler SPNetworkDataType (выдержка)", "system_profiler SPNetworkDataType"},
		{"ps -A (процессы)", "ps -A -o pid,user,comm"},
		{"ifconfig (подробно)", "ifconfig -a"},
		{"netstat -s (статистика по протоколам)", "netstat -s"},
	}
}

// runUTF8Cmd — на macOS терминал работает в UTF-8 по умолчанию, декодер не нужен.
func runUTF8Cmd(command string) (string, error) {
	ctx, cancel := windowsCmdContext(25 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// decodeConsoleOutput — на macOS просто string(b), кодировка уже UTF-8.
func decodeConsoleOutput(b []byte) string {
	return string(b)
}
