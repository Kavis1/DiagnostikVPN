//go:build windows

package main

import (
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

func platformDebugCommands() []debugCmd {
	return []debugCmd{
		{"ipconfig /all", "ipconfig /all"},
		{"route print", "route print"},
		{"netstat -rn (маршруты)", "netstat -rn"},
		{"netstat -an (открытые порты)", "netstat -an"},
		{"netsh winhttp show proxy", "netsh winhttp show proxy"},
		{"netsh advfirewall show currentprofile", "netsh advfirewall show currentprofile"},
		{"netsh advfirewall show allprofiles", "netsh advfirewall show allprofiles"},
		{"netsh int tcp show global", "netsh int tcp show global"},
		{"netsh int ipv4 show interfaces", "netsh int ipv4 show interfaces"},
		{"systeminfo (короткая выдержка)", "systeminfo"},
		{"tasklist /v (видимые процессы)", "tasklist /v /FO TABLE"},
	}
}

// runUTF8Cmd выполняет команду через cmd /c и декодирует вывод из OEM-кодировки.
// ipconfig/route/netstat игнорируют chcp 65001 и пишут в OEM хост-локали —
// поэтому проще не бороться, а декодировать на нашей стороне.
func runUTF8Cmd(command string) (string, error) {
	ctx, cancel := windowsCmdContext(25 * time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "cmd", "/c", command)
	out, err := cmd.CombinedOutput()
	return decodeConsoleOutput(out), err
}

// decodeConsoleOutput определяет кодировку Windows-консоли и декодирует.
// 1. Если вывод уже валидный UTF-8 — возвращаем как есть.
// 2. Иначе пробуем cp866 (русская DOS).
// 3. Затем cp1251 (русская Windows).
// 4. Fallback — Latin1, не теряем байты.
func decodeConsoleOutput(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	if dec, err := decodeWith(b, charmap.CodePage866.NewDecoder()); err == nil {
		if utf8.ValidString(dec) {
			return dec
		}
	}
	if dec, err := decodeWith(b, charmap.Windows1251.NewDecoder()); err == nil {
		if utf8.ValidString(dec) {
			return dec
		}
	}
	if dec, err := decodeWith(b, charmap.Windows1252.NewDecoder()); err == nil {
		return dec
	}
	return string(b)
}

func decodeWith(b []byte, dec transform.Transformer) (string, error) {
	r := transform.NewReader(strings.NewReader(string(b)), dec)
	out, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
