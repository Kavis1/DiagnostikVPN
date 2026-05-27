//go:build windows

package main

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// SystemProxyState — снимок настроек прокси (для последующего отката).
type SystemProxyState struct {
	WasEnabled bool
	Server     string
	Override   string
}

const proxyRegKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func setSystemProxy(proxyServer string) (SystemProxyState, error) {
	prev := readSystemProxyState()
	if err := regWrite("ProxyEnable", "REG_DWORD", "1"); err != nil {
		return prev, fmt.Errorf("ProxyEnable: %w", err)
	}
	if err := regWrite("ProxyServer", "REG_SZ", proxyServer); err != nil {
		return prev, fmt.Errorf("ProxyServer: %w", err)
	}
	regWrite("ProxyOverride", "REG_SZ", "<local>;127.0.0.1;localhost")
	notifyProxyChange()
	return prev, nil
}

func restoreSystemProxy(prev SystemProxyState) {
	if prev.WasEnabled {
		regWrite("ProxyEnable", "REG_DWORD", "1")
		if prev.Server != "" {
			regWrite("ProxyServer", "REG_SZ", prev.Server)
		}
		if prev.Override != "" {
			regWrite("ProxyOverride", "REG_SZ", prev.Override)
		}
	} else {
		regWrite("ProxyEnable", "REG_DWORD", "0")
	}
	notifyProxyChange()
}

func readSystemProxyState() SystemProxyState {
	st := SystemProxyState{}
	if v, err := regRead("ProxyEnable"); err == nil {
		if strings.Contains(v, "0x1") {
			st.WasEnabled = true
		}
	}
	if v, err := regRead("ProxyServer"); err == nil {
		st.Server = v
	}
	if v, err := regRead("ProxyOverride"); err == nil {
		st.Override = v
	}
	return st
}

func regWrite(name, typ, value string) error {
	cmd := exec.Command("reg", "add", proxyRegKey, "/v", name, "/t", typ, "/d", value, "/f")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func regRead(name string) (string, error) {
	out, err := exec.Command("reg", "query", proxyRegKey, "/v", name).CombinedOutput()
	if err != nil {
		return "", err
	}
	text := decodeConsoleOutput(out)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, name) {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return strings.Join(parts[2:], " "), nil
			}
		}
	}
	return "", fmt.Errorf("not found")
}

// notifyProxyChange — сигнализирует WinInet'у об изменении прокси, чтобы
// Edge/Chrome подхватили новые настройки без перезапуска.
func notifyProxyChange() {
	cmd := exec.Command("rundll32.exe", "wininet.dll,InternetSetOption", "0", "37", "0", "0")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Run()
}
