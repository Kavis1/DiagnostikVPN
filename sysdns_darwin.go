//go:build darwin

package main

import (
	"net"
	"os/exec"
	"strings"
)

// platformSystemDNS — DNS-серверы через `scutil --dns`.
// Парсим строки вида "nameserver[0] : 192.168.1.1".
func platformSystemDNS() []string {
	out, err := exec.Command("scutil", "--dns").CombinedOutput()
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver[") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		addr := strings.TrimSpace(line[idx+1:])
		if addr == "" || seen[addr] {
			continue
		}
		if net.ParseIP(addr) == nil {
			continue
		}
		seen[addr] = true
		servers = append(servers, addr)
	}
	return servers
}
