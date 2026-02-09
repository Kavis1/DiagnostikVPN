package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func runSystemInfoTests() []TestResult {
	var results []TestResult

	results = append(results, testOSInfo())
	results = append(results, testNetworkInterfaces())
	results = append(results, testDNSServers())
	results = append(results, testDefaultGateway())
	results = append(results, testTimeSync())

	return results
}

func testOSInfo() TestResult {
	hostname, _ := os.Hostname()
	info := fmt.Sprintf("%s/%s, хост: %s", runtime.GOOS, runtime.GOARCH, hostname)

	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err == nil {
		ver := strings.TrimSpace(string(out))
		if ver != "" {
			info = fmt.Sprintf("%s, %s", info, ver)
		}
	}

	return TestResult{
		Name:    "ОС и платформа",
		Status:  StatusOK,
		Message: info,
	}
}

func testNetworkInterfaces() TestResult {
	ifaces, err := net.Interfaces()
	if err != nil {
		return TestResult{
			Name:    "Сетевые интерфейсы",
			Status:  StatusError,
			Message: fmt.Sprintf("ошибка получения интерфейсов: %v", err),
		}
	}

	active := 0
	var details []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) == 0 {
			continue
		}
		active++
		addrStrs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}
		details = append(details, fmt.Sprintf("%s: %s", iface.Name, strings.Join(addrStrs, ", ")))
	}

	if active == 0 {
		return TestResult{
			Name:    "Сетевые интерфейсы",
			Status:  StatusError,
			Message: "нет активных сетевых интерфейсов",
		}
	}

	return TestResult{
		Name:    "Сетевые интерфейсы",
		Status:  StatusOK,
		Message: fmt.Sprintf("%d активных", active),
		Details: strings.Join(details, "\n"),
	}
}

func testDNSServers() TestResult {
	// Try ipconfig /all to find DNS servers (works on all Windows)
	out, err := exec.Command("ipconfig", "/all").CombinedOutput()
	if err == nil {
		servers := extractDNSFromIPConfig(string(out))
		if len(servers) > 0 {
			return TestResult{
				Name:    "DNS серверы",
				Status:  StatusOK,
				Message: strings.Join(servers, ", "),
			}
		}
	}

	// Fallback: nslookup
	out2, err2 := exec.Command("nslookup", "localhost").CombinedOutput()
	if err2 == nil {
		lines := strings.Split(string(out2), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Server:") || strings.HasPrefix(line, "Default Server:") {
				// Next line has Address
				if i+1 < len(lines) {
					addrLine := strings.TrimSpace(lines[i+1])
					if strings.HasPrefix(addrLine, "Address:") {
						addr := strings.TrimSpace(strings.SplitN(addrLine, ":", 2)[1])
						if addr != "" {
							return TestResult{
								Name:    "DNS серверы",
								Status:  StatusOK,
								Message: addr,
							}
						}
					}
				}
			}
		}
	}

	return TestResult{
		Name:    "DNS серверы",
		Status:  StatusWarning,
		Message: "не удалось определить",
	}
}

func extractDNSFromIPConfig(output string) []string {
	var servers []string
	seen := make(map[string]bool)
	lines := strings.Split(output, "\n")
	inDNS := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Match lines like "DNS Servers . . . : 8.8.8.8" or Russian equivalent
		if strings.Contains(line, "DNS") && strings.Contains(line, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				addr := strings.TrimSpace(parts[1])
				if addr != "" && isIPAddress(addr) && !seen[addr] {
					servers = append(servers, addr)
					seen[addr] = true
				}
			}
			inDNS = true
			continue
		}

		if inDNS {
			// Continuation lines (indented IP addresses)
			if trimmed != "" && isIPAddress(trimmed) && !seen[trimmed] {
				servers = append(servers, trimmed)
				seen[trimmed] = true
			} else if trimmed == "" || strings.Contains(trimmed, ":") {
				inDNS = false
			}
		}
	}
	return servers
}

func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

func testDefaultGateway() TestResult {
	out, err := exec.Command("cmd", "/c", "route", "print", "0.0.0.0").CombinedOutput()
	if err != nil {
		return TestResult{
			Name:    "Шлюз по умолчанию",
			Status:  StatusWarning,
			Message: "не удалось определить",
		}
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" {
			gateway := fields[2]
			if net.ParseIP(gateway) != nil {
				return TestResult{
					Name:    "Шлюз по умолчанию",
					Status:  StatusOK,
					Message: gateway,
				}
			}
		}
	}

	return TestResult{
		Name:    "Шлюз по умолчанию",
		Status:  StatusWarning,
		Message: "не найден",
	}
}

func testTimeSync() TestResult {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", "time.google.com:80", 3*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		return TestResult{
			Name:    "Системное время",
			Status:  StatusInfo,
			Message: fmt.Sprintf("%s (проверка недоступна)", time.Now().Format("2006-01-02 15:04:05 MST")),
		}
	}
	conn.Close()

	return TestResult{
		Name:    "Системное время",
		Status:  StatusOK,
		Message: fmt.Sprintf("%s (сеть отвечает за %s)", time.Now().Format("2006-01-02 15:04:05 MST"), elapsed.Round(time.Millisecond)),
		Latency: elapsed,
	}
}
