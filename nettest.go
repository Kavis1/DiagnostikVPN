package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func runNetworkTests(cfg *VPNConfig) []TestResult {
	var results []TestResult

	dnsResult := testDNSResolve(cfg.Address)
	results = append(results, dnsResult)

	// Если системный DNS не разрешил хост — пробуем альтернативные DNS
	if dnsResult.Status == StatusError && net.ParseIP(cfg.Address) == nil {
		results = append(results, testAlternativeDNS(cfg.Address))
	}

	results = append(results, testPing(cfg.Address))
	results = append(results, testPortConnect(cfg.Address, cfg.Port))
	results = append(results, testMTU(cfg.Address))
	results = append(results, testTraceroute(cfg.Address))

	return results
}

func testDNSResolve(host string) TestResult {
	if net.ParseIP(host) != nil {
		return TestResult{
			Name:    "DNS разрешение",
			Status:  StatusOK,
			Message: fmt.Sprintf("%s (IP адрес, DNS не требуется)", host),
		}
	}

	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := resolver.LookupIPAddr(ctx, host)
	elapsed := time.Since(start)

	if err != nil {
		return TestResult{
			Name:    "DNS разрешение",
			Status:  StatusError,
			Message: fmt.Sprintf("не удалось разрешить %s: %v", host, err),
			Latency: elapsed,
		}
	}

	if len(ips) == 0 {
		return TestResult{
			Name:    "DNS разрешение",
			Status:  StatusError,
			Message: fmt.Sprintf("хост %s не имеет IP адресов", host),
		}
	}

	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}

	return TestResult{
		Name:    "DNS разрешение",
		Status:  StatusOK,
		Message: fmt.Sprintf("%s -> %s", host, strings.Join(addrs, ", ")),
		Latency: elapsed,
	}
}

func testPing(host string) TestResult {
	start := time.Now()
	out, err := exec.Command("ping", pingArgs(4, 2000, false, 0, host)...).CombinedOutput()
	elapsed := time.Since(start)
	output := string(out)

	if err != nil {
		if !strings.Contains(output, "TTL=") && !strings.Contains(output, "ttl=") {
			return TestResult{
				Name:    "Ping",
				Status:  StatusError,
				Message: fmt.Sprintf("хост %s недоступен", host),
				Details: extractPingSummary(output),
				Latency: elapsed,
			}
		}
	}

	avgTime := extractPingAvg(output)
	if avgTime != "" {
		status := StatusOK
		if avg, e := strconv.Atoi(avgTime); e == nil && avg > 300 {
			status = StatusWarning
		}
		return TestResult{
			Name:    "Ping",
			Status:  status,
			Message: fmt.Sprintf("среднее: %sмс", avgTime),
			Details: extractPingSummary(output),
			Latency: elapsed,
		}
	}

	return TestResult{
		Name:    "Ping",
		Status:  StatusOK,
		Message: "хост доступен",
		Details: extractPingSummary(output),
		Latency: elapsed,
	}
}

func extractPingAvg(output string) string {
	// English: Average = 2ms
	// Russian: Среднее = 2мсек
	re := regexp.MustCompile(`(?:Average|Среднее)\s*=\s*(\d+)\s*(?:ms|мсек|мс)`)
	if m := re.FindStringSubmatch(output); len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractPingSummary(output string) string {
	lines := strings.Split(output, "\n")
	var summary []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "packets") || strings.Contains(lower, "пакет") ||
			strings.Contains(lower, "minimum") || strings.Contains(lower, "минимальное") ||
			strings.Contains(lower, "average") || strings.Contains(lower, "среднее") ||
			strings.Contains(lower, "lost") || strings.Contains(lower, "потеряно") ||
			strings.Contains(lower, "received") || strings.Contains(lower, "получено") {
			if line != "" {
				summary = append(summary, line)
			}
		}
	}
	return strings.Join(summary, "\n")
}

func testPortConnect(host string, port int) TestResult {
	addr := fmt.Sprintf("%s:%d", host, port)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		msg := fmt.Sprintf("порт %d недоступен: %v", port, err)
		if strings.Contains(err.Error(), "refused") {
			msg = fmt.Sprintf("порт %d: соединение отклонено (connection refused)", port)
		} else if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			msg = fmt.Sprintf("порт %d: таймаут подключения (возможна блокировка)", port)
		}
		return TestResult{
			Name:    "TCP подключение",
			Status:  StatusError,
			Message: msg,
			Latency: elapsed,
		}
	}
	conn.Close()

	status := StatusOK
	if elapsed > 8*time.Second {
		status = StatusWarning
	}

	return TestResult{
		Name:    "TCP подключение",
		Status:  status,
		Message: fmt.Sprintf("порт %d открыт", port),
		Latency: elapsed,
	}
}

func testMTU(host string) TestResult {
	// Binary search for MTU using ping -f -l (Don't Fragment)
	low, high := 500, 1472
	maxMTU := 0

	for low <= high {
		mid := (low + high) / 2
		out, err := exec.Command("ping", pingArgs(1, 2000, true, mid, host)...).CombinedOutput()
		output := string(out)

		if err == nil && (strings.Contains(output, "TTL=") || strings.Contains(output, "ttl=")) {
			maxMTU = mid + 28 // IP header (20) + ICMP header (8)
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	if maxMTU == 0 {
		return TestResult{
			Name:    "MTU",
			Status:  StatusWarning,
			Message: "не удалось определить (хост не отвечает на ping с DF)",
		}
	}

	status := StatusOK
	msg := fmt.Sprintf("%d байт", maxMTU)
	if maxMTU < 1400 {
		status = StatusWarning
		msg += " (ниже нормы, возможны проблемы с фрагментацией)"
	} else if maxMTU >= 1500 {
		msg += " (стандартный)"
	}

	return TestResult{
		Name:    "MTU",
		Status:  status,
		Message: msg,
	}
}

func testTraceroute(host string) TestResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	name, args := tracerouteCmd(host)
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	elapsed := time.Since(start)
	output := decodeConsoleOutput(out)

	if err != nil && !strings.Contains(output, "Trace") && !strings.Contains(output, "Трассировка") &&
		!strings.Contains(output, "over") && !strings.Contains(output, "route") &&
		!strings.Contains(output, "traceroute") {
		if ctx.Err() != nil {
			return TestResult{
				Name:    "Маршрут (traceroute)",
				Status:  StatusWarning,
				Message: "таймаут traceroute (>30с)",
			}
		}
		return TestResult{
			Name:    "Маршрут (traceroute)",
			Status:  StatusWarning,
			Message: "не удалось выполнить traceroute",
		}
	}

	lines := strings.Split(output, "\n")
	hops := 0
	var details []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if _, err := strconv.Atoi(fields[0]); err == nil {
					hops++
					// Очищаем строку от возможных остатков OEM кодировки
					details = append(details, sanitizeTracertLine(line))
				}
			}
		}
	}

	status := StatusOK
	if hops == 0 {
		status = StatusWarning
	} else if hops > 20 {
		status = StatusWarning
	}

	return TestResult{
		Name:    "Маршрут (traceroute)",
		Status:  status,
		Message: fmt.Sprintf("%d хопов до сервера", hops),
		Details: strings.Join(details, "\n"),
		Latency: elapsed,
	}
}

// sanitizeTracertLine очищает строку tracert от нечитаемых символов OEM кодировки
func sanitizeTracertLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return line
	}

	// Формат хопа: num  t1 ms  t2 ms  t3 ms  ip_or_text
	// Извлекаем номер хопа, тайминги и IP
	hopNum := fields[0]
	var timings []string
	var ip string

	idx := 1
	for t := 0; t < 3 && idx < len(fields); t++ {
		if fields[idx] == "*" {
			timings = append(timings, "    *")
			idx++
		} else {
			// число + "ms"
			val := fields[idx]
			idx++
			if idx < len(fields) && strings.ToLower(fields[idx]) == "ms" {
				timings = append(timings, fmt.Sprintf("%5s ms", val))
				idx++
			} else {
				timings = append(timings, fmt.Sprintf("%5s", val))
			}
		}
	}

	// Ищем IP адрес в оставшихся полях
	for ; idx < len(fields); idx++ {
		if net.ParseIP(fields[idx]) != nil {
			ip = fields[idx]
			break
		}
	}

	// Собираем чистую строку
	result := fmt.Sprintf("%-5s", hopNum)
	for _, t := range timings {
		result += fmt.Sprintf(" %s", t)
	}

	if ip != "" {
		result += "  " + ip
	} else {
		// Все тайминги * — это таймаут
		allStar := true
		for _, t := range timings {
			if !strings.Contains(t, "*") {
				allStar = false
				break
			}
		}
		if allStar {
			result += "  Превышен интервал ожидания для запроса."
		}
	}

	return result
}
