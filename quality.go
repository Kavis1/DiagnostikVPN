package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// QualityMetrics — характеристики качества соединения с VPN-сервером (вне туннеля).
type QualityMetrics struct {
	PacketsSent     int
	PacketsReceived int
	PacketLoss      float64
	RTTMin          time.Duration
	RTTAvg          time.Duration
	RTTMax          time.Duration
	Jitter          time.Duration
	Raw             string
}

// measurePacketLoss делает расширенный ping (20 пакетов) до VPN-сервера и парсит summary.
// Для Windows-ping разбирает обе локализации (en/ru).
func measurePacketLoss(host string) QualityMetrics {
	cmd := exec.Command("ping", pingArgs(20, 2000, false, 0, host)...)
	out, _ := cmd.CombinedOutput()
	output := decodeConsoleOutput(out)

	m := QualityMetrics{
		PacketsSent: 20,
		Raw:         output,
	}

	// Найти sent/received/lost
	// EN: "Packets: Sent = 20, Received = 19, Lost = 1 (5% loss)"
	// RU: "Пакетов: отправлено = 20, получено = 19, потеряно = 1 (5% потерь)"
	reCount := regexp.MustCompile(`(?:Sent|отправлено)\s*=\s*(\d+).*?(?:Received|получено)\s*=\s*(\d+).*?(?:Lost|потеряно)\s*=\s*(\d+)`)
	if mm := reCount.FindStringSubmatch(output); len(mm) == 4 {
		sent, _ := strconv.Atoi(mm[1])
		recv, _ := strconv.Atoi(mm[2])
		lost, _ := strconv.Atoi(mm[3])
		m.PacketsSent = sent
		m.PacketsReceived = recv
		if sent > 0 {
			m.PacketLoss = float64(lost) / float64(sent) * 100
		}
	}

	// RTT: min/avg/max
	// EN: "Minimum = 10ms, Maximum = 25ms, Average = 15ms"
	// RU: "Минимальное = 10мс, Максимальное = 25мс, Среднее = 15мс"
	reRTT := regexp.MustCompile(`(?:Minimum|Минимальное)\s*=\s*(\d+)\s*(?:ms|мс|мсек).*?(?:Maximum|Максимальное)\s*=\s*(\d+)\s*(?:ms|мс|мсек).*?(?:Average|Среднее)\s*=\s*(\d+)\s*(?:ms|мс|мсек)`)
	if mm := reRTT.FindStringSubmatch(output); len(mm) == 4 {
		minR, _ := strconv.Atoi(mm[1])
		maxR, _ := strconv.Atoi(mm[2])
		avgR, _ := strconv.Atoi(mm[3])
		m.RTTMin = time.Duration(minR) * time.Millisecond
		m.RTTMax = time.Duration(maxR) * time.Millisecond
		m.RTTAvg = time.Duration(avgR) * time.Millisecond
		m.Jitter = m.RTTMax - m.RTTMin
	}

	return m
}

// measureBandwidth скачивает 1MB файл через прокси-тоннель и замеряет байт/сек.
// Используем speed.cloudflare.com — единственный публичный CDN-эндпоинт который
// предсказуемо отдаёт ровно сколько просили.
func measureBandwidth(cfg *VPNConfig, sb ProxyBackend) (kBps float64, latency time.Duration, err error) {
	if sb == nil {
		if ok, _ := supportsProxyTest(cfg); !ok {
			return 0, 0, fmt.Errorf("протокол не поддерживает прокси-тест без sing-box")
		}
	}

	host := "speed.cloudflare.com"
	target := "/__down?bytes=1048576" // ровно 1 MiB

	start := time.Now()
	conn, err := dialAnyProxy(cfg, host, 443, sb)
	if err != nil {
		return 0, 0, fmt.Errorf("tunnel: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return 0, time.Since(start), fmt.Errorf("tls: %w", err)
	}
	defer tlsConn.Close()

	req, _ := http.NewRequest("GET", "https://"+host+target, nil)
	req.Header.Set("Host", host)
	req.Header.Set("User-Agent", "Mozilla/5.0 DiagnostikVPN/3.1")
	req.Header.Set("Connection", "close")

	if err := req.Write(tlsConn); err != nil {
		return 0, time.Since(start), err
	}

	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, time.Since(start), fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Считаем байты
	downloadStart := time.Now()
	n, err := io.Copy(io.Discard, resp.Body)
	dlElapsed := time.Since(downloadStart)
	if err != nil && err != io.EOF {
		return 0, time.Since(start), err
	}
	if dlElapsed.Seconds() == 0 {
		return 0, time.Since(start), fmt.Errorf("ноль секунд скачивания")
	}
	kBps = float64(n) / 1024.0 / dlElapsed.Seconds()
	return kBps, time.Since(start), nil
}

// detectExitIP пытается узнать "наш" exit-IP через прокси к ipinfo.io.
// Сравнение exit-IP с реальным IP пользователя = подтверждение что прокси действительно работает.
func detectExitIP(cfg *VPNConfig, sb ProxyBackend) (ip, country string, err error) {
	if sb == nil {
		if ok, _ := supportsProxyTest(cfg); !ok {
			return "", "", fmt.Errorf("прокси-тест недоступен без sing-box для этого протокола")
		}
	}

	host := "ipinfo.io"
	conn, err := dialAnyProxy(cfg, host, 443, sb)
	if err != nil {
		return "", "", fmt.Errorf("tunnel: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return "", "", fmt.Errorf("tls: %w", err)
	}
	defer tlsConn.Close()

	req, _ := http.NewRequest("GET", "https://ipinfo.io/json", nil)
	req.Header.Set("User-Agent", "DiagnostikVPN/3.1")
	req.Header.Set("Connection", "close")

	if err := req.Write(tlsConn); err != nil {
		return "", "", err
	}
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	bodyStr := string(body)

	// JSON-парсинг через regexp — ipinfo простой ответ, тащить encoding/json только для двух полей дорого
	if m := regexp.MustCompile(`"ip"\s*:\s*"([^"]+)"`).FindStringSubmatch(bodyStr); len(m) == 2 {
		ip = m[1]
	}
	if m := regexp.MustCompile(`"country"\s*:\s*"([^"]+)"`).FindStringSubmatch(bodyStr); len(m) == 2 {
		country = m[1]
	}
	return ip, country, nil
}

// detectLocalExitIP — то же самое, но БЕЗ прокси (используется для сравнения).
func detectLocalExitIP() (ip, country string, err error) {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get("https://ipinfo.io/json")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	bodyStr := string(body)
	if m := regexp.MustCompile(`"ip"\s*:\s*"([^"]+)"`).FindStringSubmatch(bodyStr); len(m) == 2 {
		ip = m[1]
	}
	if m := regexp.MustCompile(`"country"\s*:\s*"([^"]+)"`).FindStringSubmatch(bodyStr); len(m) == 2 {
		country = m[1]
	}
	return ip, country, nil
}

// summarizePingForReport — короткая выжимка из QualityMetrics для строки в отчёте.
func summarizePingForReport(m QualityMetrics) string {
	parts := []string{
		fmt.Sprintf("отправлено %d, получено %d", m.PacketsSent, m.PacketsReceived),
		fmt.Sprintf("потери %.1f%%", m.PacketLoss),
	}
	if m.RTTAvg > 0 {
		parts = append(parts, fmt.Sprintf("RTT min/avg/max = %d/%d/%d мс",
			int(m.RTTMin.Milliseconds()), int(m.RTTAvg.Milliseconds()), int(m.RTTMax.Milliseconds())))
	}
	if m.Jitter > 0 {
		parts = append(parts, fmt.Sprintf("jitter %d мс", int(m.Jitter.Milliseconds())))
	}
	return strings.Join(parts, ", ")
}
