package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

func runVPNTests(cfg *VPNConfig) []TestResult {
	var results []TestResult

	switch cfg.Protocol {
	case "vless":
		results = append(results, testVLESSConnection(cfg))
	case "vmess":
		results = append(results, testVMessConnection(cfg))
	case "trojan":
		results = append(results, testTrojanConnection(cfg))
	case "shadowsocks":
		results = append(results, testShadowsocksConnection(cfg))
	}

	results = append(results, testConnectionStability(cfg))

	return results
}

func getTLSConn(cfg *VPNConfig) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)

	if cfg.Security == "tls" || cfg.Security == "reality" {
		sni := cfg.SNI
		if sni == "" {
			sni = cfg.Address
		}

		tlsConfig := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}

		if cfg.ALPN != "" {
			tlsConfig.NextProtos = strings.Split(cfg.ALPN, ",")
		}

		dialer := &net.Dialer{Timeout: 10 * time.Second}
		return tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	}

	return net.DialTimeout("tcp", addr, 10*time.Second)
}

func testVLESSConnection(cfg *VPNConfig) TestResult {
	// Для non-TCP транспортов (xhttp, ws, grpc) и Vision flow прямой тест VLESS v0 невозможен:
	// - non-TCP: протокол обёрнут в транспортный слой (HTTP/2, WebSocket, gRPC)
	// - Vision (xtls-rprx-vision): сервер ожидает специальную TLS-обработку,
	//   raw VLESS handshake будет отклонён (connection forcibly closed)
	// Проверяем только TLS/TCP подключение.
	if (cfg.Transport != "tcp" && cfg.Transport != "") || cfg.Flow == "xtls-rprx-vision" {
		start := time.Now()
		conn, err := getTLSConn(cfg)
		elapsed := time.Since(start)
		if err != nil {
			return TestResult{
				Name:    "VLESS подключение",
				Status:  StatusError,
				Message: fmt.Sprintf("не удалось установить соединение: %v", err),
				Latency: elapsed,
			}
		}
		conn.Close()
		return TestResult{
			Name:    "VLESS подключение",
			Status:  StatusOK,
			Message: "соединение успешно",
			Latency: elapsed,
		}
	}

	start := time.Now()
	conn, err := getTLSConn(cfg)
	if err != nil {
		return TestResult{
			Name:    "VLESS подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("не удалось установить соединение: %v", err),
			Latency: time.Since(start),
		}
	}
	defer conn.Close()

	// Build VLESS v0 request header:
	// Version(1) + UUID(16) + AddonLen(1) [+ Addon] + Command(1) + Port(2) + AddrType(1) + Addr
	uuid, err := parseUUID(cfg.UUID)
	if err != nil {
		return TestResult{
			Name:    "VLESS подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("неверный UUID: %v", err),
			Latency: time.Since(start),
		}
	}

	targetDomain := "www.google.com"
	targetPort := uint16(80)

	var header []byte
	header = append(header, 0) // version 0
	header = append(header, uuid[:]...)

	// Addons (flow support)
	if cfg.Flow != "" {
		flowBytes := []byte(cfg.Flow)
		addonBuf := []byte{0x0a, byte(len(flowBytes))}
		addonBuf = append(addonBuf, flowBytes...)
		header = append(header, byte(len(addonBuf)))
		header = append(header, addonBuf...)
	} else {
		header = append(header, 0) // no addons
	}

	header = append(header, 0x01) // command: TCP connect

	// Port (big endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, targetPort)
	header = append(header, portBuf...)

	// Address type: 2 = domain
	header = append(header, 0x02)
	header = append(header, byte(len(targetDomain)))
	header = append(header, []byte(targetDomain)...)

	// Payload: HTTP request to test proxy
	httpReq := []byte("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n")
	header = append(header, httpReq...)

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(header)
	if err != nil {
		return TestResult{
			Name:    "VLESS подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("ошибка отправки VLESS запроса: %v", err),
			Latency: time.Since(start),
		}
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	elapsed := time.Since(start)

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "timeout") {
			return TestResult{
				Name:    "VLESS подключение",
				Status:  StatusError,
				Message: "таймаут ответа VLESS сервера (возможно неверный UUID или блокировка)",
				Latency: elapsed,
			}
		}
		return TestResult{
			Name:    "VLESS подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("ошибка чтения ответа VLESS: %v", err),
			Latency: elapsed,
		}
	}

	if n < 2 {
		return TestResult{
			Name:    "VLESS подключение",
			Status:  StatusError,
			Message: "получен слишком короткий ответ от сервера",
			Latency: elapsed,
		}
	}

	// VLESS response: Version(1) + AddonLen(1) + Addon + Payload
	if resp[0] == 0 {
		addonLen := int(resp[1])
		payloadStart := 2 + addonLen
		if payloadStart < n {
			payload := string(resp[payloadStart:n])
			if strings.Contains(payload, "HTTP/") {
				return TestResult{
					Name:    "VLESS подключение",
					Status:  StatusOK,
					Message: "успешно — VLESS аутентификация пройдена, прокси работает",
					Latency: elapsed,
				}
			}
		}
		return TestResult{
			Name:    "VLESS подключение",
			Status:  StatusOK,
			Message: "VLESS handshake успешен (ответ сервера получен)",
			Latency: elapsed,
		}
	}

	// 0x48 = 'H' — сервер вернул HTTP ответ напрямую (xtls-rprx-vision / Reality)
	// Это значит прокси работает корректно
	if n > 4 && strings.HasPrefix(string(resp[:n]), "HTTP/") {
		return TestResult{
			Name:    "VLESS подключение",
			Status:  StatusOK,
			Message: "успешно — прокси работает (HTTP ответ получен через VLESS)",
			Latency: elapsed,
		}
	}

	return TestResult{
		Name:    "VLESS подключение",
		Status:  StatusOK,
		Message: fmt.Sprintf("ответ сервера получен (%d байт)", n),
		Latency: elapsed,
	}
}

func testVMessConnection(cfg *VPNConfig) TestResult {
	// VMess has complex encryption handshake, test TLS + TCP connectivity
	start := time.Now()
	conn, err := getTLSConn(cfg)
	elapsed := time.Since(start)

	if err != nil {
		return TestResult{
			Name:    "VMess подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("не удалось установить соединение: %v", err),
			Latency: elapsed,
		}
	}
	conn.Close()

	return TestResult{
		Name:    "VMess подключение",
		Status:  StatusOK,
		Message: "TLS/TCP соединение успешно (полный VMess handshake требует клиента)",
		Latency: elapsed,
	}
}

func testTrojanConnection(cfg *VPNConfig) TestResult {
	// Для non-TCP транспортов (grpc, ws) прямой тест Trojan невозможен —
	// протокол обёрнут в транспортный слой (HTTP/2, WebSocket).
	if cfg.Transport != "tcp" && cfg.Transport != "" {
		start := time.Now()
		conn, err := getTLSConn(cfg)
		elapsed := time.Since(start)
		if err != nil {
			return TestResult{
				Name:    "Trojan подключение",
				Status:  StatusError,
				Message: fmt.Sprintf("не удалось установить соединение: %v", err),
				Latency: elapsed,
			}
		}
		conn.Close()
		return TestResult{
			Name:    "Trojan подключение",
			Status:  StatusOK,
			Message: "соединение успешно",
			Latency: elapsed,
		}
	}

	start := time.Now()
	conn, err := getTLSConn(cfg)
	if err != nil {
		return TestResult{
			Name:    "Trojan подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("не удалось установить соединение: %v", err),
			Latency: time.Since(start),
		}
	}
	defer conn.Close()

	// Trojan auth: SHA224(password) hex + CRLF + command + ATYP + addr + port + CRLF
	hash := sha256.Sum224([]byte(cfg.Password))
	hexHash := hex.EncodeToString(hash[:])

	targetDomain := "www.google.com"
	targetPort := uint16(80)

	var header []byte
	header = append(header, []byte(hexHash)...) // 56 bytes hex
	header = append(header, 0x0d, 0x0a)         // CRLF
	header = append(header, 0x01)                // command: CONNECT
	header = append(header, 0x03)                // ATYP: domain
	header = append(header, byte(len(targetDomain)))
	header = append(header, []byte(targetDomain)...)

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, targetPort)
	header = append(header, portBuf...)
	header = append(header, 0x0d, 0x0a) // CRLF

	// HTTP request as payload
	httpReq := []byte("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n")
	header = append(header, httpReq...)

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(header)
	if err != nil {
		return TestResult{
			Name:    "Trojan подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("ошибка отправки Trojan запроса: %v", err),
			Latency: time.Since(start),
		}
	}

	// Trojan doesn't send response header - it proxies directly
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	elapsed := time.Since(start)

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "timeout") {
			return TestResult{
				Name:    "Trojan подключение",
				Status:  StatusError,
				Message: "таймаут ответа Trojan сервера (возможно неверный пароль или блокировка)",
				Latency: elapsed,
			}
		}
		return TestResult{
			Name:    "Trojan подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("ошибка чтения ответа: %v", err),
			Latency: elapsed,
		}
	}

	if strings.Contains(string(resp[:n]), "HTTP/") {
		return TestResult{
			Name:    "Trojan подключение",
			Status:  StatusOK,
			Message: "успешно — Trojan аутентификация пройдена, прокси работает",
			Latency: elapsed,
		}
	}

	// Сервер ответил данными — соединение установлено
	if n > 0 {
		return TestResult{
			Name:    "Trojan подключение",
			Status:  StatusOK,
			Message: fmt.Sprintf("соединение установлено, ответ сервера получен (%d байт)", n),
			Latency: elapsed,
		}
	}

	return TestResult{
		Name:    "Trojan подключение",
		Status:  StatusWarning,
		Message: "пустой ответ от сервера",
		Latency: elapsed,
	}
}

func testShadowsocksConnection(cfg *VPNConfig) TestResult {
	// Shadowsocks requires AEAD cipher implementation for full test
	// We test TCP connectivity only
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		return TestResult{
			Name:    "Shadowsocks подключение",
			Status:  StatusError,
			Message: fmt.Sprintf("не удалось подключиться: %v", err),
			Latency: elapsed,
		}
	}
	conn.Close()

	details := fmt.Sprintf("Метод: %s", cfg.Method)
	if strings.Contains(cfg.Method, "2022") {
		details += " (Shadowsocks 2022)"
	}

	return TestResult{
		Name:    "Shadowsocks подключение",
		Status:  StatusOK,
		Message: "соединение успешно",
		Details: details,
		Latency: elapsed,
	}
}

func testConnectionStability(cfg *VPNConfig) TestResult {
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)

	successes := 0
	totalTime := time.Duration(0)
	attempts := 5

	for i := 0; i < attempts; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		elapsed := time.Since(start)

		if err == nil {
			successes++
			totalTime += elapsed
			conn.Close()
		}

		// Small delay between attempts
		if i < attempts-1 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	if successes == 0 {
		return TestResult{
			Name:    "Стабильность соединения",
			Status:  StatusError,
			Message: fmt.Sprintf("0 из %d попыток подключения успешны", attempts),
		}
	}

	avgTime := totalTime / time.Duration(successes)

	status := StatusOK
	msg := fmt.Sprintf("%d из %d подключений успешны, среднее время: %s",
		successes, attempts, avgTime.Round(time.Millisecond))

	if successes < attempts {
		status = StatusWarning
		msg += " (нестабильное соединение)"
	}

	return TestResult{
		Name:    "Стабильность соединения",
		Status:  status,
		Message: msg,
		Latency: avgTime,
	}
}

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return uuid, fmt.Errorf("неверная длина UUID: %d (ожидается 32 hex символа)", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return uuid, fmt.Errorf("неверные символы в UUID: %w", err)
	}
	copy(uuid[:], b)
	return uuid, nil
}
