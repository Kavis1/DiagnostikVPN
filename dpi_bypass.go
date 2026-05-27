package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// runDPIBypassTests делает Go-нативный аналог zapret/byedpi:
// формирует ClientHello вручную и шлёт его кусками, имитируя split2/fake-стратегию zapret.
// Если стандартный TLS-handshake падал, но фрагментированный проходит — это явный
// признак DPI-блокировки по SNI, и пользователю стоит запускать zapret/winws.
func runDPIBypassTests(cfg *VPNConfig) []TestResult {
	if cfg.Security == "none" || cfg.Security == "" {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Address
	}

	var results []TestResult

	// 1. Контрольный замер — обычный handshake (как делает обычный VPN-клиент).
	normalOK, normalErr, normalLatency := plainTLSProbe(addr, sni)

	// 2. Split-strategy: режем ClientHello на байт-уровне в позиции внутри SNI.
	splitOK, splitErr, splitLatency := fragmentedTLSProbe(addr, sni)

	// 3. TCP-segment fragmentation (PSH+small writes на стороне ОС).
	smallOK, smallErr, smallLatency := writeFragmentedProbe(addr, sni)

	// Анализируем разницу
	switch {
	case normalOK && splitOK && smallOK:
		results = append(results, TestResult{
			Name:    "DPI обход (Go-native)",
			Status:  StatusOK,
			Message: "DPI не обнаружен — TLS-handshake проходит во всех вариантах",
			Details: fmt.Sprintf("normal: %v, fragmented: %v, byte-split: %v",
				normalLatency.Round(time.Millisecond),
				splitLatency.Round(time.Millisecond),
				smallLatency.Round(time.Millisecond)),
		})

	case !normalOK && (splitOK || smallOK):
		// Обычный handshake падает, фрагментированный — проходит. КЛАССИЧЕСКАЯ DPI-БЛОКИРОВКА.
		strategies := []string{}
		if splitOK {
			strategies = append(strategies, "fragmented ClientHello")
		}
		if smallOK {
			strategies = append(strategies, "byte-split write")
		}
		results = append(results, TestResult{
			Name:   "DPI обход (Go-native)",
			Status: StatusWarning,
			Message: "ОБНАРУЖЕНА DPI-БЛОКИРОВКА — стандартный TLS падает, но фрагментированный проходит",
			Details: fmt.Sprintf("Рабочие стратегии: %s\nNormal error: %s\n\n"+
				"=> Установите zapret/winws (https://github.com/bol-van/zapret-win-bundle) "+
				"и запустите с пресетом для вашего ISP. Или используйте VPN-клиент с встроенным "+
				"fragmentation (Hiddify, NekoBox с TLS fragmentation enabled).",
				strings.Join(strategies, ", "), normalErr),
		})

	case !normalOK && !splitOK && !smallOK:
		results = append(results, TestResult{
			Name:    "DPI обход (Go-native)",
			Status:  StatusError,
			Message: "ни одна стратегия не помогла — вероятна IP-блокировка или сервер недоступен",
			Details: fmt.Sprintf("normal: %s\nfragmented: %s\nbyte-split: %s",
				normalErr, splitErr, smallErr),
		})

	default:
		// normalOK == true, фрагментированные упали — это нормально для серверов
		// которые строго проверяют ClientHello (Reality иногда такой).
		results = append(results, TestResult{
			Name:    "DPI обход (Go-native)",
			Status:  StatusOK,
			Message: "обычный handshake работает, DPI не обнаружен",
			Details: fmt.Sprintf("normal: %v", normalLatency.Round(time.Millisecond)),
		})
	}

	return results
}

func plainTLSProbe(addr, sni string) (bool, string, time.Duration) {
	start := time.Now()
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // диагностический — нам важен факт handshake, не валидность серта
		MinVersion:         tls.VersionTLS12,
	})
	elapsed := time.Since(start)
	if err != nil {
		return false, err.Error(), elapsed
	}
	conn.Close()
	return true, "", elapsed
}

// fragmentedTLSProbe пишет ClientHello, побайтово разорванный в позиции SNI.
// Это классическая техника zapret "split2".
func fragmentedTLSProbe(addr, sni string) (bool, string, time.Duration) {
	start := time.Now()

	rawConn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return false, err.Error(), time.Since(start)
	}
	defer rawConn.Close()

	rawConn.SetDeadline(time.Now().Add(10 * time.Second))

	hello, err := buildClientHello(sni)
	if err != nil {
		return false, "build error: " + err.Error(), time.Since(start)
	}

	// Найдём позицию SNI в hello — разорвём прямо посередине его длины
	splitAt := len(hello) / 2
	if sniPos := findSNIPos(hello, sni); sniPos > 0 {
		// Режем посреди значения SNI
		splitAt = sniPos + len(sni)/2
	}

	if _, err := rawConn.Write(hello[:splitAt]); err != nil {
		return false, "write1: " + err.Error(), time.Since(start)
	}
	// Маленькая задержка чтобы пакеты ушли в отдельных сегментах
	time.Sleep(40 * time.Millisecond)
	if _, err := rawConn.Write(hello[splitAt:]); err != nil {
		return false, "write2: " + err.Error(), time.Since(start)
	}

	// Ждём ServerHello (TLS record type 0x16 = handshake)
	header := make([]byte, 5)
	if _, err := io.ReadFull(rawConn, header); err != nil {
		return false, "read header: " + err.Error(), time.Since(start)
	}
	if header[0] != 0x16 {
		return false, fmt.Sprintf("invalid record type: 0x%02x", header[0]), time.Since(start)
	}
	return true, "", time.Since(start)
}

// writeFragmentedProbe шлёт ClientHello очень маленькими TCP-сегментами (по 4 байта).
// Это другая популярная стратегия для тупых DPI которые ищут SNI в одном сегменте.
func writeFragmentedProbe(addr, sni string) (bool, string, time.Duration) {
	start := time.Now()

	rawConn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return false, err.Error(), time.Since(start)
	}
	defer rawConn.Close()

	rawConn.SetDeadline(time.Now().Add(10 * time.Second))

	hello, err := buildClientHello(sni)
	if err != nil {
		return false, err.Error(), time.Since(start)
	}

	// Пишем по 4 байта с микро-задержкой
	chunk := 4
	for i := 0; i < len(hello); i += chunk {
		end := i + chunk
		if end > len(hello) {
			end = len(hello)
		}
		if _, err := rawConn.Write(hello[i:end]); err != nil {
			return false, "write: " + err.Error(), time.Since(start)
		}
		time.Sleep(2 * time.Millisecond)
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(rawConn, header); err != nil {
		return false, "read: " + err.Error(), time.Since(start)
	}
	if header[0] != 0x16 {
		return false, fmt.Sprintf("invalid record type: 0x%02x", header[0]), time.Since(start)
	}
	return true, "", time.Since(start)
}

// buildClientHello собирает минимальный валидный TLS 1.2/1.3 ClientHello с SNI.
// Используем стандартную Go tls библиотеку для генерации, перехватив запись.
func buildClientHello(sni string) ([]byte, error) {
	// Используем "обманку" — настоящий tls.Conn, но через pipe.
	// Намного проще чем собирать ClientHello руками.
	clientPipe, serverPipe := net.Pipe()
	defer serverPipe.Close()

	captured := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := serverPipe.Read(buf)
		captured <- buf[:n]
		// Закроем чтобы клиент получил EOF и tls.Handshake завершился
		serverPipe.Close()
	}()

	tlsClient := tls.Client(clientPipe, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})

	done := make(chan struct{})
	go func() {
		_ = tlsClient.Handshake()
		clientPipe.Close()
		close(done)
	}()

	var hello []byte
	select {
	case hello = <-captured:
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("таймаут генерации ClientHello")
	}
	<-done

	if len(hello) < 10 {
		return nil, fmt.Errorf("слишком короткий ClientHello: %d байт", len(hello))
	}
	// Проверяем что это TLS handshake record
	if hello[0] != 0x16 {
		return nil, fmt.Errorf("не TLS record: 0x%02x", hello[0])
	}
	// Длина record (байты 3-4)
	recLen := int(binary.BigEndian.Uint16(hello[3:5]))
	full := 5 + recLen
	if len(hello) < full {
		// Дочитываем если capture поймал не всё (маловероятно для ClientHello)
		return hello, nil
	}
	return hello[:full], nil
}

// findSNIPos ищет байтовое смещение значения SNI внутри уже собранного ClientHello.
func findSNIPos(hello []byte, sni string) int {
	sniBytes := []byte(sni)
	return bytesIndex(hello, sniBytes)
}

func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// Чтобы избежать неиспользуемого rand'a — простая утилита для проб
func unusedRandomByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}
