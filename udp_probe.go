package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// probeUDPPort пытается определить — доступен ли UDP-порт.
// Так как UDP без ответа от приложения по-умолчанию не подтверждает доступ,
// мы используем эвристику:
//   - Если ICMP unreachable приходит → порт закрыт.
//   - Если приходит data → порт открыт и приложение ответило.
//   - Если ничего → "open|filtered" (нельзя различить без активного сервиса).
//
// Для UDP-протоколов вроде Hysteria2/WG/QUIC возвращаем "open|filtered" — это
// самый лучший результат который можно получить без знания протокола.
func probeUDPPort(host string, port int) TestResult {
	addr := fmt.Sprintf("%s:%d", host, port)

	start := time.Now()

	// Резолвим хост сами (UDP без DNS-зависимости)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return TestResult{
			Name:    fmt.Sprintf("UDP %d", port),
			Status:  StatusInfo,
			Message: fmt.Sprintf("не удалось разрешить адрес: %v", err),
		}
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return TestResult{
			Name:    fmt.Sprintf("UDP %d", port),
			Status:  StatusInfo,
			Message: fmt.Sprintf("не удалось создать UDP сокет: %v", err),
		}
	}
	defer conn.Close()

	// Шлём небольшой пакет — он не нанесёт вреда, многие сервисы его проигнорируют
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, werr := conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
	if werr != nil {
		return TestResult{
			Name:    fmt.Sprintf("UDP %d", port),
			Status:  StatusInfo,
			Message: fmt.Sprintf("ошибка отправки: %v", werr),
			Latency: time.Since(start),
		}
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, _, rerr := conn.ReadFromUDP(buf)
	elapsed := time.Since(start)

	if rerr != nil {
		// "i/o timeout" — нет ответа, скорее всего фильтр или сервис игнорирует
		// "refused"/"unreachable" — точно закрыт (ICMP Port Unreachable)
		errStr := rerr.Error()
		if strings.Contains(errStr, "refused") || strings.Contains(errStr, "unreachable") {
			return TestResult{
				Name:    fmt.Sprintf("UDP %d", port),
				Status:  StatusError,
				Message: "порт закрыт (ICMP Port Unreachable)",
				Latency: elapsed,
			}
		}
		// Таймаут — open|filtered
		return TestResult{
			Name:    fmt.Sprintf("UDP %d", port),
			Status:  StatusInfo,
			Message: "open|filtered — приложение не ответило (норма для большинства UDP VPN)",
			Latency: elapsed,
		}
	}

	return TestResult{
		Name:    fmt.Sprintf("UDP %d", port),
		Status:  StatusOK,
		Message: fmt.Sprintf("получен ответ от UDP-сервиса (%d байт)", n),
		Latency: elapsed,
	}
}
