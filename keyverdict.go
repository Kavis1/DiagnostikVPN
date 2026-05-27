package main

import (
	"fmt"
	"strings"
	"time"
)

// runKeyTests запускает полный набор тестов для ОДНОГО ключа:
//   1. Пытается поднять sing-box (поддерживает все протоколы/транспорты)
//   2. Если sing-box не доступен — fallback на Go-native dialer (VLESS/Trojan TCP)
//   3. packet loss / RTT (extended ping)
//   4. exit IP detection через прокси
//   5. список сайтов через прокси
//   6. bandwidth measurement
//   7. формирует verdict
func runKeyTests(cfg *VPNConfig, localIP, localCountry string) (KeyVerdict, []TestResult) {
	v := KeyVerdict{
		ConfigName: cfg.Remark,
		ServerAddr: fmt.Sprintf("%s:%d", cfg.Address, cfg.Port),
		SitesTotal: len(CommonSites),
	}
	if v.ConfigName == "" {
		v.ConfigName = v.ServerAddr
	}

	var results []TestResult

	// 1. Поднимаем правильный backend под cfg (sing-box или xray-core)
	var sb ProxyBackend
	sb, sbErr := newProxyBackend(cfg)
	if sb != nil {
		defer sb.Stop()
		results = append(results, TestResult{
			Name:    fmt.Sprintf("Прокси-тест [%s]", v.ConfigName),
			Status:  StatusInfo,
			Message: fmt.Sprintf("поднят %s SOCKS5 на %s", sb.BackendName(), sb.SocksAddr()),
		})
	} else {
		// Fallback на Go-native — только для VLESS/Trojan TCP без Vision/Reality
		supports, note := supportsProxyTest(cfg)
		if !supports {
			v.Verdict = "PROXY_UNSUPPORTED"
			v.Recommendation = note + ". Backend не запустился: " + sbErr.Error() +
				". Используйте флаги -download-singbox / -download-xray."
			results = append(results, TestResult{
				Name:    fmt.Sprintf("Прокси-тест [%s]", v.ConfigName),
				Status:  StatusWarning,
				Message: "backend недоступен И Go-native fallback не поддерживает " + cfg.Protocol + "/" + cfg.Transport,
				Details: sbErr.Error(),
			})
			return v, results
		}
		results = append(results, TestResult{
			Name:    fmt.Sprintf("Прокси-тест [%s]", v.ConfigName),
			Status:  StatusWarning,
			Message: "backend (sing-box/xray) недоступен — fallback на Go-native (точность ниже)",
			Details: sbErr.Error(),
		})
	}

	// 2. Packet loss / RTT
	q := measurePacketLoss(cfg.Address)
	v.PacketLoss = q.PacketLoss
	v.AvgPing = q.RTTAvg

	pingStatus := StatusOK
	switch {
	case q.PacketLoss >= 30:
		pingStatus = StatusError
	case q.PacketLoss >= 5 || q.RTTAvg > 300*time.Millisecond:
		pingStatus = StatusWarning
	}
	results = append(results, TestResult{
		Name:    fmt.Sprintf("Качество канала [%s]", v.ConfigName),
		Status:  pingStatus,
		Message: summarizePingForReport(q),
	})

	// 3. Exit IP
	ip, country, ipErr := detectExitIP(cfg, sb)
	if ipErr == nil && ip != "" {
		v.ExitIP = ip
		v.ExitCountry = country
		egress := StatusOK
		msg := fmt.Sprintf("exit IP: %s (%s)", ip, country)
		if ip == localIP {
			egress = StatusError
			msg = fmt.Sprintf("ВНИМАНИЕ: exit IP %s СОВПАДАЕТ с локальным — туннель не работает / leak", ip)
		}
		results = append(results, TestResult{
			Name:    fmt.Sprintf("Egress IP [%s]", v.ConfigName),
			Status:  egress,
			Message: msg,
		})
	} else if ipErr != nil {
		results = append(results, TestResult{
			Name:    fmt.Sprintf("Egress IP [%s]", v.ConfigName),
			Status:  StatusError,
			Message: "не удалось определить exit IP — туннель скорее всего не поднимается",
			Details: "Причина: " + ipErr.Error(),
		})
	}

	// 4. Сайты
	siteResults := testKeyAgainstSites(cfg, CommonSites, sb)
	v.SiteResults = siteResults
	var totalLatency time.Duration
	for _, sr := range siteResults {
		if sr.Reachable {
			v.SitesPassed++
			totalLatency += sr.Latency
		}
		status := StatusError
		msg := "недоступен"
		if sr.Reachable {
			status = StatusOK
			msg = fmt.Sprintf("HTTP %d, %s, %d байт",
				sr.StatusCode, sr.Latency.Round(time.Millisecond), sr.BodySize)
		} else if sr.StatusCode > 0 {
			msg = fmt.Sprintf("HTTP %d (не ОК)", sr.StatusCode)
		}
		if sr.Error != "" {
			msg += " — " + sr.Error
		}
		results = append(results, TestResult{
			Name:    fmt.Sprintf("Сайт %s [%s]", sr.Site, v.ConfigName),
			Status:  status,
			Message: msg,
			Latency: sr.Latency,
		})
	}
	if v.SitesPassed > 0 {
		v.AvgLatency = totalLatency / time.Duration(v.SitesPassed)
	}

	// 5. Bandwidth
	bw, _, bwErr := measureBandwidth(cfg, sb)
	v.BandwidthKBps = bw
	if bwErr != nil {
		results = append(results, TestResult{
			Name:    fmt.Sprintf("Bandwidth [%s]", v.ConfigName),
			Status:  StatusWarning,
			Message: "не удалось замерить: " + bwErr.Error(),
		})
	} else {
		bwStatus := StatusOK
		if bw < 200 {
			bwStatus = StatusWarning
		}
		results = append(results, TestResult{
			Name:    fmt.Sprintf("Bandwidth [%s]", v.ConfigName),
			Status:  bwStatus,
			Message: fmt.Sprintf("%.0f KB/s (%.2f Mbps) — 1 MiB через speed.cloudflare.com",
				bw, bw*8/1024),
		})
	}

	// 6. Verdict
	v.Verdict, v.Recommendation = computeVerdict(v, q, ipErr != nil)
	results = append(results, TestResult{
		Name:    fmt.Sprintf("ИТОГ [%s]", v.ConfigName),
		Status:  verdictToStatus(v.Verdict),
		Message: v.Verdict + " — " + v.Recommendation,
		Details: formatVerdictDetails(v),
	})

	return v, results
}

func computeVerdict(v KeyVerdict, q QualityMetrics, exitErr bool) (string, string) {
	pct := 0
	if v.SitesTotal > 0 {
		pct = v.SitesPassed * 100 / v.SitesTotal
	}

	// Высокий ICMP-loss НЕ должен понижать вердикт если все сайты открываются и BW нормальная.
	// Большинство VPN-серверов специально режут ICMP/пинг чтобы спрятаться от сканеров.
	icmpLossButTCPok := v.PacketLoss > 5 && pct == 100 && v.BandwidthKBps > 500

	switch {
	case exitErr && v.SitesPassed == 0:
		return "FAIL",
			"туннель не работает совсем. Проверьте: 1) правильность ключа, " +
				"2) есть ли блокировки провайдера, 3) попробуйте включить zapret/WARP."

	case icmpLossButTCPok:
		return "OK",
			fmt.Sprintf("ключ работает — все %d сайтов открываются, BW %.0f KB/s. "+
				"ICMP-loss %.0f%% — провайдер VPN-сервера режет пинг (норма), на TCP-трафик не влияет.",
				v.SitesTotal, v.BandwidthKBps, v.PacketLoss)

	case pct == 100 && v.PacketLoss < 1 && v.AvgPing < 200*time.Millisecond:
		return "EXCELLENT",
			fmt.Sprintf("ключ работает отлично — все %d сайтов, потери %.1f%%, RTT %dмс, BW %.0f KB/s",
				v.SitesTotal, v.PacketLoss, int(v.AvgPing.Milliseconds()), v.BandwidthKBps)

	case pct == 100 && v.PacketLoss < 5:
		return "OK",
			fmt.Sprintf("все %d сайтов открываются, лёгкие потери %.1f%% — допустимо, BW %.0f KB/s",
				v.SitesTotal, v.PacketLoss, v.BandwidthKBps)

	case pct >= 60:
		failed := []string{}
		for _, sr := range v.SiteResults {
			if !sr.Reachable {
				failed = append(failed, sr.Site)
			}
		}
		return "PARTIAL",
			fmt.Sprintf("%d/%d сайтов открывается. НЕ открылись: %s. "+
				"Часто причина — TLS-fingerprint или геоблок на стороне сайта. "+
				"Попробуйте другой выходной IP или включите zapret.",
				v.SitesPassed, v.SitesTotal, strings.Join(failed, ", "))

	case pct > 0:
		return "POOR",
			fmt.Sprintf("открывается только %d/%d. Сильное вмешательство DPI. "+
				"РЕКОМЕНДУЕТСЯ: 1) включить zapret/winws, 2) включить WARP перед VPN, "+
				"3) сменить сервер выхода.",
				v.SitesPassed, v.SitesTotal)

	default:
		if q.PacketLoss > 50 {
			return "FAIL",
				fmt.Sprintf("сайты не открываются + потери пакетов %.0f%%. "+
					"Скорее всего IP-блокировка сервера провайдером.",
					q.PacketLoss)
		}
		return "FAIL",
			"туннель устанавливается, но сайты не открываются. " +
				"Похоже на DPI-фильтр TLS внутри ключа. Включите zapret/winws."
	}
}

func verdictToStatus(verdict string) TestStatus {
	switch verdict {
	case "EXCELLENT", "OK":
		return StatusOK
	case "PARTIAL", "POOR":
		return StatusWarning
	case "FAIL", "PROXY_UNSUPPORTED":
		return StatusError
	default:
		return StatusInfo
	}
}

func formatVerdictDetails(v KeyVerdict) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("Сервер: %s", v.ServerAddr))
	if v.ExitIP != "" {
		lines = append(lines, fmt.Sprintf("Exit IP: %s (%s)", v.ExitIP, v.ExitCountry))
	}
	lines = append(lines, fmt.Sprintf("Сайты: %d/%d открываются", v.SitesPassed, v.SitesTotal))
	if v.AvgLatency > 0 {
		lines = append(lines, fmt.Sprintf("Средний latency открытия сайтов: %s", v.AvgLatency.Round(time.Millisecond)))
	}
	lines = append(lines, fmt.Sprintf("Ping: avg %dмс, потери %.1f%%",
		int(v.AvgPing.Milliseconds()), v.PacketLoss))
	if v.BandwidthKBps > 0 {
		lines = append(lines, fmt.Sprintf("Bandwidth: %.0f KB/s (%.2f Mbps)",
			v.BandwidthKBps, v.BandwidthKBps*8/1024))
	}
	lines = append(lines, "")
	lines = append(lines, "Результаты по сайтам:")
	for _, sr := range v.SiteResults {
		icon := "[XX]"
		if sr.Reachable {
			icon = "[OK]"
		}
		line := fmt.Sprintf("  %s %s", icon, sr.Site)
		if sr.Reachable {
			line += fmt.Sprintf(" — HTTP %d, %s", sr.StatusCode, sr.Latency.Round(time.Millisecond))
		} else if sr.Error != "" {
			line += fmt.Sprintf(" — %s", sr.Error)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// formatAllVerdictsTable собирает все verdict'ы в одну удобную таблицу для отчёта.
func formatAllVerdictsTable(verdicts []KeyVerdict) string {
	if len(verdicts) == 0 {
		return "(нет данных)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-30s %-8s %-7s %-9s %-9s %-9s\n",
		"Ключ", "Verdict", "Sites", "Loss", "RTT", "BW")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 80))
	for _, v := range verdicts {
		name := v.ConfigName
		if len(name) > 28 {
			name = name[:25] + "..."
		}
		bw := "—"
		if v.BandwidthKBps > 0 {
			bw = fmt.Sprintf("%.0fKB/s", v.BandwidthKBps)
		}
		fmt.Fprintf(&b, "%-30s %-8s %d/%d    %5.1f%%   %5dмс   %s\n",
			name, v.Verdict,
			v.SitesPassed, v.SitesTotal,
			v.PacketLoss,
			int(v.AvgPing.Milliseconds()),
			bw)
	}
	return b.String()
}
