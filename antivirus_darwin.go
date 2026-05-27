//go:build darwin

package main

import (
	"fmt"
	"strings"
)

// macOS-аналог антивирусной проверки. На macOS нет WMI/SecurityCenter2,
// и системный антивирусный софт встречается реже. Здесь мы:
//   1) Проверяем список запущенных процессов на известные сторонние AV
//      для macOS (Sophos, Avast, ESET, Bitdefender, Norton, Trend Micro,
//      Malwarebytes for Mac, CrowdStrike Falcon и т.д.)
//   2) Сообщаем о встроенном XProtect (system-default).
//
// В отличие от Windows-версии, тут нет проверки "статус enabled/disabled"
// или "tamper protection" — это всё AV-specific и сложно унифицировать.

var knownAntivirusesMac = map[string]string{
	"sophosscandservice":     "Sophos",
	"sophosagent":            "Sophos",
	"avast.app":              "Avast",
	"avastsetup":             "Avast",
	"esets_daemon":           "ESET",
	"esets_proxy":            "ESET",
	"bdldaemon":              "Bitdefender",
	"bdcoreissues":           "Bitdefender",
	"symdaemon":              "Norton / Symantec",
	"norton.app":             "Norton",
	"iCoreService":           "Trend Micro",
	"icoreservice":           "Trend Micro",
	"rtprotectiondaemon":     "Malwarebytes",
	"malwarebytes":           "Malwarebytes",
	"falcon-sensor":          "CrowdStrike Falcon",
	"falcond":                "CrowdStrike Falcon",
	"sentineld":              "SentinelOne",
	"sentinel agent":         "SentinelOne",
	"kespersky_anti-virus":   "Kaspersky",
	"kavmonitor":             "Kaspersky",
	"clamav":                 "ClamAV",
	"clamd":                  "ClamAV",
	"freshclam":              "ClamAV",
	"webrootsmscli":          "Webroot",
	"wsdaemon":               "Webroot",
}

func runAntivirusChecks(processList string) []TestResult {
	var results []TestResult

	// Запущенные AV
	found := map[string]bool{}
	if processList != "" {
		for proc, name := range knownAntivirusesMac {
			if strings.Contains(processList, strings.ToLower(proc)) {
				found[name] = true
			}
		}
	}
	if len(found) == 0 {
		results = append(results, TestResult{
			Name:    "Антивирусы (процессы)",
			Status:  StatusOK,
			Message: "сторонних AV-процессов не обнаружено",
		})
	} else {
		names := make([]string, 0, len(found))
		for n := range found {
			names = append(names, n)
		}
		results = append(results, TestResult{
			Name:    "Антивирусы (процессы)",
			Status:  StatusWarning,
			Message: fmt.Sprintf("активны %d security-процессов: %s — могут блокировать VPN-трафик",
				len(names), strings.Join(names, ", ")),
			Details: "Если AV делает SSL-инспекцию (Sophos/ESET/Bitdefender — типичные виновники), " +
				"временно отключите модуль 'Web Protection' и попробуйте снова.",
		})
	}

	// XProtect — встроенный
	results = append(results, TestResult{
		Name:    "Антивирусы (установленные)",
		Status:  StatusInfo,
		Message: "XProtect (системный, встроен в macOS) — обычно не мешает VPN",
	})

	return results
}
