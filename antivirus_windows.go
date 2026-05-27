//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// Известные антивирусы и security suite — процессы и человеко-читаемые названия.
// Многие из них активно блокируют/режут VPN-трафик (особенно при анализе TLS).
var knownAntiviruses = map[string]string{
	// Российские
	"avp.exe":                "Kaspersky",
	"avpui.exe":              "Kaspersky",
	"kavfs.exe":              "Kaspersky",
	"kavfswp.exe":            "Kaspersky",
	"kavfswh.exe":            "Kaspersky",
	"ksde.exe":               "Kaspersky Endpoint",
	"ksdeui.exe":             "Kaspersky Endpoint",
	"klnagent.exe":           "Kaspersky Network Agent",
	"klwtblfs.exe":           "Kaspersky",
	"dr_web32.exe":           "Dr.Web",
	"drweb32.exe":            "Dr.Web",
	"drwebcom.exe":           "Dr.Web",
	"spidergate.exe":         "Dr.Web SpIDer Gate",
	"drwebupw.exe":           "Dr.Web Updater",

	// Международные
	"msmpeng.exe":            "Windows Defender (MsMpEng)",
	"mssense.exe":            "Microsoft Defender ATP",
	"smartscreen.exe":        "Windows SmartScreen",
	"avgnt.exe":              "Avira",
	"avguard.exe":            "Avira",
	"avastsvc.exe":           "Avast",
	"avastui.exe":            "Avast",
	"afwserv.exe":            "Avast Firewall",
	"avgsvc.exe":             "AVG",
	"avgui.exe":              "AVG",
	"avgnt.exe ":             "Avira AntiVir",
	"bdagent.exe":            "Bitdefender",
	"vsserv.exe":             "Bitdefender",
	"bdservicehost.exe":      "Bitdefender",
	"epdrsvc.exe":            "Bitdefender EDR",
	"egui.exe":               "ESET NOD32",
	"ekrn.exe":               "ESET kernel",
	"ecls.exe":               "ESET",
	"mcshield.exe":           "McAfee",
	"mcafee.exe":             "McAfee",
	"masvc.exe":              "McAfee Agent",
	"mfemms.exe":             "McAfee",
	"ns.exe":                 "Norton",
	"nortonsecurity.exe":     "Norton",
	"ccsvchst.exe":           "Norton/Symantec",
	"rtvscan.exe":            "Symantec",
	"smc.exe":                "Symantec Endpoint",
	"smcgui.exe":             "Symantec Endpoint",
	"f-secure.exe":           "F-Secure",
	"fsav32.exe":             "F-Secure",
	"fsdfwd.exe":             "F-Secure",
	"sophosui.exe":           "Sophos",
	"sophoshealth.exe":       "Sophos",
	"sed.exe":                "Sophos EDR",
	"sava.exe":               "Sophos",
	"savservice.exe":         "Sophos",
	"trendmicro.exe":         "Trend Micro",
	"tmlisten.exe":           "Trend Micro",
	"tmproxy.exe":            "Trend Micro Proxy",
	"officeclickToRun.exe":   "Trend Micro Office Scan",
	"360tray.exe":            "360 Total Security",
	"360safe.exe":            "360 Total Security",
	"qhsafetray.exe":         "QQ PC Manager",
	"qhwatchdog.exe":         "QQ PC Manager",
	"comodo.exe":             "Comodo",
	"cmdagent.exe":           "Comodo Agent",
	"cis.exe":                "Comodo Internet Security",
	"malwarebytes.exe":       "Malwarebytes",
	"mbamservice.exe":        "Malwarebytes",
	"mbamtray.exe":           "Malwarebytes",
	"webroot.exe":            "Webroot",
	"wrsa.exe":               "Webroot",
	"crowdstrike.exe":        "CrowdStrike",
	"csagent.exe":            "CrowdStrike",
	"csfalconservice.exe":    "CrowdStrike Falcon",
	"sentinelagent.exe":      "SentinelOne",
	"sentinelone.exe":        "SentinelOne",
	"cylance.exe":            "Cylance",
	"cylancesvc.exe":         "Cylance",
	"emsisoftgui.exe":        "Emsisoft",
	"a2service.exe":          "Emsisoft",

	// Прокси/инспекция трафика (MITM)
	"fiddler.exe":            "Fiddler (HTTP proxy)",
	"charles.exe":            "Charles Proxy",
	"burpsuite.exe":          "Burp Suite",
	"wireshark.exe":          "Wireshark (sniffer)",
	"clumsy.exe":             "Clumsy (packet manipulation)",
}

// runAntivirusChecks выполняет проверки установленных антивирусов и связанных служб.
func runAntivirusChecks(processList string) []TestResult {
	var results []TestResult

	results = append(results, checkInstalledAntivirus())
	results = append(results, checkRunningAntivirus(processList))
	results = append(results, checkDefenderTamperProtection())

	return results
}

// checkInstalledAntivirus читает список AV из SecurityCenter2 (WMI).
func checkInstalledAntivirus() TestResult {
	// PowerShell-запрос к SecurityCenter2 — это canonical способ.
	psCmd := `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ` +
		`ForEach-Object { ` +
		`  $state = [Convert]::ToString($_.productState, 16).PadLeft(6, '0'); ` +
		`  $en = $state.Substring(2,2); ` +
		`  $up = $state.Substring(4,2); ` +
		`  $enabled = if ($en -eq '10' -or $en -eq '11') { 'enabled' } else { 'disabled' }; ` +
		`  $uptodate = if ($up -eq '00') { 'up-to-date' } else { 'outdated' }; ` +
		`  '{0}|{1}|{2}' -f $_.displayName, $enabled, $uptodate ` +
		`}`

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	if err != nil {
		return TestResult{
			Name:    "Антивирусы (установленные)",
			Status:  StatusInfo,
			Message: "не удалось опросить WMI SecurityCenter2",
		}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && strings.TrimSpace(lines[0]) == "") {
		return TestResult{
			Name:    "Антивирусы (установленные)",
			Status:  StatusOK,
			Message: "не обнаружены",
		}
	}

	var names []string
	var details []string
	enabledCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 3 {
			name := parts[0]
			state := parts[1]
			update := parts[2]
			names = append(names, name)
			details = append(details, fmt.Sprintf("%s — %s, %s", name, state, update))
			if state == "enabled" {
				enabledCount++
			}
		}
	}

	if len(names) == 0 {
		return TestResult{
			Name:    "Антивирусы (установленные)",
			Status:  StatusOK,
			Message: "не обнаружены",
		}
	}

	status := StatusInfo
	msg := fmt.Sprintf("найдено %d антивирусов (%d активных)", len(names), enabledCount)
	if enabledCount > 0 {
		// AV сам по себе не баг — но это потенциальный источник проблем с VPN.
		status = StatusWarning
		msg = fmt.Sprintf("активен %d AV: %s — может фильтровать VPN-трафик",
			enabledCount, strings.Join(names, ", "))
	}

	return TestResult{
		Name:    "Антивирусы (установленные)",
		Status:  status,
		Message: msg,
		Details: strings.Join(details, "\n"),
	}
}

// checkRunningAntivirus ищет AV-процессы в текущем списке tasklist'а.
func checkRunningAntivirus(processList string) TestResult {
	if processList == "" {
		return TestResult{
			Name:    "Антивирусы (процессы)",
			Status:  StatusInfo,
			Message: "не удалось получить tasklist",
		}
	}

	found := map[string]bool{}
	for proc, name := range knownAntiviruses {
		if strings.Contains(processList, strings.ToLower(strings.TrimSpace(proc))) {
			found[name] = true
		}
	}

	if len(found) == 0 {
		return TestResult{
			Name:    "Антивирусы (процессы)",
			Status:  StatusOK,
			Message: "активных AV/security-процессов не обнаружено",
		}
	}

	var names []string
	for name := range found {
		names = append(names, name)
	}

	return TestResult{
		Name:    "Антивирусы (процессы)",
		Status:  StatusWarning,
		Message: fmt.Sprintf("активны %d security-процессов: %s — могут блокировать VPN",
			len(names), strings.Join(names, ", ")),
		Details: "Многие AV выполняют HTTPS-инспекцию (Kaspersky, ESET, Avast) и могут разрывать TLS внутри VPN. Попробуйте временно отключить веб-защиту/HTTPS-сканирование.",
	}
}

// checkDefenderTamperProtection отдельная проверка состояния Windows Defender.
func checkDefenderTamperProtection() TestResult {
	psCmd := `try { ` +
		`$pref = Get-MpPreference -ErrorAction Stop; ` +
		`$status = Get-MpComputerStatus -ErrorAction Stop; ` +
		`'RealTime={0}|Tamper={1}|Antispyware={2}|AMServiceEnabled={3}' -f ` +
		`(-not $pref.DisableRealtimeMonitoring), $status.IsTamperProtected, ` +
		`$status.AntispywareEnabled, $status.AMServiceEnabled ` +
		`} catch { '' }`

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return TestResult{
			Name:    "Windows Defender",
			Status:  StatusInfo,
			Message: "не удалось опросить (нужны права/Defender отключён)",
		}
	}

	line := strings.TrimSpace(string(out))
	return TestResult{
		Name:    "Windows Defender",
		Status:  StatusInfo,
		Message: "состояние: " + line,
		Details: "RealTime — мониторинг, Tamper — защита от изменений, Antispyware — антишпион модуль",
	}
}
