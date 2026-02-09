package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Xray-совместимые VPN клиенты (нужны для подключения)
var xrayClients = map[string]string{
	"hiddify.exe":                "Hiddify",
	"hiddifynext.exe":            "Hiddify Next",
	"hiddifycli.exe":             "Hiddify CLI",
	"v2rayn.exe":                 "v2rayN",
	"v2rayng.exe":                "v2rayNG",
	"v2ray.exe":                  "V2Ray Core",
	"xray.exe":                   "Xray Core",
	"sing-box.exe":               "sing-box",
	"nekoray.exe":                "NekoRay",
	"nekobox.exe":                "NekoBox",
	"clash.exe":                  "Clash",
	"clash-meta.exe":             "Clash Meta",
	"mihomo.exe":                 "Mihomo (Clash)",
	"sslocal.exe":                "Shadowsocks",
	"naiveproxy.exe":             "NaiveProxy",
	"hysteria.exe":               "Hysteria",
	"tuic-client.exe":            "TUIC",
	"invisible-man-xray.exe":     "InvisibleMan XRay",
	"v2raysetool.exe":            "V2RaySeTool",
	"qv2ray.exe":                 "Qv2ray",
}

// Коммерческие VPN (могут мешать подключению)
var commercialVPNs = map[string]string{
	"openvpn.exe":           "OpenVPN",
	"openvpn-gui.exe":       "OpenVPN GUI",
	"wireguard.exe":         "WireGuard",
	"nordvpn-service.exe":   "NordVPN",
	"nordlynx.exe":          "NordLynx (NordVPN)",
	"protonvpn.exe":         "ProtonVPN",
	"protonvpn-service.exe": "ProtonVPN Service",
	"expressvpnservice.exe": "ExpressVPN",
	"warp-svc.exe":          "Cloudflare WARP",
	"cloudflarewarp.exe":    "Cloudflare WARP",
	"windscribe.exe":        "Windscribe",
	"surfsharkservice.exe":  "Surfshark",
	"cyberghostvpn.exe":     "CyberGhost",
	"pia-service.exe":       "Private Internet Access",
	"mullvad-daemon.exe":    "Mullvad VPN",
	"psiphon.exe":           "Psiphon",
	"lantern.exe":           "Lantern",
	"tailscaled.exe":        "Tailscale",
	"zerotier-one.exe":      "ZeroTier",
	"hamachi-2.exe":         "Hamachi",
	"softether.exe":         "SoftEther VPN",
}

// Альтернативные DNS серверы для проверки
var altDNSServers = []struct {
	IP   string
	Name string
}{
	{"8.8.8.8", "Google DNS"},
	{"1.1.1.1", "Cloudflare DNS"},
	{"9.9.9.9", "Quad9 DNS"},
	{"208.67.222.222", "OpenDNS"},
	{"76.76.2.0", "Control D"},
	{"94.140.14.14", "AdGuard DNS"},
}

func getProcessList() string {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.ToLower(string(out))
}

func runInterferenceTests() []TestResult {
	var results []TestResult

	processList := getProcessList()
	results = append(results, checkVPNClient(processList))
	results = append(results, checkCommercialVPNs(processList))
	results = append(results, checkFirewallStatus())
	results = append(results, checkSystemProxy())
	results = append(results, checkVPNAdapters())

	return results
}

func checkVPNClient(processList string) TestResult {
	if processList == "" {
		return TestResult{
			Name:    "VPN-клиент",
			Status:  StatusWarning,
			Message: "не удалось определить",
		}
	}

	var found []string
	for proc, name := range xrayClients {
		if strings.Contains(processList, strings.ToLower(proc)) {
			found = append(found, name)
		}
	}

	if len(found) > 0 {
		return TestResult{
			Name:    "VPN-клиент",
			Status:  StatusOK,
			Message: fmt.Sprintf("обнаружен: %s", strings.Join(found, ", ")),
		}
	}

	return TestResult{
		Name:    "VPN-клиент",
		Status:  StatusWarning,
		Message: "не обнаружен — установите Hiddify, v2rayN или NekoRay для подключения",
	}
}

func checkCommercialVPNs(processList string) TestResult {
	if processList == "" {
		return TestResult{
			Name:    "Сторонние VPN",
			Status:  StatusInfo,
			Message: "не удалось проверить",
		}
	}

	var found []string
	for proc, name := range commercialVPNs {
		if strings.Contains(processList, strings.ToLower(proc)) {
			found = append(found, name)
		}
	}

	if len(found) > 0 {
		return TestResult{
			Name:    "Сторонние VPN",
			Status:  StatusWarning,
			Message: fmt.Sprintf("обнаружено %d — отключите перед подключением!", len(found)),
			Details: strings.Join(found, ", "),
		}
	}

	return TestResult{
		Name:    "Сторонние VPN",
		Status:  StatusOK,
		Message: "не обнаружены",
	}
}

func checkFirewallStatus() TestResult {
	// Проверяем статус через реестр — не зависит от языка системы
	profiles := []struct {
		key  string
		name string
	}{
		{`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`, "Domain"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`, "Private"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`, "Public"},
	}

	var details []string
	enabledCount := 0

	for _, p := range profiles {
		out, err := exec.Command("reg", "query", p.key, "/v", "EnableFirewall").CombinedOutput()
		if err != nil {
			details = append(details, fmt.Sprintf("%s: не удалось определить", p.name))
			continue
		}
		output := string(out)
		if strings.Contains(output, "0x1") {
			details = append(details, fmt.Sprintf("%s: ВКЛ", p.name))
			enabledCount++
		} else if strings.Contains(output, "0x0") {
			details = append(details, fmt.Sprintf("%s: ВЫКЛ", p.name))
		}
	}

	status := StatusOK
	msg := "Windows Firewall активен"
	if enabledCount == 0 {
		status = StatusInfo
		msg = "Windows Firewall отключён (проверьте, если это не намеренно)"
	} else if enabledCount < 3 {
		status = StatusInfo
		msg = fmt.Sprintf("Windows Firewall: %d из 3 профилей активны", enabledCount)
	}

	return TestResult{
		Name:    "Брандмауэр",
		Status:  status,
		Message: msg,
		Details: strings.Join(details, "\n"),
	}
}

func checkSystemProxy() TestResult {
	// Проверяем системные прокси через реестр
	out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable").CombinedOutput()

	proxyEnabled := false
	if err == nil && strings.Contains(string(out), "0x1") {
		proxyEnabled = true
	}

	var proxyServer string
	if proxyEnabled {
		out2, err2 := exec.Command("reg", "query",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
			"/v", "ProxyServer").CombinedOutput()
		if err2 == nil {
			lines := strings.Split(string(out2), "\n")
			for _, line := range lines {
				if strings.Contains(line, "ProxyServer") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						proxyServer = parts[len(parts)-1]
					}
				}
			}
		}
	}

	// Проверяем переменные окружения
	var envProxies []string
	for _, env := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"} {
		if val := getEnvVar(env); val != "" {
			envProxies = append(envProxies, fmt.Sprintf("%s=%s", env, val))
		}
	}

	if proxyEnabled || len(envProxies) > 0 {
		var details []string
		msg := "обнаружены системные прокси — могут перехватывать трафик VPN"
		if proxyEnabled && proxyServer != "" {
			details = append(details, fmt.Sprintf("Системный прокси: %s", proxyServer))
		}
		if len(envProxies) > 0 {
			details = append(details, envProxies...)
		}
		return TestResult{
			Name:    "Системный прокси",
			Status:  StatusWarning,
			Message: msg,
			Details: strings.Join(details, "\n"),
		}
	}

	return TestResult{
		Name:    "Системный прокси",
		Status:  StatusOK,
		Message: "системные прокси не настроены",
	}
}

func getEnvVar(name string) string {
	out, err := exec.Command("cmd", "/c", "echo", "%"+name+"%").Output()
	if err != nil {
		return ""
	}
	val := strings.TrimSpace(string(out))
	if val == "%"+name+"%" || val == "" {
		return ""
	}
	return val
}

func checkVPNAdapters() TestResult {
	ifaces, err := net.Interfaces()
	if err != nil {
		return TestResult{
			Name:    "VPN-адаптеры",
			Status:  StatusWarning,
			Message: "не удалось получить список интерфейсов",
		}
	}

	vpnKeywords := []string{
		"tun", "tap", "wintun", "wireguard", "wg",
		"nordlynx", "proton", "mullvad", "warp",
		"vpn", "virtual", "zerotier", "tailscale",
		"hamachi", "softether", "hyper-v",
	}

	var vpnAdapters []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		nameLower := strings.ToLower(iface.Name)
		for _, kw := range vpnKeywords {
			if strings.Contains(nameLower, kw) {
				addrs, _ := iface.Addrs()
				addrStrs := make([]string, 0)
				for _, a := range addrs {
					addrStrs = append(addrStrs, a.String())
				}
				detail := iface.Name
				if len(addrStrs) > 0 {
					detail += ": " + strings.Join(addrStrs, ", ")
				}
				vpnAdapters = append(vpnAdapters, detail)
				break
			}
		}
	}

	if len(vpnAdapters) > 0 {
		return TestResult{
			Name:    "VPN-адаптеры",
			Status:  StatusWarning,
			Message: fmt.Sprintf("обнаружено %d VPN/виртуальных адаптеров — могут влиять на маршрутизацию", len(vpnAdapters)),
			Details: strings.Join(vpnAdapters, "\n"),
		}
	}

	return TestResult{
		Name:    "VPN-адаптеры",
		Status:  StatusOK,
		Message: "VPN-адаптеры не обнаружены",
	}
}

// checkDNSHijacking проверяет подмену DNS, сравнивая ответы от системного и публичных DNS
func checkDNSHijacking(host string) TestResult {
	if net.ParseIP(host) != nil {
		return TestResult{
			Name:    "DNS проверка",
			Status:  StatusInfo,
			Message: "пропущена (используется IP-адрес напрямую)",
		}
	}

	// Разрешаем через системный DNS
	systemIPs, sysErr := net.LookupHost(host)

	// Разрешаем через Google DNS (8.8.8.8) и Cloudflare (1.1.1.1)
	googleIPs := resolveWithDNS(host, "8.8.8.8:53")
	cloudflareIPs := resolveWithDNS(host, "1.1.1.1:53")

	if sysErr != nil && len(googleIPs) == 0 && len(cloudflareIPs) == 0 {
		return TestResult{
			Name:    "DNS проверка",
			Status:  StatusError,
			Message: fmt.Sprintf("домен %s не разрешается ни одним DNS сервером", host),
		}
	}

	if sysErr != nil && (len(googleIPs) > 0 || len(cloudflareIPs) > 0) {
		var workingDNS []string
		if len(googleIPs) > 0 {
			workingDNS = append(workingDNS, fmt.Sprintf("Google (8.8.8.8): %s", strings.Join(googleIPs, ", ")))
		}
		if len(cloudflareIPs) > 0 {
			workingDNS = append(workingDNS, fmt.Sprintf("Cloudflare (1.1.1.1): %s", strings.Join(cloudflareIPs, ", ")))
		}
		return TestResult{
			Name:   "DNS проверка",
			Status: StatusError,
			Message: fmt.Sprintf("системный DNS не разрешает %s, но публичные DNS работают — "+
				"возможна блокировка/подмена DNS провайдером", host),
			Details: strings.Join(workingDNS, "\n"),
		}
	}

	// Сравниваем IP-адреса
	if len(systemIPs) > 0 && len(googleIPs) > 0 {
		sysSet := make(map[string]bool)
		for _, ip := range systemIPs {
			sysSet[ip] = true
		}
		match := false
		for _, ip := range googleIPs {
			if sysSet[ip] {
				match = true
				break
			}
		}
		if !match {
			details := fmt.Sprintf("Системный DNS: %s\nGoogle DNS: %s",
				strings.Join(systemIPs, ", "), strings.Join(googleIPs, ", "))
			if len(cloudflareIPs) > 0 {
				details += fmt.Sprintf("\nCloudflare DNS: %s", strings.Join(cloudflareIPs, ", "))
			}
			return TestResult{
				Name:    "DNS проверка",
				Status:  StatusWarning,
				Message: fmt.Sprintf("IP-адреса %s от разных DNS серверов НЕ совпадают — возможна подмена DNS!", host),
				Details: details,
			}
		}
	}

	details := fmt.Sprintf("Системный: %s", strings.Join(systemIPs, ", "))
	if len(googleIPs) > 0 {
		details += fmt.Sprintf("\nGoogle: %s", strings.Join(googleIPs, ", "))
	}

	return TestResult{
		Name:    "DNS проверка",
		Status:  StatusOK,
		Message: fmt.Sprintf("DNS для %s — совпадение подтверждено, подмена не обнаружена", host),
		Details: details,
	}
}

func resolveWithDNS(host, dnsServer string) []string {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return addrs
}

// testAlternativeDNS пробует альтернативные DNS серверы, когда системный DNS не работает
func testAlternativeDNS(host string) TestResult {
	var working []string
	var details []string

	for _, dns := range altDNSServers {
		start := time.Now()
		ips := resolveWithDNS(host, dns.IP+":53")
		elapsed := time.Since(start)

		if len(ips) > 0 {
			working = append(working, dns.Name)
			details = append(details, fmt.Sprintf("[OK] %s (%s): %s (%s)",
				dns.Name, dns.IP, strings.Join(ips, ", "), elapsed.Round(time.Millisecond)))
		} else {
			details = append(details, fmt.Sprintf("[FAIL] %s (%s): не удалось разрешить (%s)",
				dns.Name, dns.IP, elapsed.Round(time.Millisecond)))
		}
	}

	if len(working) == 0 {
		return TestResult{
			Name:    "Альтернативные DNS",
			Status:  StatusError,
			Message: fmt.Sprintf("ни один публичный DNS не смог разрешить %s", host),
			Details: strings.Join(details, "\n"),
		}
	}

	if len(working) == len(altDNSServers) {
		return TestResult{
			Name:    "Альтернативные DNS",
			Status:  StatusOK,
			Message: fmt.Sprintf("все %d публичных DNS серверов разрешают %s", len(working), host),
			Details: strings.Join(details, "\n"),
		}
	}

	return TestResult{
		Name:    "Альтернативные DNS",
		Status:  StatusWarning,
		Message: fmt.Sprintf("%d из %d DNS серверов разрешают %s (рекомендуется: %s)",
			len(working), len(altDNSServers), host, working[0]),
		Details: strings.Join(details, "\n"),
	}
}
