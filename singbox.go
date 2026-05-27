package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// SingBoxProxy — управляемый процесс sing-box.exe с локальным SOCKS5-входом.
// Использование:
//   sb, err := newSingBoxProxy(cfg)
//   if err != nil { fallback }
//   defer sb.Stop()
//   conn, _ := sb.Dial("www.youtube.com", 443)
type SingBoxProxy struct {
	cmd        *exec.Cmd
	socksAddr  string
	configPath string
	stderr     *bytes.Buffer
	binPath    string
}

const (
	singBoxVersion = "1.13.9"
	singBoxDir     = "sing-box-bin"
)

// singBoxDownloadURL формирует URL под текущую ОС/архитектуру.
func singBoxDownloadURL() string {
	return "https://github.com/SagerNet/sing-box/releases/download/v" + singBoxVersion +
		"/sing-box-" + singBoxVersion + "-" + singBoxAssetSuffix()
}

// locateSingBox ищет sing-box бинарник в нескольких типичных местах.
// На Windows ищет .exe, на macOS/Linux без расширения.
func locateSingBox() string {
	exe := "sing-box" + binaryExt()
	candidates := []string{
		filepath.Join(singBoxDir, exe),
		filepath.Join(singBoxDir, "sing-box-"+singBoxVersion+"-"+strings.TrimSuffix(singBoxAssetSuffix(), ".zip"), exe),
		filepath.Join(singBoxDir, "sing-box-"+singBoxVersion+"-"+strings.TrimSuffix(singBoxAssetSuffix(), ".tar.gz"), exe),
		exe,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	if p, err := exec.LookPath(exe); err == nil {
		return p
	}
	return ""
}

// downloadSingBox тянет архив (zip на Windows / tar.gz на macOS+Linux) с GitHub
// и распаковывает sing-box бинарник в ./sing-box-bin/.
func downloadSingBox() (string, error) {
	if err := os.MkdirAll(singBoxDir, 0o755); err != nil {
		return "", err
	}
	url := singBoxDownloadURL()
	if url == "" {
		return "", fmt.Errorf("неподдерживаемая платформа для sing-box: %s", singBoxAssetSuffix())
	}

	isZip := strings.HasSuffix(url, ".zip")
	var archivePath string
	if isZip {
		archivePath = filepath.Join(singBoxDir, "sing-box.zip")
	} else {
		archivePath = filepath.Join(singBoxDir, "sing-box.tar.gz")
	}

	client := &http.Client{Timeout: 120 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "DiagnostikVPN/3.5")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d при скачивании sing-box", resp.StatusCode)
	}

	out, err := os.Create(archivePath)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return "", err
	}
	out.Close()

	exeName := "sing-box" + binaryExt()
	if isZip {
		return extractFromZip(archivePath, singBoxDir, exeName)
	}
	return extractFromTarGz(archivePath, singBoxDir, exeName)
}

// extractFromZip извлекает указанный файл (по basename) в dest dir.
func extractFromZip(archivePath, dest, fileName string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer r.Close()
	for _, f := range r.File {
		if strings.HasSuffix(strings.ToLower(f.Name), strings.ToLower(fileName)) {
			dst := filepath.Join(dest, fileName)
			outFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
			if err != nil {
				return "", err
			}
			rc, err := f.Open()
			if err != nil {
				outFile.Close()
				return "", err
			}
			if _, err := io.Copy(outFile, rc); err != nil {
				outFile.Close()
				rc.Close()
				return "", err
			}
			outFile.Close()
			rc.Close()
			abs, _ := filepath.Abs(dst)
			return abs, nil
		}
	}
	return "", fmt.Errorf("%s не найден в архиве", fileName)
}

// extractFromTarGz извлекает указанный файл (по basename) в dest dir.
func extractFromTarGz(archivePath, dest, fileName string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(hdr.Name), strings.ToLower(fileName)) {
			continue
		}
		dst := filepath.Join(dest, fileName)
		outFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return "", err
		}
		outFile.Close()
		abs, _ := filepath.Abs(dst)
		return abs, nil
	}
	return "", fmt.Errorf("%s не найден в архиве", fileName)
}

// newSingBoxProxy запускает sing-box для одного VPN-конфига.
// Жизненный цикл: caller обязан вызвать .Stop() — иначе процесс остаётся жить.
func newSingBoxProxy(cfg *VPNConfig) (*SingBoxProxy, error) {
	binPath := locateSingBox()
	if binPath == "" {
		return nil, fmt.Errorf("sing-box.exe не найден (передайте -download-singbox или установите вручную)")
	}

	port, err := getFreeTCPPort()
	if err != nil {
		return nil, fmt.Errorf("free port: %w", err)
	}

	configJSON, err := generateSingBoxConfig(cfg, port)
	if err != nil {
		return nil, fmt.Errorf("config gen: %w", err)
	}

	tmpfile, err := os.CreateTemp("", "diag-singbox-*.json")
	if err != nil {
		return nil, err
	}
	if _, err := tmpfile.Write(configJSON); err != nil {
		tmpfile.Close()
		os.Remove(tmpfile.Name())
		return nil, err
	}
	tmpfile.Close()

	var stderr bytes.Buffer
	cmd := exec.Command(binPath, "run", "-c", tmpfile.Name())
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		os.Remove(tmpfile.Name())
		return nil, fmt.Errorf("start sing-box: %w", err)
	}

	p := &SingBoxProxy{
		cmd:        cmd,
		socksAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		configPath: tmpfile.Name(),
		stderr:     &stderr,
		binPath:    binPath,
	}

	if err := p.waitReady(12 * time.Second); err != nil {
		errMsg := err.Error()
		if stderrTxt := stderr.String(); stderrTxt != "" {
			// Берём первые 400 символов stderr — обычно там вся ошибка sing-box'a
			short := strings.TrimSpace(stderrTxt)
			if len(short) > 400 {
				short = short[:400] + "..."
			}
			errMsg += " | stderr: " + short
		}
		p.Stop()
		return nil, fmt.Errorf("sing-box не поднял SOCKS5 на %s: %s", p.socksAddr, errMsg)
	}

	return p, nil
}

func (p *SingBoxProxy) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Проверяем что процесс ещё жив
		if p.cmd.ProcessState != nil && p.cmd.ProcessState.Exited() {
			return fmt.Errorf("sing-box завершился преждевременно (код %d)", p.cmd.ProcessState.ExitCode())
		}
		conn, err := net.DialTimeout("tcp", p.socksAddr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("порт %s не слушает за %s", p.socksAddr, timeout)
}

// Dial устанавливает TCP-соединение к target через SOCKS5-вход sing-box.
func (p *SingBoxProxy) Dial(host string, port int) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", p.socksAddr, nil, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
}

// Stop останавливает sing-box и удаляет временный config.
func (p *SingBoxProxy) Stop() {
	if p == nil {
		return
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
	if p.configPath != "" {
		os.Remove(p.configPath)
	}
}

// StderrTail возвращает последний кусок stderr sing-box (для диагностики).
func (p *SingBoxProxy) StderrTail(n int) string {
	if p == nil || p.stderr == nil {
		return ""
	}
	s := p.stderr.String()
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// normalizeUUID приводит UUID к каноничному виду 8-4-4-4-12.
// Если на вход дали голый hex без дефисов — добавляет.
func normalizeUUID(raw string) string {
	s := strings.ReplaceAll(raw, "-", "")
	if len(s) != 32 {
		return raw // пусть sing-box сам ругнётся
	}
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}

// getFreeTCPPort берёт системой выданный свободный порт на 127.0.0.1.
func getFreeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// generateSingBoxConfig формирует JSON-конфиг sing-box из нашего VPNConfig.
// Поддерживает: VLESS (Reality/TLS/Vision), Trojan, Shadowsocks, VMess
// и транспорты tcp/ws/grpc/http(xhttp)/httpupgrade.
func generateSingBoxConfig(cfg *VPNConfig, socksPort int) ([]byte, error) {
	outbound, err := buildOutbound(cfg)
	if err != nil {
		return nil, err
	}

	// sing-box v1.13: убраны legacy поля sniff / outbound в route rules.
	// Минимальный валидный config: SOCKS5 inbound без sniff + route.final.
	full := map[string]interface{}{
		"log": map[string]interface{}{
			"level":     "warn",
			"timestamp": true,
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"type":        "socks",
				"tag":         "socks-in",
				"listen":      "127.0.0.1",
				"listen_port": socksPort,
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{
				"type": "direct",
				"tag":  "direct",
			},
		},
		"route": map[string]interface{}{
			"final": "proxy",
		},
	}

	return json.MarshalIndent(full, "", "  ")
}

func buildOutbound(cfg *VPNConfig) (map[string]interface{}, error) {
	tlsCfg := buildSingBoxTLS(cfg)
	transport := buildSingBoxTransport(cfg)

	switch cfg.Protocol {
	case "vless":
		ob := map[string]interface{}{
			"type":        "vless",
			"tag":         "proxy",
			"server":      cfg.Address,
			"server_port": cfg.Port,
			"uuid":        normalizeUUID(cfg.UUID),
		}
		if cfg.Flow != "" {
			ob["flow"] = cfg.Flow
		}
		if tlsCfg != nil {
			ob["tls"] = tlsCfg
		}
		if transport != nil {
			ob["transport"] = transport
		}
		return ob, nil

	case "trojan":
		ob := map[string]interface{}{
			"type":        "trojan",
			"tag":         "proxy",
			"server":      cfg.Address,
			"server_port": cfg.Port,
			"password":    cfg.Password,
		}
		if tlsCfg != nil {
			ob["tls"] = tlsCfg
		}
		if transport != nil {
			ob["transport"] = transport
		}
		return ob, nil

	case "shadowsocks":
		ob := map[string]interface{}{
			"type":        "shadowsocks",
			"tag":         "proxy",
			"server":      cfg.Address,
			"server_port": cfg.Port,
			"method":      cfg.Method,
			"password":    cfg.Password,
		}
		return ob, nil

	case "vmess":
		ob := map[string]interface{}{
			"type":        "vmess",
			"tag":         "proxy",
			"server":      cfg.Address,
			"server_port": cfg.Port,
			"uuid":        normalizeUUID(cfg.UUID),
			"security":    "auto",
		}
		if cfg.HeaderType != "" && cfg.HeaderType != "none" {
			// alterId / packetEncoding в новом vmess уже не нужны для большинства серверов
		}
		if tlsCfg != nil {
			ob["tls"] = tlsCfg
		}
		if transport != nil {
			ob["transport"] = transport
		}
		return ob, nil
	}
	return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
}

func buildSingBoxTLS(cfg *VPNConfig) map[string]interface{} {
	if cfg.Security == "" || cfg.Security == "none" {
		return nil
	}
	t := map[string]interface{}{
		"enabled":  true,
		"insecure": false,
	}
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Address
	}
	t["server_name"] = sni

	if cfg.ALPN != "" {
		alpns := strings.Split(cfg.ALPN, ",")
		clean := make([]string, 0, len(alpns))
		for _, a := range alpns {
			a = strings.TrimSpace(a)
			if a != "" {
				clean = append(clean, a)
			}
		}
		if len(clean) > 0 {
			t["alpn"] = clean
		}
	}

	// uTLS — Reality требует, остальным тоже не вредит
	fp := cfg.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	t["utls"] = map[string]interface{}{
		"enabled":     true,
		"fingerprint": fp,
	}

	if cfg.Security == "reality" {
		reality := map[string]interface{}{
			"enabled":    true,
			"public_key": cfg.PublicKey,
		}
		if cfg.ShortID != "" {
			reality["short_id"] = cfg.ShortID
		}
		t["reality"] = reality
	}

	return t
}

func buildSingBoxTransport(cfg *VPNConfig) map[string]interface{} {
	switch cfg.Transport {
	case "", "tcp", "raw":
		// pure TCP — sing-box опускает transport
		return nil
	case "ws":
		t := map[string]interface{}{"type": "ws"}
		if cfg.Path != "" {
			t["path"] = cfg.Path
		}
		if cfg.Host != "" {
			t["headers"] = map[string]interface{}{
				"Host": cfg.Host,
			}
		}
		return t
	case "grpc":
		t := map[string]interface{}{"type": "grpc"}
		if cfg.ServiceName != "" {
			t["service_name"] = cfg.ServiceName
		}
		return t
	case "http":
		t := map[string]interface{}{"type": "http"}
		if cfg.Path != "" {
			t["path"] = cfg.Path
		}
		if cfg.Host != "" {
			t["host"] = []string{cfg.Host}
		}
		return t
	case "xhttp":
		// xhttp в sing-box 1.13 нет — он есть только в xray-core.
		// Возвращаем nil тут означает "sing-box не подходит для этого конфига" —
		// в keyverdict.go диспетчер увидит transport=xhttp и поднимет XrayProxy вместо.
		return nil
	case "httpupgrade":
		t := map[string]interface{}{"type": "httpupgrade"}
		if cfg.Path != "" {
			t["path"] = cfg.Path
		}
		if cfg.Host != "" {
			t["host"] = cfg.Host
		}
		return t
	}
	// Неизвестный транспорт — пусть sing-box сам ругнётся
	return map[string]interface{}{"type": cfg.Transport}
}
