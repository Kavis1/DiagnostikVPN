package main

import (
	"archive/zip"
	"bytes"
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

// XrayProxy — управляемый процесс xray.exe (xray-core).
// Используется для VPN-конфигов с xhttp-транспортом, которые sing-box не понимает.
type XrayProxy struct {
	cmd        *exec.Cmd
	socksAddr  string
	configPath string
	stderr     *bytes.Buffer
	binPath    string
}

const (
	xrayVersion = "26.3.27"
	// GitHub release asset URL
	xrayZipURL = "https://github.com/XTLS/Xray-core/releases/download/v" + xrayVersion +
		"/Xray-windows-64.zip"
	xrayDir = "xray-bin"
)

// locateXrayCore ищет xray.exe в типичных местах.
func locateXrayCore() string {
	candidates := []string{
		filepath.Join(xrayDir, "xray.exe"),
		"xray.exe",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	if p, err := exec.LookPath("xray.exe"); err == nil {
		return p
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	return ""
}

// downloadXrayCore тянет ZIP с GitHub и распаковывает xray.exe в ./xray-bin/.
func downloadXrayCore() (string, error) {
	if err := os.MkdirAll(xrayDir, 0o755); err != nil {
		return "", err
	}
	zipPath := filepath.Join(xrayDir, "xray.zip")

	client := &http.Client{Timeout: 180 * time.Second}
	req, _ := http.NewRequest("GET", xrayZipURL, nil)
	req.Header.Set("User-Agent", "DiagnostikVPN/3.3")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d при скачивании xray-core", resp.StatusCode)
	}

	out, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return "", err
	}
	out.Close()

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	// В ZIP'е лежат xray.exe + geo*.dat (нужны для роутинга — пусть будут рядом).
	var xrayExePath string
	for _, f := range r.File {
		baseName := filepath.Base(f.Name)
		if strings.HasSuffix(strings.ToLower(baseName), ".exe") ||
			strings.HasSuffix(strings.ToLower(baseName), ".dat") {
			dst := filepath.Join(xrayDir, baseName)
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
			if strings.EqualFold(baseName, "xray.exe") {
				xrayExePath, _ = filepath.Abs(dst)
			}
		}
	}
	if xrayExePath == "" {
		return "", fmt.Errorf("xray.exe не найден в архиве")
	}
	return xrayExePath, nil
}

// newXrayProxy поднимает xray-core с одним outbound на cfg и локальным SOCKS5 inbound.
func newXrayProxy(cfg *VPNConfig) (*XrayProxy, error) {
	binPath := locateXrayCore()
	if binPath == "" {
		return nil, fmt.Errorf("xray.exe не найден (используйте -download-xray=true)")
	}

	port, err := getFreeTCPPort()
	if err != nil {
		return nil, fmt.Errorf("free port: %w", err)
	}

	configJSON, err := generateXrayConfig(cfg, port)
	if err != nil {
		return nil, fmt.Errorf("config gen: %w", err)
	}

	tmpfile, err := os.CreateTemp("", "diag-xray-*.json")
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
		return nil, fmt.Errorf("start xray: %w", err)
	}

	p := &XrayProxy{
		cmd:        cmd,
		socksAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		configPath: tmpfile.Name(),
		stderr:     &stderr,
		binPath:    binPath,
	}

	if err := p.waitReady(12 * time.Second); err != nil {
		errMsg := err.Error()
		if s := strings.TrimSpace(stderr.String()); s != "" {
			if len(s) > 400 {
				s = s[:400] + "..."
			}
			errMsg += " | stderr: " + s
		}
		p.Stop()
		return nil, fmt.Errorf("xray не поднял SOCKS5 на %s: %s", p.socksAddr, errMsg)
	}

	return p, nil
}

func (p *XrayProxy) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if p.cmd.ProcessState != nil && p.cmd.ProcessState.Exited() {
			return fmt.Errorf("xray завершился преждевременно (код %d)", p.cmd.ProcessState.ExitCode())
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

// Dial — реализация ProxyBackend.
func (p *XrayProxy) Dial(host string, port int) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", p.socksAddr, nil, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
}

func (p *XrayProxy) Stop() {
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

func (p *XrayProxy) SocksAddr() string  { return p.socksAddr }
func (p *XrayProxy) BackendName() string { return "xray-core" }
func (p *XrayProxy) StderrTail(n int) string {
	if p == nil || p.stderr == nil {
		return ""
	}
	s := p.stderr.String()
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// generateXrayConfig формирует Xray JSON-конфиг.
// Формат отличается от sing-box:
//   - inbounds[].protocol="socks", settings={auth,udp}
//   - outbounds[].protocol="vless"/"trojan"/etc, streamSettings={network,security,...Settings}
//   - xhttp задаётся через streamSettings.network="xhttp" + xhttpSettings={path,host,mode}
func generateXrayConfig(cfg *VPNConfig, socksPort int) ([]byte, error) {
	outbound, err := buildXrayOutbound(cfg)
	if err != nil {
		return nil, err
	}

	full := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":      "socks-in",
				"port":     socksPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  false,
				},
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{
				"tag":      "direct",
				"protocol": "freedom",
			},
		},
	}

	return json.MarshalIndent(full, "", "  ")
}

func buildXrayOutbound(cfg *VPNConfig) (map[string]interface{}, error) {
	stream := buildXrayStreamSettings(cfg)

	switch cfg.Protocol {
	case "vless":
		settings := map[string]interface{}{
			"vnext": []interface{}{
				map[string]interface{}{
					"address": cfg.Address,
					"port":    cfg.Port,
					"users": []interface{}{
						map[string]interface{}{
							"id":         normalizeUUID(cfg.UUID),
							"encryption": "none",
							"flow":       cfg.Flow,
						},
					},
				},
			},
		}
		return map[string]interface{}{
			"tag":            "proxy",
			"protocol":       "vless",
			"settings":       settings,
			"streamSettings": stream,
		}, nil

	case "trojan":
		settings := map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{
					"address":  cfg.Address,
					"port":     cfg.Port,
					"password": cfg.Password,
				},
			},
		}
		return map[string]interface{}{
			"tag":            "proxy",
			"protocol":       "trojan",
			"settings":       settings,
			"streamSettings": stream,
		}, nil

	case "vmess":
		settings := map[string]interface{}{
			"vnext": []interface{}{
				map[string]interface{}{
					"address": cfg.Address,
					"port":    cfg.Port,
					"users": []interface{}{
						map[string]interface{}{
							"id":       normalizeUUID(cfg.UUID),
							"security": "auto",
						},
					},
				},
			},
		}
		return map[string]interface{}{
			"tag":            "proxy",
			"protocol":       "vmess",
			"settings":       settings,
			"streamSettings": stream,
		}, nil

	case "shadowsocks":
		settings := map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{
					"address":  cfg.Address,
					"port":     cfg.Port,
					"method":   cfg.Method,
					"password": cfg.Password,
				},
			},
		}
		return map[string]interface{}{
			"tag":      "proxy",
			"protocol": "shadowsocks",
			"settings": settings,
		}, nil
	}

	return nil, fmt.Errorf("xray: unsupported protocol %s", cfg.Protocol)
}

func buildXrayStreamSettings(cfg *VPNConfig) map[string]interface{} {
	network := cfg.Transport
	if network == "" || network == "raw" {
		network = "tcp"
	}

	stream := map[string]interface{}{
		"network": network,
	}

	// Security: tls / reality / none
	switch cfg.Security {
	case "tls":
		stream["security"] = "tls"
		tlsSet := map[string]interface{}{
			"serverName": firstNonEmpty(cfg.SNI, cfg.Address),
			"fingerprint": firstNonEmpty(cfg.Fingerprint, "chrome"),
		}
		if cfg.ALPN != "" {
			alpns := []string{}
			for _, a := range strings.Split(cfg.ALPN, ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					alpns = append(alpns, a)
				}
			}
			if len(alpns) > 0 {
				tlsSet["alpn"] = alpns
			}
		}
		stream["tlsSettings"] = tlsSet
	case "reality":
		stream["security"] = "reality"
		realitySet := map[string]interface{}{
			"serverName":  firstNonEmpty(cfg.SNI, cfg.Address),
			"fingerprint": firstNonEmpty(cfg.Fingerprint, "chrome"),
			"publicKey":   cfg.PublicKey,
		}
		if cfg.ShortID != "" {
			realitySet["shortId"] = cfg.ShortID
		}
		if cfg.SpiderX != "" {
			realitySet["spiderX"] = cfg.SpiderX
		}
		stream["realitySettings"] = realitySet
	default:
		// none / "" — без security
	}

	// Transport-specific settings
	switch network {
	case "tcp":
		if cfg.HeaderType == "http" {
			stream["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{"type": "http"},
			}
		}
	case "ws":
		ws := map[string]interface{}{}
		if cfg.Path != "" {
			ws["path"] = cfg.Path
		}
		if cfg.Host != "" {
			ws["host"] = cfg.Host
			ws["headers"] = map[string]interface{}{"Host": cfg.Host}
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]interface{}{}
		if cfg.ServiceName != "" {
			grpc["serviceName"] = cfg.ServiceName
		}
		if cfg.Mode == "multi" {
			grpc["multiMode"] = true
		}
		stream["grpcSettings"] = grpc
	case "xhttp":
		xh := map[string]interface{}{}
		if cfg.Path != "" {
			xh["path"] = cfg.Path
		}
		if cfg.Host != "" {
			xh["host"] = cfg.Host
		}
		if cfg.Mode != "" {
			xh["mode"] = cfg.Mode
		} else {
			xh["mode"] = "auto"
		}
		stream["xhttpSettings"] = xh
	case "httpupgrade":
		hu := map[string]interface{}{}
		if cfg.Path != "" {
			hu["path"] = cfg.Path
		}
		if cfg.Host != "" {
			hu["host"] = cfg.Host
		}
		stream["httpupgradeSettings"] = hu
	}

	return stream
}

func firstNonEmpty(args ...string) string {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}
