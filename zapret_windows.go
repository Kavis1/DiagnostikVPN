//go:build windows

package main

import (
	"archive/zip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Интеграция со внешним zapret-win-bundle (winws.exe + WinDivert).
//
// Поведение:
//   1) Ищем winws.exe в:
//      - ./zapret/winws.exe
//      - ./zapret-winws/winws.exe
//      - ./winws.exe
//      - %PATH%
//   2) Если не нашли — можем (опционально) скачать с GitHub master в ./zapret-winws/.
//   3) Запускаем с одной из проверенных стратегий для России.
//   4) Делаем повторные TLS-probe для нод которые ранее упали.
//   5) Останавливаем winws, фиксируем результат в отчёте.
//
// ВНИМАНИЕ: winws.exe требует прав администратора для работы WinDivert.

const (
	zapretBaseRaw = "https://raw.githubusercontent.com/bol-van/zapret-win-bundle/master/zapret-winws/"
	zapretDir     = "zapret-winws"
)

var zapretFiles = []string{
	"winws.exe",
	"WinDivert.dll",
	"WinDivert64.sys",
	"cygwin1.dll",
}

// Базовые стратегии — упорядочены от легкой к агрессивной. Это проверенные
// конфиги из официального readme и сообщества.
var zapretStrategies = []struct {
	name string
	args []string
}{
	{
		name: "split2 (фрагментация ClientHello)",
		args: []string{
			"--wf-tcp=443",
			"--dpi-desync=split2",
			"--dpi-desync-split-pos=1",
			"--dpi-desync-split-seqovl=652",
		},
	},
	{
		name: "fake (вставка fake-пакета перед ClientHello)",
		args: []string{
			"--wf-tcp=443",
			"--dpi-desync=fake",
			"--dpi-desync-ttl=4",
			"--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com",
		},
	},
	{
		name: "fakedsplit (fake + split)",
		args: []string{
			"--wf-tcp=443",
			"--dpi-desync=fakedsplit",
			"--dpi-desync-split-pos=1",
			"--dpi-desync-ttl=4",
		},
	},
}

// runZapretRetests запускается ПОСЛЕ основных тестов. Принимает список
// конфигов, для которых TLS-handshake / TCP-connect упал в обычном режиме,
// и пытается достучаться до них через zapret.
func runZapretRetests(failedConfigs []*VPNConfig, autoDownload bool) []TestResult {
	if len(failedConfigs) == 0 {
		return nil
	}

	var results []TestResult

	winws := locateWinws()
	if winws == "" {
		if !autoDownload {
			results = append(results, TestResult{
				Name:   "Zapret (DPI bypass)",
				Status: StatusInfo,
				Message: "winws.exe не найден локально, автоскачивание отключено — пропускаю retest",
				Details: "Чтобы включить retest через zapret: положите winws.exe в ./zapret-winws/ " +
					"(скачать https://github.com/bol-van/zapret-win-bundle ) или запустите программу с флагом --download-zapret.",
			})
			return results
		}
		// Пытаемся скачать
		if err := downloadZapret(zapretDir); err != nil {
			results = append(results, TestResult{
				Name:    "Zapret (DPI bypass)",
				Status:  StatusError,
				Message: fmt.Sprintf("не удалось скачать zapret-win-bundle: %v", err),
				Details: "Возможно провайдер блокирует raw.githubusercontent.com. Скачайте вручную: https://github.com/bol-van/zapret-win-bundle",
			})
			return results
		}
		winws = filepath.Join(zapretDir, "winws.exe")
	}

	results = append(results, TestResult{
		Name:    "Zapret (DPI bypass)",
		Status:  StatusInfo,
		Message: fmt.Sprintf("найден winws: %s — запускаю retest для %d ноды(нод)", winws, len(failedConfigs)),
	})

	for _, strat := range zapretStrategies {
		cmd, err := startWinws(winws, strat.args)
		if err != nil {
			results = append(results, TestResult{
				Name:    fmt.Sprintf("Zapret [%s]", strat.name),
				Status:  StatusWarning,
				Message: fmt.Sprintf("не удалось запустить winws: %v", err),
				Details: "Чаще всего это значит что нет прав администратора или WinDivert не загрузился.",
			})
			continue
		}

		// Дадим winws подняться
		time.Sleep(2 * time.Second)

		anySuccess := false
		var perCfg []string
		var helpedCfgs []*VPNConfig
		for _, cfg := range failedConfigs {
			ok, lat := zapretTLSProbe(cfg)
			status := "FAIL"
			if ok {
				status = "OK"
				anySuccess = true
				helpedCfgs = append(helpedCfgs, cfg)
			}
			perCfg = append(perCfg, fmt.Sprintf("  %s [%s:%d] -> %s (%v)",
				status, cfg.Address, cfg.Port,
				stratLabel(strat.name), lat.Round(time.Millisecond)))
		}

		// Если winws помог хотя бы одному ключу — для каждого такого ключа
		// прогоняем реальный тест сайтов прямо сейчас (winws ещё работает).
		var siteRetests []string
		if anySuccess {
			for _, cfg := range helpedCfgs {
				// При retest через winws — поднимаем правильный backend заново.
				sbR, _ := newProxyBackend(cfg)
				sitesOK := 0
				siteResults := testKeyAgainstSites(cfg, CommonSites, sbR)
				for _, sr := range siteResults {
					if sr.Reachable {
						sitesOK++
					}
				}
				if sbR != nil {
					sbR.Stop()
				}
				siteRetests = append(siteRetests, fmt.Sprintf(
					"  %s — %d/%d сайтов через winws+%s",
					cfg.Address, sitesOK, len(CommonSites), stratLabel(strat.name)))
			}
		}

		_ = stopWinws(cmd)

		status := StatusWarning
		msg := fmt.Sprintf("[%s] ни одна нода не заработала", strat.name)
		if anySuccess {
			status = StatusOK
			msg = fmt.Sprintf("[%s] стратегия помогла хотя бы для 1 ноды — рекомендуется использовать!", strat.name)
		}
		details := "Аргументы: " + strings.Join(strat.args, " ") + "\nTLS-handshake по нодам:\n" + strings.Join(perCfg, "\n")
		if len(siteRetests) > 0 {
			details += "\n\nРеальные сайты через эту стратегию:\n" + strings.Join(siteRetests, "\n")
		}
		details += "\n\nКомандная строка для запуска winws с этой стратегией:\n  winws.exe " + strings.Join(strat.args, " ")
		results = append(results, TestResult{
			Name:    fmt.Sprintf("Zapret [%s]", strat.name),
			Status:  status,
			Message: msg,
			Details: details,
		})

		if anySuccess {
			// Не имеет смысла гонять более агрессивные стратегии — первая сработала.
			break
		}
	}

	return results
}

func stratLabel(s string) string {
	if i := strings.Index(s, " "); i > 0 {
		return s[:i]
	}
	return s
}

// zapretTLSProbe делает TLS-handshake через системный стек — winws перехватит
// трафик через WinDivert и применит стратегию (split/fake).
func zapretTLSProbe(cfg *VPNConfig) (bool, time.Duration) {
	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Address
	}
	start := time.Now()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // диагностика — проверяем именно handshake
		MinVersion:         tls.VersionTLS12,
	})
	elapsed := time.Since(start)
	if err != nil {
		return false, elapsed
	}
	conn.Close()
	return true, elapsed
}

func locateWinws() string {
	candidates := []string{
		filepath.Join("zapret-winws", "winws.exe"),
		filepath.Join("zapret", "winws.exe"),
		"winws.exe",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	// Проверим PATH
	if p, err := exec.LookPath("winws.exe"); err == nil {
		return p
	}
	return ""
}

func startWinws(path string, args []string) (*exec.Cmd, error) {
	cmd := exec.Command(path, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func stopWinws(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Kill()
	_, err := cmd.Process.Wait()
	// Cleanup на всякий — отдельно убиваем winws.exe
	_ = exec.Command("taskkill", "/F", "/IM", "winws.exe").Run()
	return err
}

// downloadZapret тянет минимальный набор файлов с raw.githubusercontent
// прямо в указанную папку. Не использует zip — берём отдельные файлы по списку.
func downloadZapret(dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	client := &http.Client{Timeout: 60 * time.Second}
	for _, f := range zapretFiles {
		url := zapretBaseRaw + f
		dst := filepath.Join(dest, f)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		req, _ := http.NewRequest("GET", url, nil)
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("download %s: %w", f, err)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return fmt.Errorf("download %s: HTTP %d", f, resp.StatusCode)
		}
		out, err := os.Create(dst)
		if err != nil {
			resp.Body.Close()
			return err
		}
		if _, err := io.Copy(out, resp.Body); err != nil {
			out.Close()
			resp.Body.Close()
			return err
		}
		out.Close()
		resp.Body.Close()
	}
	return nil
}

// unzipFile — utility если бы скачивали zip-релиз (на будущее).
func unzipFile(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, f.Mode())
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
