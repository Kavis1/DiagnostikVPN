//go:build darwin

package main

// zapret (winws.exe + WinDivert) — Windows-only DPI-bypass решение.
// На macOS аналог — byedpi или прямая поддержка fragmentation в клиенте
// (Hiddify Next, NekoBox умеют). Реализовывать интеграцию с byedpi
// не стоит — пользователю проще включить fragmentation в самом клиенте.

func runZapretRetests(failedConfigs []*VPNConfig, autoDownload bool) []TestResult {
	if len(failedConfigs) == 0 {
		return nil
	}
	return []TestResult{{
		Name:    "Zapret (DPI bypass)",
		Status:  StatusInfo,
		Message: "winws/zapret — Windows-only. На macOS используйте встроенную TLS fragmentation в Hiddify Next / NekoBox / FoXray.",
	}}
}
