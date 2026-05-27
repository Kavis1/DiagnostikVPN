package main

import (
	"runtime"
)

// Cross-OS константы. Часть из них зависит от GOOS/GOARCH и заполняется
// в platform_windows.go / platform_darwin.go.
//
// Логика разделения:
//   - platform.go (этот файл) — то что зависит только от runtime.GOOS/GOARCH
//     и работает в Go cross-compile (URL'ы скачки, имена бинарников).
//   - platform_windows.go / platform_darwin.go — то что есть только на одной
//     системе и компилируется build-тагом.

// binaryExt — расширение для исполняемых файлов sing-box / xray / winws.
func binaryExt() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// singBoxAssetSuffix — что искать в названии релиза sing-box.
// Например "windows-amd64.zip" / "darwin-amd64.tar.gz" / "darwin-arm64.tar.gz".
func singBoxAssetSuffix() string {
	arch := runtime.GOARCH
	switch runtime.GOOS {
	case "windows":
		return "windows-" + arch + ".zip"
	case "darwin":
		return "darwin-" + arch + ".tar.gz"
	case "linux":
		return "linux-" + arch + ".tar.gz"
	}
	return ""
}

// xrayAssetName — название артефакта xray-core для текущей OS/архитектуры.
// Xray использует свои подписи: 64 для amd64, arm64-v8a для arm64.
func xrayAssetName() string {
	switch runtime.GOOS + "-" + runtime.GOARCH {
	case "windows-amd64":
		return "Xray-windows-64.zip"
	case "windows-arm64":
		return "Xray-windows-arm64-v8a.zip"
	case "darwin-amd64":
		return "Xray-macos-64.zip"
	case "darwin-arm64":
		return "Xray-macos-arm64-v8a.zip"
	case "linux-amd64":
		return "Xray-linux-64.zip"
	case "linux-arm64":
		return "Xray-linux-arm64-v8a.zip"
	}
	return ""
}

// isWindows / isDarwin / isLinux — удобные шорткаты.
func isWindows() bool { return runtime.GOOS == "windows" }
func isDarwin() bool  { return runtime.GOOS == "darwin" }
