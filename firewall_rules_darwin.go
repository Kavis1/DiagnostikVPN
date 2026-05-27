//go:build darwin

package main

// Stub'ы для macOS. На macOS нет аналога Windows Firewall outbound block
// rules + AppLocker — там работают pfctl (нужен sudo) и встроенный
// Application Firewall (см. interference_darwin.go).

func checkOutboundBlockRules() TestResult {
	return TestResult{
		Name:    "Outbound-блокировки Firewall",
		Status:  StatusInfo,
		Message: "проверка outbound-rules применима только к Windows Firewall — пропущено",
	}
}

func checkAppRestrictions() TestResult {
	return TestResult{
		Name:    "Ограничения запуска приложений",
		Status:  StatusInfo,
		Message: "проверка SmartScreen/AppLocker применима только к Windows — пропущено",
	}
}
