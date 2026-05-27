package main

import (
	"fmt"
	"net"
	"strings"
)

// ProxyBackend — абстракция над локальным процессом, который превращает
// один VPN-конфиг в локальный SOCKS5-прокси.
//
// Сейчас реализаций две:
//   - *SingBoxProxy — для всего кроме xhttp transport
//   - *XrayProxy    — для xhttp transport (sing-box не имеет нативной поддержки xhttp)
type ProxyBackend interface {
	Dial(host string, port int) (net.Conn, error)
	Stop()
	SocksAddr() string
	BackendName() string
	StderrTail(n int) string
}

// newProxyBackend выбирает правильный движок под конфиг и поднимает процесс.
// Возврат:
//   - ProxyBackend готовый к Dial
//   - error с детализацией если ни один движок не подошёл
func newProxyBackend(cfg *VPNConfig) (ProxyBackend, error) {
	if strings.EqualFold(cfg.Transport, "xhttp") {
		// xhttp идёт только через xray-core
		xp, err := newXrayProxy(cfg)
		if err != nil {
			return nil, fmt.Errorf("xray-core (для xhttp): %w", err)
		}
		return xp, nil
	}

	// Всё остальное — sing-box (точная поддержка Reality+Vision, gRPC, WS, SS-2022, VMess)
	sb, err := newSingBoxProxy(cfg)
	if err != nil {
		return nil, fmt.Errorf("sing-box: %w", err)
	}
	return sb, nil
}

// Адаптеры существующих типов под интерфейс ProxyBackend.

func (p *SingBoxProxy) SocksAddr() string  { return p.socksAddr }
func (p *SingBoxProxy) BackendName() string { return "sing-box" }
