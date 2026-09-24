package meowcaller

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/sctp"
	"github.com/rs/zerolog"
)

// startSilentRelay accepts the media stack on loopback and never sends anything.
func startSilentRelay(t *testing.T) *net.UDPAddr {
	t.Helper()
	cert, err := selfsign.GenerateSelfSignedWithDNS("relay")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := dtls.Listen("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &dtls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		assoc, err := sctp.Server(sctp.Config{NetConn: conn, LoggerFactory: logging.NewDefaultLoggerFactory()})
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = assoc.Close() })
	}()
	return listener.Addr().(*net.UDPAddr)
}

func TestRunMediaReturnsOnCancelWhenRelayIsSilent(t *testing.T) {
	relayAddr := startSilentRelay(t)
	callKey := make([]byte, 32)
	_, _ = rand.Read(callKey)
	rd := &relayData{
		relayKeyASCII: []byte("relay-key"),
		relayTokens:   [][]byte{[]byte("relay-token")},
		endpoints: []relayEndpoint{{
			relayName: "loopback",
			addresses: []relayAddress{{ipv4: "127.0.0.1", port: uint16(relayAddr.Port)}},
		}},
	}
	eng := &engine{c: &Client{log: zerolog.Nop()}, calls: map[string]*engineCall{
		"CALLID": {selfLID: "1@lid", peerLID: "2@lid"},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- eng.runMedia(ctx, "CALLID", nil, callKey, "1@lid", "2@lid", rd, false)
	}()
	select {
	case err := <-done:
		t.Fatalf("runMedia ended before the call was cancelled: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runMedia still blocked in relay recv 5 s after the call was cancelled")
	}
}
