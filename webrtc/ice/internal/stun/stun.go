// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package stun

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/amarnathcjd/gortc/webrtc/stun"
)

var (
	errGetXorMappedAddrResponse = errors.New("failed to get XOR-MAPPED-ADDRESS response")
	errMismatchUsername         = errors.New("username mismatch")
)

func GetXORMappedAddr(conn net.PacketConn, serverAddr net.Addr, timeout time.Duration) (*stun.XORMappedAddress, error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}

		defer conn.SetReadDeadline(time.Time{})
	}

	req, err := stun.Build(stun.BindingRequest, stun.TransactionID)
	if err != nil {
		return nil, err
	}

	if _, err = conn.WriteTo(req.Raw, serverAddr); err != nil {
		return nil, err
	}

	const maxMessageSize = 1280
	buf := make([]byte, maxMessageSize)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	res := &stun.Message{Raw: buf[:n]}
	if err = res.Decode(); err != nil {
		return nil, err
	}

	var addr stun.XORMappedAddress
	if err = addr.GetFrom(res); err != nil {
		return nil, fmt.Errorf("%w: %v", errGetXorMappedAddrResponse, err)
	}

	return &addr, nil
}

func AssertUsername(m *stun.Message, expectedUsername string) error {
	var username stun.Username
	if err := username.GetFrom(m); err != nil {
		return err
	} else if string(username) != expectedUsername {
		return fmt.Errorf("%w expected(%x) actual(%x)", errMismatchUsername, expectedUsername, string(username))
	}

	return nil
}
