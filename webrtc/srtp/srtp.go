// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package srtp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"github.com/amarnathcjd/gortc/webrtc/logging"
	"github.com/amarnathcjd/gortc/webrtc/rtcp"
	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"github.com/amarnathcjd/gortc/webrtc/transport"
	"net"
	"slices"
	"sync"
	"time"
	"unsafe"
)

const (
	labelSRTPEncryption        = 0x00
	labelSRTPAuthenticationTag = 0x01
	labelSRTPSalt              = 0x02

	labelSRTCPEncryption        = 0x03
	labelSRTCPAuthenticationTag = 0x04
	labelSRTCPSalt              = 0x05

	maxSequenceNumber = 65535
	maxROC            = (1 << 32) - 1

	seqNumMedian = 1 << 15
	seqNumMax    = 1 << 16
)

type srtpSSRCState struct {
	ssrc                 uint32
	rolloverHasProcessed bool
	index                uint64
	replayDetector       transport.ReplayDetector
}

type srtcpSSRCState struct {
	srtcpIndex     uint32
	ssrc           uint32
	replayDetector transport.ReplayDetector
}

type RCCMode int

const (
	RCCModeNone RCCMode = iota

	RCCMode1

	RCCMode2

	RCCMode3
)

type CryptexMode int

const (
	CryptexModeDisabled CryptexMode = 0

	CryptexModeEnabled CryptexMode = 1

	CryptexModeRequired CryptexMode = 2
)

type Context struct {
	cipher                 srtpCipher
	srtpSSRCStates         map[uint32]*srtpSSRCState
	srtcpSSRCStates        map[uint32]*srtcpSSRCState
	newSRTCPReplayDetector func() transport.ReplayDetector
	newSRTPReplayDetector  func() transport.ReplayDetector
	profile                ProtectionProfile
	sendMKI                []byte
	mkis                   map[string]srtpCipher
	encryptSRTP            bool
	encryptSRTCP           bool
	rccMode                RCCMode
	rocTransmitRate        uint16
	authTagRTPLen          *int
	cryptexMode            CryptexMode
}

func CreateContext(
	masterKey, masterSalt []byte,
	profile ProtectionProfile,
	opts ...ContextOption,
) (c *Context, err error) {
	c = &Context{
		srtpSSRCStates:  map[uint32]*srtpSSRCState{},
		srtcpSSRCStates: map[uint32]*srtcpSSRCState{},
		profile:         profile,
		mkis:            map[string]srtpCipher{},
	}

	for _, o := range append(
		[]ContextOption{
			SRTPNoReplayProtection(),
			SRTCPNoReplayProtection(),
			SRTPEncryption(),
			SRTCPEncryption(),
		},
		opts...,
	) {
		if errOpt := o(c); errOpt != nil {
			return nil, errOpt
		}
	}

	if err = c.checkRCCMode(); err != nil {
		return nil, err
	}

	if c.authTagRTPLen != nil {
		var authKeyLen int
		authKeyLen, err = c.profile.AuthKeyLen()
		if err != nil {
			return nil, err
		}
		if *c.authTagRTPLen > authKeyLen {
			return nil, errTooLongSRTPAuthTag
		}
	}

	c.cipher, err = c.createCipher(c.sendMKI, masterKey, masterSalt, c.encryptSRTP, c.encryptSRTCP)
	if err != nil {
		return nil, err
	}
	if len(c.sendMKI) != 0 {
		c.mkis[string(c.sendMKI)] = c.cipher
	}

	return c, nil
}

func (c *Context) AddCipherForMKI(mki, masterKey, masterSalt []byte) error {
	if len(c.mkis) == 0 {
		return errMKIIsNotEnabled
	}
	if len(mki) == 0 || len(mki) != len(c.sendMKI) {
		return errInvalidMKILength
	}
	if _, ok := c.mkis[string(mki)]; ok {
		return errMKIAlreadyInUse
	}

	cipher, err := c.createCipher(mki, masterKey, masterSalt, c.encryptSRTP, c.encryptSRTCP)
	if err != nil {
		return err
	}
	c.mkis[string(mki)] = cipher

	return nil
}

func (c *Context) createCipher(mki, masterKey, masterSalt []byte, encryptSRTP, encryptSRTCP bool) (srtpCipher, error) {
	keyLen, err := c.profile.KeyLen()
	if err != nil {
		return nil, err
	}

	saltLen, err := c.profile.SaltLen()
	if err != nil {
		return nil, err
	}

	if masterKeyLen := len(masterKey); masterKeyLen != keyLen {
		return nil, fmt.Errorf("%w expected(%d) actual(%d)", errShortSrtpMasterKey, keyLen, masterKey)
	} else if masterSaltLen := len(masterSalt); masterSaltLen != saltLen {
		return nil, fmt.Errorf("%w expected(%d) actual(%d)", errShortSrtpMasterSalt, saltLen, masterSaltLen)
	}

	profileWithArgs := protectionProfileWithArgs{
		ProtectionProfile: c.profile,
		authTagRTPLen:     c.authTagRTPLen,
	}

	useCryptex := c.cryptexMode != CryptexModeDisabled && encryptSRTP
	switch c.profile {
	case ProtectionProfileAeadAes128Gcm, ProtectionProfileAeadAes256Gcm:
		return newSrtpCipherAeadAesGcm(profileWithArgs, masterKey, masterSalt, mki, encryptSRTP, encryptSRTCP, useCryptex)
	case ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80:
		return newSrtpCipherAesCmHmacSha1(profileWithArgs, masterKey, masterSalt, mki, encryptSRTP, encryptSRTCP, useCryptex)
	case ProtectionProfileNullHmacSha1_32, ProtectionProfileNullHmacSha1_80:
		return newSrtpCipherAesCmHmacSha1(profileWithArgs, masterKey, masterSalt, mki, false, false, false)
	default:
		return nil, fmt.Errorf("%w: %#v", errNoSuchSRTPProfile, c.profile)
	}
}

func (c *Context) RemoveMKI(mki []byte) error {
	if _, ok := c.mkis[string(mki)]; !ok {
		return ErrMKINotFound
	}
	if bytes.Equal(mki, c.sendMKI) {
		return errMKIAlreadyInUse
	}
	delete(c.mkis, string(mki))

	return nil
}

func (c *Context) SetSendMKI(mki []byte) error {
	cipher, ok := c.mkis[string(mki)]
	if !ok {
		return ErrMKINotFound
	}
	c.sendMKI = mki
	c.cipher = cipher

	return nil
}

func (s *srtpSSRCState) nextRolloverCount(sequenceNumber uint16) (roc uint32, diff int64, overflow bool) {
	seq := int32(sequenceNumber)
	localRoc := uint32(s.index >> 16)
	localSeq := int32(s.index & (seqNumMax - 1))

	guessRoc := localRoc
	var difference int32

	if s.rolloverHasProcessed {

		if s.index > seqNumMedian {
			if localSeq < seqNumMedian {
				if seq-localSeq > seqNumMedian {
					guessRoc = localRoc - 1
					difference = seq - localSeq - seqNumMax
				} else {
					guessRoc = localRoc
					difference = seq - localSeq
				}
			} else {
				if localSeq-seqNumMedian > seq {
					guessRoc = localRoc + 1
					difference = seq - localSeq + seqNumMax
				} else {
					guessRoc = localRoc
					difference = seq - localSeq
				}
			}
		} else {

			difference = seq - localSeq
		}
	}

	return guessRoc, int64(difference), (guessRoc == 0 && localRoc == maxROC)
}

func (s *srtpSSRCState) updateRolloverCount(sequenceNumber uint16, difference int64, hasRemoteRoc bool,
	remoteRoc uint32,
) {
	switch {
	case hasRemoteRoc:
		s.index = (uint64(remoteRoc) << 16) | uint64(sequenceNumber)
		s.rolloverHasProcessed = true
	case !s.rolloverHasProcessed:
		s.index |= uint64(sequenceNumber)
		s.rolloverHasProcessed = true
	case difference > 0:
		s.index += uint64(difference)
	}
}

func (c *Context) getSRTPSSRCState(ssrc uint32) *srtpSSRCState {
	s, ok := c.srtpSSRCStates[ssrc]
	if ok {
		return s
	}

	s = &srtpSSRCState{
		ssrc:           ssrc,
		replayDetector: c.newSRTPReplayDetector(),
	}
	c.srtpSSRCStates[ssrc] = s

	return s
}

func (c *Context) getSRTCPSSRCState(ssrc uint32) *srtcpSSRCState {
	s, ok := c.srtcpSSRCStates[ssrc]
	if ok {
		return s
	}

	s = &srtcpSSRCState{
		ssrc:           ssrc,
		replayDetector: c.newSRTCPReplayDetector(),
	}
	c.srtcpSSRCStates[ssrc] = s

	return s
}

func (c *Context) ROC(ssrc uint32) (uint32, bool) {
	s, ok := c.srtpSSRCStates[ssrc]
	if !ok {
		return 0, false
	}

	return uint32(s.index >> 16), true
}

func (c *Context) SetROC(ssrc uint32, roc uint32) {
	s := c.getSRTPSSRCState(ssrc)
	s.index = uint64(roc) << 16
	s.rolloverHasProcessed = false
}

func (c *Context) Index(ssrc uint32) (uint32, bool) {
	s, ok := c.srtcpSSRCStates[ssrc]
	if !ok {
		return 0, false
	}

	return s.srtcpIndex, true
}

func (c *Context) SetIndex(ssrc uint32, index uint32) {
	s := c.getSRTCPSSRCState(ssrc)
	s.srtcpIndex = index % (maxSRTCPIndex + 1)
}

func (c *Context) checkRCCMode() error {
	if c.rccMode == RCCModeNone {
		return nil
	}

	if c.rocTransmitRate == 0 {
		return errZeroRocTransmitRate
	}

	switch c.profile {
	case ProtectionProfileAeadAes128Gcm, ProtectionProfileAeadAes256Gcm:

		if c.rccMode != RCCMode3 {
			return errUnsupportedRccMode
		}

	case ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileNullHmacSha1_32:
		if c.authTagRTPLen == nil {

			return errTooShortSRTPAuthTag
		}

		fallthrough

	case ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileNullHmacSha1_80:

		if c.rccMode != RCCMode2 {
			return errUnsupportedRccMode
		}
		if c.authTagRTPLen != nil && *c.authTagRTPLen < 4 {
			return errTooShortSRTPAuthTag
		}

	default:
		return errUnsupportedRccMode
	}

	return nil
}

func incrementCTR(ctr []byte) {
	for i := len(ctr) - 1; i >= 0; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
	}
}

const xorBufferSize = 32

var xorBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, xorBufferSize)
	},
}

func xorBytesCTR(block cipher.Block, iv []byte, dst, src []byte) error {
	if len(iv) != block.BlockSize() || (len(iv)+block.BlockSize()) > xorBufferSize {
		return errBadIVLength
	}

	xorBuf := xorBufferPool.Get()
	defer xorBufferPool.Put(xorBuf)
	buffer, ok := xorBuf.([]byte)
	if !ok {
		return errFailedTypeAssertion
	}

	ctr := buffer[:len(iv)]
	copy(ctr, iv)
	bs := block.BlockSize()
	stream := buffer[len(iv) : len(iv)+bs]

	i := 0
	for i < len(src) {
		block.Encrypt(stream, ctr)
		incrementCTR(ctr)
		n := transport.XorBytes(dst[i:], src[i:], stream)
		if n == 0 {
			break
		}
		i += n
	}

	return nil
}

var (
	ErrFailedToVerifyAuthTag = errors.New("failed to verify auth tag")

	ErrMKINotFound = errors.New("MKI not found")

	errDuplicated                    = errors.New("duplicated packet")
	errShortSrtpMasterKey            = errors.New("SRTP master key is not long enough")
	errShortSrtpMasterSalt           = errors.New("SRTP master salt is not long enough")
	errNoSuchSRTPProfile             = errors.New("no such SRTP Profile")
	errNonZeroKDRNotSupported        = errors.New("indexOverKdr > 0 is not supported yet")
	errNoConfig                      = errors.New("no config provided")
	errNoConn                        = errors.New("no conn provided")
	errTooShortRTP                   = errors.New("packet is too short to be RTP packet")
	errTooShortRTCP                  = errors.New("packet is too short to be RTCP packet")
	errStartedChannelUsedIncorrectly = errors.New("started channel used incorrectly, should only be closed")
	errBadIVLength                   = errors.New("bad iv length in xorBytesCTR")
	errExceededMaxPackets            = errors.New("exceeded the maximum number of packets")
	errMKIAlreadyInUse               = errors.New("MKI already in use")
	errMKIIsNotEnabled               = errors.New("MKI is not enabled")
	errInvalidMKILength              = errors.New("invalid MKI length")
	errTooLongSRTPAuthTag            = errors.New("SRTP auth tag is too long")
	errTooShortSRTPAuthTag           = errors.New("SRTP auth tag is too short")

	errStreamNotInited     = errors.New("stream has not been inited, unable to close")
	errStreamAlreadyClosed = errors.New("stream is already closed")
	errStreamAlreadyInited = errors.New("stream is already inited")
	errFailedTypeAssertion = errors.New("failed to cast child")

	errZeroRocTransmitRate = errors.New("ROC transmit rate is zero")
	errUnsupportedRccMode  = errors.New("unsupported RCC mode")

	errUnsupportedHeaderExtension   = errors.New("unsupported header extension")
	errHeaderLengthMismatch         = errors.New("header length mismatch")
	errUnencryptedHeaderExtAndCSRCs = errors.New("unencrypted header extensions and CSRCs are not allowed")
	errCryptexDisabled              = errors.New("cryptex is disabled")
)

type duplicatedError struct {
	Proto string
	SSRC  uint32
	Index uint32
}

func (e *duplicatedError) Error() string {
	return fmt.Sprintf("%s ssrc=%d index=%d: %v", e.Proto, e.SSRC, e.Index, errDuplicated)
}

func (e *duplicatedError) Unwrap() error {
	return errDuplicated
}

func aesCmKeyDerivation(label byte, masterKey, masterSalt []byte, indexOverKdr int, outLen int) ([]byte, error) {
	if indexOverKdr != 0 {

		return nil, errNonZeroKDRNotSupported
	}

	nMasterSalt := len(masterSalt)

	prfIn := make([]byte, 16)
	copy(prfIn[:nMasterSalt], masterSalt)

	prfIn[7] ^= label

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	nBlockSize := block.BlockSize()
	out := make([]byte, ((outLen+nBlockSize-1)/nBlockSize)*nBlockSize)
	var i uint16
	for n := 0; n < outLen; n += nBlockSize {
		binary.BigEndian.PutUint16(prfIn[len(prfIn)-2:], i)
		block.Encrypt(out[n:n+nBlockSize], prfIn)
		i++
	}

	return out[:outLen], nil
}

func generateCounter(
	sequenceNumber uint16,
	rolloverCounter uint32,
	ssrc uint32, sessionSalt []byte,
) (counter [16]byte) {
	copy(counter[:], sessionSalt)

	counter[4] ^= byte(ssrc >> 24)
	counter[5] ^= byte(ssrc >> 16)
	counter[6] ^= byte(ssrc >> 8)
	counter[7] ^= byte(ssrc)
	counter[8] ^= byte(rolloverCounter >> 24)
	counter[9] ^= byte(rolloverCounter >> 16)
	counter[10] ^= byte(rolloverCounter >> 8)
	counter[11] ^= byte(rolloverCounter)
	counter[12] ^= byte(sequenceNumber >> 8)
	counter[13] ^= byte(sequenceNumber)

	return counter
}

const labelExtractorDtlsSrtp = "EXTRACTOR-dtls_srtp"

type KeyingMaterialExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

func (c *Config) ExtractSessionKeysFromDTLS(exporter KeyingMaterialExporter, isClient bool) error {
	keyLen, err := c.Profile.KeyLen()
	if err != nil {
		return err
	}

	saltLen, err := c.Profile.SaltLen()
	if err != nil {
		return err
	}

	keyingMaterial, err := exporter.ExportKeyingMaterial(labelExtractorDtlsSrtp, nil, (keyLen*2)+(saltLen*2))
	if err != nil {
		return err
	}

	offset := 0
	clientWriteKey := append([]byte{}, keyingMaterial[offset:offset+keyLen]...)
	offset += keyLen

	serverWriteKey := append([]byte{}, keyingMaterial[offset:offset+keyLen]...)
	offset += keyLen

	clientWriteKey = append(clientWriteKey, keyingMaterial[offset:offset+saltLen]...)
	offset += saltLen

	serverWriteKey = append(serverWriteKey, keyingMaterial[offset:offset+saltLen]...)

	if isClient {
		c.Keys.LocalMasterKey = clientWriteKey[0:keyLen]
		c.Keys.LocalMasterSalt = clientWriteKey[keyLen:]
		c.Keys.RemoteMasterKey = serverWriteKey[0:keyLen]
		c.Keys.RemoteMasterSalt = serverWriteKey[keyLen:]

		return nil
	}

	c.Keys.LocalMasterKey = serverWriteKey[0:keyLen]
	c.Keys.LocalMasterSalt = serverWriteKey[keyLen:]
	c.Keys.RemoteMasterKey = clientWriteKey[0:keyLen]
	c.Keys.RemoteMasterSalt = clientWriteKey[keyLen:]

	return nil
}

type ContextOption func(*Context) error

func SRTPReplayProtection(windowSize uint) ContextOption {
	return func(c *Context) error {
		c.newSRTPReplayDetector = func() transport.ReplayDetector {
			return transport.NewReplayDetector(windowSize, maxROC<<16|maxSequenceNumber)
		}

		return nil
	}
}

func SRTCPReplayProtection(windowSize uint) ContextOption {
	return func(c *Context) error {
		c.newSRTCPReplayDetector = func() transport.ReplayDetector {
			return transport.NewReplayDetector(windowSize, maxSRTCPIndex)
		}

		return nil
	}
}

func SRTPNoReplayProtection() ContextOption {
	return func(c *Context) error {
		c.newSRTPReplayDetector = func() transport.ReplayDetector {
			return &nopReplayDetector{}
		}

		return nil
	}
}

func SRTCPNoReplayProtection() ContextOption {
	return func(c *Context) error {
		c.newSRTCPReplayDetector = func() transport.ReplayDetector {
			return &nopReplayDetector{}
		}

		return nil
	}
}

type nopReplayDetector struct{}

func (s *nopReplayDetector) Check(uint64) (func() bool, bool) {
	return func() bool { return true }, true
}

func SRTPEncryption() ContextOption {
	return func(c *Context) error {
		c.encryptSRTP = true

		return nil
	}
}

func SRTCPEncryption() ContextOption {
	return func(c *Context) error {
		c.encryptSRTCP = true

		return nil
	}
}

type ProtectionProfile uint16

const (
	ProtectionProfileAes128CmHmacSha1_80 ProtectionProfile = 0x0001
	ProtectionProfileAes128CmHmacSha1_32 ProtectionProfile = 0x0002
	ProtectionProfileAes256CmHmacSha1_80 ProtectionProfile = 0x0003
	ProtectionProfileAes256CmHmacSha1_32 ProtectionProfile = 0x0004
	ProtectionProfileNullHmacSha1_80     ProtectionProfile = 0x0005
	ProtectionProfileNullHmacSha1_32     ProtectionProfile = 0x0006
	ProtectionProfileAeadAes128Gcm       ProtectionProfile = 0x0007
	ProtectionProfileAeadAes256Gcm       ProtectionProfile = 0x0008
)

func (p ProtectionProfile) KeyLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileNullHmacSha1_32,
		ProtectionProfileNullHmacSha1_80:
		return 16, nil
	case ProtectionProfileAeadAes256Gcm, ProtectionProfileAes256CmHmacSha1_32, ProtectionProfileAes256CmHmacSha1_80:
		return 32, nil
	default:
		return 0, fmt.Errorf("%w: %#v", errNoSuchSRTPProfile, p)
	}
}

func (p ProtectionProfile) SaltLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileNullHmacSha1_32,
		ProtectionProfileNullHmacSha1_80:
		return 14, nil
	case ProtectionProfileAeadAes128Gcm, ProtectionProfileAeadAes256Gcm:
		return 12, nil
	default:
		return 0, fmt.Errorf("%w: %#v", errNoSuchSRTPProfile, p)
	}
}

func (p ProtectionProfile) AuthTagRTPLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_80, ProtectionProfileAes256CmHmacSha1_80, ProtectionProfileNullHmacSha1_80:
		return 10, nil
	case ProtectionProfileAes128CmHmacSha1_32, ProtectionProfileAes256CmHmacSha1_32, ProtectionProfileNullHmacSha1_32:
		return 4, nil
	case ProtectionProfileAeadAes128Gcm, ProtectionProfileAeadAes256Gcm:
		return 0, nil
	default:
		return 0, fmt.Errorf("%w: %#v", errNoSuchSRTPProfile, p)
	}
}

func (p ProtectionProfile) AuthTagRTCPLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileNullHmacSha1_32,
		ProtectionProfileNullHmacSha1_80:
		return 10, nil
	case ProtectionProfileAeadAes128Gcm, ProtectionProfileAeadAes256Gcm:
		return 0, nil
	default:
		return 0, fmt.Errorf("%w: %#v", errNoSuchSRTPProfile, p)
	}
}

func (p ProtectionProfile) AEADAuthTagLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileNullHmacSha1_32,
		ProtectionProfileNullHmacSha1_80:
		return 0, nil
	case ProtectionProfileAeadAes128Gcm, ProtectionProfileAeadAes256Gcm:
		return 16, nil
	default:
		return 0, fmt.Errorf("%w: %#v", errNoSuchSRTPProfile, p)
	}
}

func (p ProtectionProfile) AuthKeyLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileNullHmacSha1_32,
		ProtectionProfileNullHmacSha1_80:
		return 20, nil
	case ProtectionProfileAeadAes128Gcm, ProtectionProfileAeadAes256Gcm:
		return 0, nil
	default:
		return 0, fmt.Errorf("%w: %#v", errNoSuchSRTPProfile, p)
	}
}

func (p ProtectionProfile) String() string {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_80:
		return "SRTP_AES128_CM_HMAC_SHA1_80"
	case ProtectionProfileAes128CmHmacSha1_32:
		return "SRTP_AES128_CM_HMAC_SHA1_32"
	case ProtectionProfileAes256CmHmacSha1_80:
		return "SRTP_AES256_CM_HMAC_SHA1_80"
	case ProtectionProfileAes256CmHmacSha1_32:
		return "SRTP_AES256_CM_HMAC_SHA1_32"
	case ProtectionProfileAeadAes128Gcm:
		return "SRTP_AEAD_AES_128_GCM"
	case ProtectionProfileAeadAes256Gcm:
		return "SRTP_AEAD_AES_256_GCM"
	case ProtectionProfileNullHmacSha1_80:
		return "SRTP_NULL_HMAC_SHA1_80"
	case ProtectionProfileNullHmacSha1_32:
		return "SRTP_NULL_HMAC_SHA1_32"
	default:
		return fmt.Sprintf("Unknown SRTP profile: %#v", p)
	}
}

type protectionProfileWithArgs struct {
	ProtectionProfile
	authTagRTPLen *int
}

func (p protectionProfileWithArgs) AuthTagRTPLen() (int, error) {
	if p.authTagRTPLen != nil {
		return *p.authTagRTPLen, nil
	}

	return p.ProtectionProfile.AuthTagRTPLen()
}

type streamSession interface {
	Close() error
	write([]byte) (int, error)
	decrypt([]byte) error
}

type session struct {
	localContextMutex           sync.Mutex
	localContext, remoteContext *Context
	localOptions, remoteOptions []ContextOption
	newStream                   chan readStream
	acceptStreamTimeout         time.Time
	started                     chan any
	closed                      chan any
	readStreamsClosed           bool
	readStreams                 map[uint32]readStream
	readStreamsLock             sync.Mutex
	log                         logging.LeveledLogger
	bufferFactory               func(packetType transport.BufferPacketType, ssrc uint32) io.ReadWriteCloser
	nextConn                    net.Conn
}

type Config struct {
	Keys                        SessionKeys
	Profile                     ProtectionProfile
	BufferFactory               func(packetType transport.BufferPacketType, ssrc uint32) io.ReadWriteCloser
	LoggerFactory               logging.LoggerFactory
	AcceptStreamTimeout         time.Time
	LocalOptions, RemoteOptions []ContextOption
}

type SessionKeys struct {
	LocalMasterKey   []byte
	LocalMasterSalt  []byte
	RemoteMasterKey  []byte
	RemoteMasterSalt []byte
}

func (s *session) getOrCreateReadStream(ssrc uint32, child streamSession, proto func() readStream) (readStream, bool) {
	s.readStreamsLock.Lock()
	defer s.readStreamsLock.Unlock()

	if s.readStreamsClosed {
		return nil, false
	}

	rStream, ok := s.readStreams[ssrc]
	if ok {
		return rStream, false
	}

	rStream = proto()

	if err := rStream.init(child, ssrc); err != nil {
		return nil, false
	}

	s.readStreams[ssrc] = rStream

	return rStream, true
}

func (s *session) removeReadStream(ssrc uint32) {
	s.readStreamsLock.Lock()
	defer s.readStreamsLock.Unlock()

	if s.readStreamsClosed {
		return
	}

	delete(s.readStreams, ssrc)
}

func (s *session) close() error {
	if s.nextConn == nil {
		return nil
	} else if err := s.nextConn.Close(); err != nil {
		return err
	}

	<-s.closed

	return nil
}

func (s *session) start(
	localMasterKey, localMasterSalt, remoteMasterKey, remoteMasterSalt []byte,
	profile ProtectionProfile,
	child streamSession,
) error {
	var err error
	s.localContext, err = CreateContext(localMasterKey, localMasterSalt, profile, s.localOptions...)
	if err != nil {
		return err
	}

	s.remoteContext, err = CreateContext(remoteMasterKey, remoteMasterSalt, profile, s.remoteOptions...)
	if err != nil {
		return err
	}

	if err = s.nextConn.SetReadDeadline(s.acceptStreamTimeout); err != nil {
		return err
	}

	go func() {
		defer func() {
			close(s.newStream)

			s.readStreamsLock.Lock()
			s.readStreamsClosed = true
			s.readStreamsLock.Unlock()
			close(s.closed)
		}()

		b := make([]byte, 8192)
		for {
			var i int
			i, err = s.nextConn.Read(b)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					s.log.Error(err.Error())
				}

				return
			}

			if err = child.decrypt(b[:i]); err != nil {
				s.log.Info(err.Error())
			}
		}
	}()

	close(s.started)

	return nil
}

const defaultSessionSRTCPReplayProtectionWindow = 64

type SessionSRTCP struct {
	session
	writeStream *WriteStreamSRTCP
}

func NewSessionSRTCP(conn net.Conn, config *Config) (*SessionSRTCP, error) {
	if config == nil {
		return nil, errNoConfig
	} else if conn == nil {
		return nil, errNoConn
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	localOpts := append(
		[]ContextOption{},
		config.LocalOptions...,
	)
	remoteOpts := append(
		[]ContextOption{

			SRTCPReplayProtection(defaultSessionSRTCPReplayProtectionWindow),
		},
		config.RemoteOptions...,
	)

	srtcpSession := &SessionSRTCP{
		session: session{
			nextConn:            conn,
			localOptions:        localOpts,
			remoteOptions:       remoteOpts,
			readStreams:         map[uint32]readStream{},
			newStream:           make(chan readStream),
			acceptStreamTimeout: config.AcceptStreamTimeout,
			started:             make(chan any),
			closed:              make(chan any),
			bufferFactory:       config.BufferFactory,
			log:                 loggerFactory.NewLogger("srtp"),
		},
	}
	srtcpSession.writeStream = &WriteStreamSRTCP{srtcpSession}

	err := srtcpSession.session.start(
		config.Keys.LocalMasterKey, config.Keys.LocalMasterSalt,
		config.Keys.RemoteMasterKey, config.Keys.RemoteMasterSalt,
		config.Profile,
		srtcpSession,
	)
	if err != nil {
		return nil, err
	}

	return srtcpSession, nil
}

func (s *SessionSRTCP) OpenWriteStream() (*WriteStreamSRTCP, error) {
	return s.writeStream, nil
}

func (s *SessionSRTCP) OpenReadStream(ssrc uint32) (*ReadStreamSRTCP, error) {
	r, _ := s.session.getOrCreateReadStream(ssrc, s, newReadStreamSRTCP)

	if readStream, ok := r.(*ReadStreamSRTCP); ok {
		return readStream, nil
	}

	return nil, errFailedTypeAssertion
}

func (s *SessionSRTCP) AcceptStream() (*ReadStreamSRTCP, uint32, error) {
	stream, ok := <-s.newStream
	if !ok {
		return nil, 0, errStreamAlreadyClosed
	}

	readStream, ok := stream.(*ReadStreamSRTCP)
	if !ok {
		return nil, 0, errFailedTypeAssertion
	}

	return readStream, stream.GetSSRC(), nil
}

func (s *SessionSRTCP) Close() error {
	return s.session.close()
}

func (s *SessionSRTCP) write(buf []byte) (int, error) {
	if _, ok := <-s.session.started; ok {
		return 0, errStartedChannelUsedIncorrectly
	}

	ibuf := bufferpool.Get()
	defer bufferpool.Put(ibuf)

	s.session.localContextMutex.Lock()
	encrypted, err := s.localContext.EncryptRTCP(ibuf.([]byte), buf, nil)
	s.session.localContextMutex.Unlock()

	if err != nil {
		return 0, err
	}

	return s.session.nextConn.Write(encrypted)
}

func (s *SessionSRTCP) setWriteDeadline(t time.Time) error {
	return s.session.nextConn.SetWriteDeadline(t)
}

func destinationSSRC(pkts []rtcp.Packet) []uint32 {
	ssrcSet := make(map[uint32]struct{})
	for _, p := range pkts {
		for _, ssrc := range p.DestinationSSRC() {
			ssrcSet[ssrc] = struct{}{}
		}
	}

	out := make([]uint32, 0, len(ssrcSet))
	for ssrc := range ssrcSet {
		out = append(out, ssrc)
	}

	return out
}

func (s *SessionSRTCP) decrypt(buf []byte) error {
	decrypted, err := s.remoteContext.DecryptRTCP(buf, buf, nil)
	if err != nil {
		return err
	}

	pkt, err := rtcp.Unmarshal(decrypted)
	if err != nil {
		return err
	}

	for _, ssrc := range destinationSSRC(pkt) {
		r, isNew := s.session.getOrCreateReadStream(ssrc, s, newReadStreamSRTCP)
		if r == nil {
			return nil
		} else if isNew {
			if !s.session.acceptStreamTimeout.IsZero() {
				_ = s.session.nextConn.SetReadDeadline(time.Time{})
			}
			s.session.newStream <- r
		}

		readStream, ok := r.(*ReadStreamSRTCP)
		if !ok {
			return errFailedTypeAssertion
		}

		_, err = readStream.write(decrypted)
		if err != nil {
			return err
		}
	}

	return nil
}

const defaultSessionSRTPReplayProtectionWindow = 64

type SessionSRTP struct {
	session
	writeStream *WriteStreamSRTP
}

func NewSessionSRTP(conn net.Conn, config *Config) (*SessionSRTP, error) {
	if config == nil {
		return nil, errNoConfig
	} else if conn == nil {
		return nil, errNoConn
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	localOpts := append(
		[]ContextOption{},
		config.LocalOptions...,
	)
	remoteOpts := append(
		[]ContextOption{

			SRTPReplayProtection(defaultSessionSRTPReplayProtectionWindow),
		},
		config.RemoteOptions...,
	)

	srtpSession := &SessionSRTP{
		session: session{
			nextConn:            conn,
			localOptions:        localOpts,
			remoteOptions:       remoteOpts,
			readStreams:         map[uint32]readStream{},
			newStream:           make(chan readStream),
			acceptStreamTimeout: config.AcceptStreamTimeout,
			started:             make(chan any),
			closed:              make(chan any),
			bufferFactory:       config.BufferFactory,
			log:                 loggerFactory.NewLogger("srtp"),
		},
	}
	srtpSession.writeStream = &WriteStreamSRTP{srtpSession}

	err := srtpSession.session.start(
		config.Keys.LocalMasterKey, config.Keys.LocalMasterSalt,
		config.Keys.RemoteMasterKey, config.Keys.RemoteMasterSalt,
		config.Profile,
		srtpSession,
	)
	if err != nil {
		return nil, err
	}

	return srtpSession, nil
}

func (s *SessionSRTP) OpenWriteStream() (*WriteStreamSRTP, error) {
	return s.writeStream, nil
}

func (s *SessionSRTP) OpenReadStream(ssrc uint32) (*ReadStreamSRTP, error) {
	r, _ := s.session.getOrCreateReadStream(ssrc, s, newReadStreamSRTP)

	if readStream, ok := r.(*ReadStreamSRTP); ok {
		return readStream, nil
	}

	return nil, errFailedTypeAssertion
}

func (s *SessionSRTP) AcceptStream() (*ReadStreamSRTP, uint32, error) {
	stream, ok := <-s.newStream
	if !ok {
		return nil, 0, errStreamAlreadyClosed
	}

	readStream, ok := stream.(*ReadStreamSRTP)
	if !ok {
		return nil, 0, errFailedTypeAssertion
	}

	return readStream, stream.GetSSRC(), nil
}

func (s *SessionSRTP) Close() error {
	return s.session.close()
}

func (s *SessionSRTP) write(b []byte) (int, error) {
	packet := &rtp.Packet{}

	if err := packet.Unmarshal(b); err != nil {
		return 0, err
	}

	return s.writeRTP(&packet.Header, packet.Payload)
}

var bufferpool = sync.Pool{
	New: func() any {
		return make([]byte, 1492)
	},
}

func (s *SessionSRTP) writeRTP(header *rtp.Header, payload []byte) (int, error) {
	if _, ok := <-s.session.started; ok {
		return 0, errStartedChannelUsedIncorrectly
	}

	ibuf := bufferpool.Get()
	defer bufferpool.Put(ibuf)

	buf := ibuf.([]byte)
	headerLen, marshalSize := rtp.HeaderAndPacketMarshalSize(header, payload)
	if len(buf) < marshalSize+20 {

		buf = make([]byte, marshalSize+20)
	}
	_, err := rtp.MarshalPacketTo(buf, header, payload)
	if err != nil {
		return 0, err
	}

	s.session.localContextMutex.Lock()
	encrypted, err := s.localContext.encryptRTP(buf, header, headerLen, buf[:marshalSize])
	s.session.localContextMutex.Unlock()

	if err != nil {
		return 0, err
	}

	return s.session.nextConn.Write(encrypted)
}

func (s *SessionSRTP) setWriteDeadline(t time.Time) error {
	return s.session.nextConn.SetWriteDeadline(t)
}

func (s *SessionSRTP) decrypt(buf []byte) error {
	header := &rtp.Header{}
	headerLen, err := header.Unmarshal(buf)
	if err != nil {
		return err
	}

	r, isNew := s.session.getOrCreateReadStream(header.SSRC, s, newReadStreamSRTP)
	if r == nil {
		return nil
	} else if isNew {
		if !s.session.acceptStreamTimeout.IsZero() {
			_ = s.session.nextConn.SetReadDeadline(time.Time{})
		}
		s.session.newStream <- r
	}

	readStream, ok := r.(*ReadStreamSRTP)
	if !ok {
		return errFailedTypeAssertion
	}

	decrypted, err := s.remoteContext.decryptRTP(buf, buf, header, headerLen)
	if err != nil {
		return err
	}

	_, err = readStream.write(decrypted)
	if err != nil {
		return err
	}

	return nil
}

const (
	maxSRTCPIndex = 0x7FFFFFFF

	srtcpHeaderSize     = 8
	srtcpIndexSize      = 4
	srtcpEncryptionFlag = 0x80
)

func (c *Context) decryptRTCP(dst, encrypted []byte) ([]byte, error) {
	authTagLen, err := c.cipher.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	aeadAuthTagLen, err := c.cipher.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(c.sendMKI)

	if len(encrypted) < (srtcpHeaderSize + aeadAuthTagLen + srtcpIndexSize + mkiLen + authTagLen) {
		return nil, fmt.Errorf("%w: %d", errTooShortRTCP, len(encrypted))
	}

	index := c.cipher.getRTCPIndex(encrypted)
	ssrc := binary.BigEndian.Uint32(encrypted[4:])

	s := c.getSRTCPSSRCState(ssrc)
	markAsValid, ok := s.replayDetector.Check(uint64(index))
	if !ok {
		return nil, &duplicatedError{Proto: "srtcp", SSRC: ssrc, Index: index}
	}

	cipher := c.cipher
	if len(c.mkis) > 0 {

		actualMKI := encrypted[len(encrypted)-mkiLen-authTagLen : len(encrypted)-authTagLen]
		cipher, ok = c.mkis[string(actualMKI)]
		if !ok {
			return nil, ErrMKINotFound
		}
	}

	out, err := cipher.decryptRTCP(dst, encrypted, index, ssrc)
	if err != nil {
		return nil, err
	}

	markAsValid()

	return out, nil
}

func (c *Context) DecryptRTCP(dst, encrypted []byte, header *rtcp.Header) ([]byte, error) {
	if header == nil {
		header = &rtcp.Header{}
	}

	if err := header.Unmarshal(encrypted); err != nil {
		return nil, err
	}

	return c.decryptRTCP(dst, encrypted)
}

func (c *Context) encryptRTCP(dst, decrypted []byte) ([]byte, error) {
	if len(decrypted) < srtcpHeaderSize {
		return nil, fmt.Errorf("%w: %d", errTooShortRTCP, len(decrypted))
	}

	ssrc := binary.BigEndian.Uint32(decrypted[4:])
	ssrcState := c.getSRTCPSSRCState(ssrc)

	if ssrcState.srtcpIndex >= maxSRTCPIndex {

		return nil, errExceededMaxPackets
	}

	ssrcState.srtcpIndex++

	return c.cipher.encryptRTCP(dst, decrypted, ssrcState.srtcpIndex, ssrc)
}

func (c *Context) EncryptRTCP(dst, decrypted []byte, header *rtcp.Header) ([]byte, error) {
	if header == nil {
		header = &rtcp.Header{}
	}

	if err := header.Unmarshal(decrypted); err != nil {
		return nil, err
	}

	return c.encryptRTCP(dst, decrypted)
}

func (c *Context) decryptRTP(dst, ciphertext []byte, header *rtp.Header, headerLen int) ([]byte, error) {
	authTagLen, err := c.cipher.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}
	aeadAuthTagLen, err := c.cipher.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(c.sendMKI)

	var hasRocInPacket bool
	hasRocInPacket, authTagLen = c.hasROCInPacket(header, authTagLen)

	if len(ciphertext) < (headerLen + aeadAuthTagLen + mkiLen + authTagLen) {
		return nil, fmt.Errorf("%w: %d", errTooShortRTP, len(ciphertext))
	}

	ssrcState := c.getSRTPSSRCState(header.SSRC)

	var roc uint32
	var diff int64
	var index uint64
	if !hasRocInPacket {

		roc, diff, _ = ssrcState.nextRolloverCount(header.SequenceNumber)
		index = (uint64(roc) << 16) | uint64(header.SequenceNumber)
	} else {

		roc = binary.BigEndian.Uint32(ciphertext[len(ciphertext)-authTagLen:])
		index = (uint64(roc) << 16) | uint64(header.SequenceNumber)
		diff = int64(ssrcState.index) - int64(index)
	}

	markAsValid, ok := ssrcState.replayDetector.Check(index)
	if !ok {
		return nil, &duplicatedError{
			Proto: "srtp", SSRC: header.SSRC, Index: uint32(header.SequenceNumber),
		}
	}

	err = c.checkCryptex(header)
	if err != nil {
		return nil, err
	}

	cipher := c.cipher
	if len(c.mkis) > 0 {

		actualMKI := ciphertext[len(ciphertext)-mkiLen-authTagLen : len(ciphertext)-authTagLen]
		cipher, ok = c.mkis[string(actualMKI)]
		if !ok {
			return nil, ErrMKINotFound
		}
	}

	dst = growBufferSize(dst, len(ciphertext)-authTagLen-mkiLen)

	dst, err = cipher.decryptRTP(dst, ciphertext, header, headerLen, roc, hasRocInPacket)
	if err != nil {
		return nil, err
	}

	markAsValid()
	ssrcState.updateRolloverCount(header.SequenceNumber, diff, hasRocInPacket, roc)

	return dst, nil
}

func (c *Context) DecryptRTP(dst, encrypted []byte, header *rtp.Header) ([]byte, error) {
	if header == nil {
		header = &rtp.Header{}
	}

	headerLen, err := header.Unmarshal(encrypted)
	if err != nil {
		return nil, err
	}

	return c.decryptRTP(dst, encrypted, header, headerLen)
}

func (c *Context) EncryptRTP(dst []byte, plaintext []byte, header *rtp.Header) ([]byte, error) {
	if header == nil {
		header = &rtp.Header{}
	}

	headerLen, err := header.Unmarshal(plaintext)
	if err != nil {
		return nil, err
	}

	return c.encryptRTP(dst, header, headerLen, plaintext)
}

func (c *Context) encryptRTP(dst []byte, header *rtp.Header, headerLen int, plaintext []byte,
) (ciphertext []byte, err error) {

	if c.cryptexMode != CryptexModeDisabled && header.Extension &&
		header.ExtensionProfile != rtp.ExtensionProfileOneByte &&
		header.ExtensionProfile != rtp.ExtensionProfileTwoByte {
		return nil, errUnsupportedHeaderExtension
	}

	s := c.getSRTPSSRCState(header.SSRC)
	roc, diff, ovf := s.nextRolloverCount(header.SequenceNumber)
	if ovf {

		return nil, errExceededMaxPackets
	}
	s.updateRolloverCount(header.SequenceNumber, diff, false, 0)

	rocInPacket := c.rccMode != RCCModeNone && header.SequenceNumber%c.rocTransmitRate == 0

	return c.cipher.encryptRTP(dst, header, headerLen, plaintext, roc, rocInPacket)
}

func (c *Context) hasROCInPacket(header *rtp.Header, authTagLen int) (bool, int) {
	hasRocInPacket := false
	switch c.rccMode {
	case RCCMode2:

		hasRocInPacket = header.SequenceNumber%c.rocTransmitRate == 0
	case RCCMode3:

		hasRocInPacket = header.SequenceNumber%c.rocTransmitRate == 0
		if hasRocInPacket {
			authTagLen = 4
		}
	default:
	}

	return hasRocInPacket, authTagLen
}

func (c *Context) checkCryptex(header *rtp.Header) error {
	switch c.cryptexMode {
	case CryptexModeDisabled:
		if isCryptexPacket(header) {
			return errCryptexDisabled
		}
	case CryptexModeRequired:
		if (header.Extension || len(header.CSRC) > 0) && !isCryptexPacket(header) {
			return errUnencryptedHeaderExtAndCSRCs
		}
	default:
	}

	return nil
}

type srtpCipher interface {
	AuthTagRTPLen() (int, error)
	AuthTagRTCPLen() (int, error)
	AEADAuthTagLen() (int, error)
	getRTCPIndex([]byte) uint32
	encryptRTP([]byte, *rtp.Header, int, []byte, uint32, bool) ([]byte, error)
	encryptRTCP([]byte, []byte, uint32, uint32) ([]byte, error)
	decryptRTP([]byte, []byte, *rtp.Header, int, uint32, bool) ([]byte, error)
	decryptRTCP([]byte, []byte, uint32, uint32) ([]byte, error)
}

type srtpCipherAeadAesGcm struct {
	protectionProfileWithArgs
	srtpCipher, srtcpCipher           cipher.AEAD
	srtpSessionSalt, srtcpSessionSalt []byte
	mki                               []byte
	srtpEncrypted, srtcpEncrypted     bool
	useCryptex                        bool
}

func newSrtpCipherAeadAesGcm(
	profile protectionProfileWithArgs,
	masterKey, masterSalt, mki []byte,
	encryptSRTP, encryptSRTCP, useCryptex bool,
) (*srtpCipherAeadAesGcm, error) {
	srtpCipher := &srtpCipherAeadAesGcm{
		protectionProfileWithArgs: profile,
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
		useCryptex:                useCryptex,
	}

	srtpSessionKey, err := aesCmKeyDerivation(labelSRTPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		return nil, err
	}

	srtpBlock, err := aes.NewCipher(srtpSessionKey)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtpCipher, err = cipher.NewGCM(srtpBlock)
	if err != nil {
		return nil, err
	}

	srtcpSessionKey, err := aesCmKeyDerivation(labelSRTCPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		return nil, err
	}

	srtcpBlock, err := aes.NewCipher(srtcpSessionKey)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtcpCipher, err = cipher.NewGCM(srtcpBlock)
	if err != nil {
		return nil, err
	}

	if srtpCipher.srtpSessionSalt, err = aesCmKeyDerivation(
		labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt),
	); err != nil {
		return nil, err
	} else if srtpCipher.srtcpSessionSalt, err = aesCmKeyDerivation(
		labelSRTCPSalt, masterKey, masterSalt, 0, len(masterSalt),
	); err != nil {
		return nil, err
	}

	mkiLen := len(mki)
	if mkiLen > 0 {
		srtpCipher.mki = make([]byte, mkiLen)
		copy(srtpCipher.mki, mki)
	}

	return srtpCipher, nil
}

func (s *srtpCipherAeadAesGcm) encryptRTP(
	dst []byte,
	header *rtp.Header,
	headerLen int,
	plaintext []byte,
	roc uint32,
	rocInAuthTag bool,
) (ciphertext []byte, err error) {

	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	payloadLen := len(plaintext) - headerLen
	authPartLen := headerLen + payloadLen + authTagLen
	dstLen := authPartLen + len(s.mki)
	if rocInAuthTag {
		dstLen += 4
	}

	insertEmptyExtHdr := needsEmptyExtensionHeader(s.useCryptex, header)
	if insertEmptyExtHdr {
		dstLen += extensionHeaderSize
	}

	dst = growBufferSize(dst, dstLen)
	sameBuffer := isSameBuffer(dst, plaintext)

	if insertEmptyExtHdr {
		plaintext = insertEmptyExtensionHeader(dst, plaintext, sameBuffer, header)
		sameBuffer = true
		headerLen += extensionHeaderSize
	}

	err = s.doEncryptRTP(dst, header, headerLen, plaintext, roc, rocInAuthTag, sameBuffer, payloadLen, authPartLen)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *srtpCipherAeadAesGcm) doEncryptRTP(dst []byte, header *rtp.Header, headerLen int, plaintext []byte, roc uint32,
	rocInAuthTag bool, sameBuffer bool, payloadLen int, authPartLen int,
) error {
	iv := s.rtpInitializationVector(header, roc)
	encrypt := func(dst, plaintext []byte, headerLen int) error {
		s.srtpCipher.Seal(dst[headerLen:headerLen], iv[:], plaintext[headerLen:], plaintext[:headerLen])

		return nil
	}

	switch {
	case s.useCryptex && header.Extension:
		err := encryptCryptexRTP(dst, plaintext, sameBuffer, header, encrypt)
		if err != nil {
			return err
		}
	case s.srtpEncrypted:

		if !sameBuffer {
			copy(dst, plaintext[:headerLen])
		}
		s.srtpCipher.Seal(dst[headerLen:headerLen], iv[:], plaintext[headerLen:], dst[:headerLen])
	default:
		clearLen := headerLen + payloadLen
		if !sameBuffer {
			copy(dst, plaintext)
		}
		s.srtpCipher.Seal(dst[clearLen:clearLen], iv[:], nil, dst[:clearLen])
	}

	if len(s.mki) > 0 {
		copy(dst[authPartLen:], s.mki)
	}

	if rocInAuthTag {
		binary.BigEndian.PutUint32(dst[len(dst)-4:], roc)
	}

	return nil
}

func (s *srtpCipherAeadAesGcm) decryptRTP(
	dst, ciphertext []byte,
	header *rtp.Header,
	headerLen int,
	roc uint32,
	rocInAuthTag bool,
) ([]byte, error) {

	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	rocLen := 0
	if rocInAuthTag {
		rocLen = 4
	}
	nDst := len(ciphertext) - authTagLen - len(s.mki) - rocLen
	if nDst < headerLen {

		return nil, ErrFailedToVerifyAuthTag
	}
	dst = growBufferSize(dst, nDst)
	sameBuffer := isSameBuffer(dst, ciphertext)

	nEnd := len(ciphertext) - len(s.mki) - rocLen

	err = s.doDecryptRTP(dst, ciphertext, header, headerLen, roc, sameBuffer, nEnd, authTagLen)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *srtpCipherAeadAesGcm) doDecryptRTP(dst, ciphertext []byte, header *rtp.Header, headerLen int, roc uint32,
	sameBuffer bool, nEnd int, authTagLen int,
) error {
	iv := s.rtpInitializationVector(header, roc)
	decrypt := func(dst, ciphertext []byte, headerLen int) error {
		_, err := s.srtpCipher.Open(dst[headerLen:headerLen], iv[:], ciphertext[headerLen:nEnd], ciphertext[:headerLen])

		return err
	}

	switch {
	case isCryptexPacket(header):
		err := decryptCryptexRTP(dst, ciphertext, sameBuffer, header, headerLen, decrypt)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
	case s.srtpEncrypted:
		if err := decrypt(dst, ciphertext[:nEnd], headerLen); err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}

		if !sameBuffer {
			copy(dst[:headerLen], ciphertext[:headerLen])
		}
	default:
		nDataEnd := nEnd - authTagLen
		if _, err := s.srtpCipher.Open(
			nil, iv[:], ciphertext[nDataEnd:nEnd], ciphertext[:nDataEnd],
		); err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}

		if !sameBuffer {
			copy(dst, ciphertext[:nDataEnd])
		}
	}

	return nil
}

func (s *srtpCipherAeadAesGcm) encryptRTCP(dst, decrypted []byte, srtcpIndex uint32, ssrc uint32) ([]byte, error) {
	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	aadPos := len(decrypted) + authTagLen

	dst = growBufferSize(dst, aadPos+srtcpIndexSize+len(s.mki))
	sameBuffer := isSameBuffer(dst, decrypted)

	iv := s.rtcpInitializationVector(srtcpIndex, ssrc)
	if s.srtcpEncrypted {
		aad := s.rtcpAdditionalAuthenticatedData(decrypted, srtcpIndex)
		if !sameBuffer {

			copy(dst[:srtcpHeaderSize], decrypted[:srtcpHeaderSize])
		}

		copy(dst[aadPos:aadPos+srtcpIndexSize], aad[8:12])
		s.srtcpCipher.Seal(dst[srtcpHeaderSize:srtcpHeaderSize], iv[:], decrypted[srtcpHeaderSize:], aad[:])
	} else {

		if !sameBuffer {
			copy(dst, decrypted)
		}

		binary.BigEndian.PutUint32(dst[len(decrypted):], srtcpIndex)

		tag := make([]byte, authTagLen)
		s.srtcpCipher.Seal(tag[0:0], iv[:], nil, dst[:len(decrypted)+srtcpIndexSize])

		copy(dst[aadPos:], dst[len(decrypted):len(decrypted)+srtcpIndexSize])

		copy(dst[len(decrypted):], tag)
	}

	copy(dst[aadPos+srtcpIndexSize:], s.mki)

	return dst, nil
}

func (s *srtpCipherAeadAesGcm) decryptRTCP(dst, encrypted []byte, srtcpIndex, ssrc uint32) ([]byte, error) {
	aadPos := len(encrypted) - srtcpIndexSize - len(s.mki)

	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	nDst := aadPos - authTagLen
	if nDst < 0 {

		return nil, ErrFailedToVerifyAuthTag
	}
	dst = growBufferSize(dst, nDst)
	sameBuffer := isSameBuffer(dst, encrypted)

	isEncrypted := encrypted[aadPos]&srtcpEncryptionFlag != 0
	iv := s.rtcpInitializationVector(srtcpIndex, ssrc)
	if isEncrypted {
		aad := s.rtcpAdditionalAuthenticatedData(encrypted, srtcpIndex)
		if _, err := s.srtcpCipher.Open(dst[srtcpHeaderSize:srtcpHeaderSize], iv[:], encrypted[srtcpHeaderSize:aadPos],
			aad[:]); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
	} else {

		dataEnd := aadPos - authTagLen
		aad := make([]byte, dataEnd+4)
		copy(aad, encrypted[:dataEnd])
		copy(aad[dataEnd:], encrypted[aadPos:aadPos+4])

		if _, err := s.srtcpCipher.Open(nil, iv[:], encrypted[dataEnd:aadPos], aad); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}

		if !sameBuffer {
			copy(dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:dataEnd])
		}
	}

	if !sameBuffer {
		copy(dst[:srtcpHeaderSize], encrypted[:srtcpHeaderSize])
	}

	return dst, nil
}

func (s *srtpCipherAeadAesGcm) rtpInitializationVector(header *rtp.Header, roc uint32) [12]byte {
	var iv [12]byte
	binary.BigEndian.PutUint32(iv[2:], header.SSRC)
	binary.BigEndian.PutUint32(iv[6:], roc)
	binary.BigEndian.PutUint16(iv[10:], header.SequenceNumber)

	for i := range iv {
		iv[i] ^= s.srtpSessionSalt[i]
	}

	return iv
}

func (s *srtpCipherAeadAesGcm) rtcpInitializationVector(srtcpIndex uint32, ssrc uint32) [12]byte {
	var iv [12]byte

	binary.BigEndian.PutUint32(iv[2:], ssrc)
	binary.BigEndian.PutUint32(iv[8:], srtcpIndex)

	for i := range iv {
		iv[i] ^= s.srtcpSessionSalt[i]
	}

	return iv
}

func (s *srtpCipherAeadAesGcm) rtcpAdditionalAuthenticatedData(rtcpPacket []byte, srtcpIndex uint32) [12]byte {
	var aad [12]byte

	copy(aad[:], rtcpPacket[:8])
	binary.BigEndian.PutUint32(aad[8:], srtcpIndex)
	aad[8] |= srtcpEncryptionFlag

	return aad
}

func (s *srtpCipherAeadAesGcm) getRTCPIndex(in []byte) uint32 {
	return binary.BigEndian.Uint32(in[len(in)-len(s.mki)-srtcpIndexSize:]) &^ (srtcpEncryptionFlag << 24)
}

type srtpCipherAesCmHmacSha1 struct {
	protectionProfileWithArgs
	srtpSessionSalt  []byte
	srtpSessionAuth  hash.Hash
	srtpBlock        cipher.Block
	srtpEncrypted    bool
	srtcpSessionSalt []byte
	srtcpSessionAuth hash.Hash
	srtcpBlock       cipher.Block
	srtcpEncrypted   bool
	mki              []byte
	useCryptex       bool
}

func newSrtpCipherAesCmHmacSha1(
	profile protectionProfileWithArgs,
	masterKey, masterSalt, mki []byte,
	encryptSRTP, encryptSRTCP, useCryptex bool,
) (*srtpCipherAesCmHmacSha1, error) {
	switch profile.ProtectionProfile {
	case ProtectionProfileNullHmacSha1_80, ProtectionProfileNullHmacSha1_32:
		encryptSRTP = false
		encryptSRTCP = false
	default:
	}

	srtpCipher := &srtpCipherAesCmHmacSha1{
		protectionProfileWithArgs: profile,
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
		useCryptex:                useCryptex,
	}

	srtpSessionKey, err := aesCmKeyDerivation(labelSRTPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		return nil, err
	} else if srtpCipher.srtpBlock, err = aes.NewCipher(srtpSessionKey); err != nil {
		return nil, err
	}

	srtcpSessionKey, err := aesCmKeyDerivation(labelSRTCPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		return nil, err
	} else if srtpCipher.srtcpBlock, err = aes.NewCipher(srtcpSessionKey); err != nil {
		return nil, err
	}

	if srtpCipher.srtpSessionSalt, err = aesCmKeyDerivation(
		labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt),
	); err != nil {
		return nil, err
	} else if srtpCipher.srtcpSessionSalt, err = aesCmKeyDerivation(
		labelSRTCPSalt, masterKey, masterSalt, 0, len(masterSalt),
	); err != nil {
		return nil, err
	}

	authKeyLen, err := profile.AuthKeyLen()
	if err != nil {
		return nil, err
	}

	srtpSessionAuthTag, err := aesCmKeyDerivation(labelSRTPAuthenticationTag, masterKey, masterSalt, 0, authKeyLen)
	if err != nil {
		return nil, err
	}

	srtcpSessionAuthTag, err := aesCmKeyDerivation(labelSRTCPAuthenticationTag, masterKey, masterSalt, 0, authKeyLen)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtcpSessionAuth = hmac.New(sha1.New, srtcpSessionAuthTag)
	srtpCipher.srtpSessionAuth = hmac.New(sha1.New, srtpSessionAuthTag)

	mkiLen := len(mki)
	if mkiLen > 0 {
		srtpCipher.mki = make([]byte, mkiLen)
		copy(srtpCipher.mki, mki)
	}

	return srtpCipher, nil
}

func (s *srtpCipherAesCmHmacSha1) encryptRTP(
	dst []byte,
	header *rtp.Header,
	headerLen int,
	plaintext []byte,
	roc uint32,
	rocInAuthTag bool,
) (ciphertext []byte, err error) {

	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}
	payloadLen := len(plaintext) - headerLen
	dstLen := headerLen + payloadLen + len(s.mki) + authTagLen

	insertEmptyExtHdr := needsEmptyExtensionHeader(s.useCryptex, header)
	if insertEmptyExtHdr {
		dstLen += extensionHeaderSize
	}

	dst = growBufferSize(dst, dstLen)
	sameBuffer := isSameBuffer(dst, plaintext)

	if insertEmptyExtHdr {

		plaintext = insertEmptyExtensionHeader(dst, plaintext, sameBuffer, header)
		sameBuffer = true
		headerLen += extensionHeaderSize
	}

	err = s.doEncryptRTP(dst, header, headerLen, plaintext, roc, rocInAuthTag, sameBuffer, payloadLen)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) doEncryptRTP(dst []byte, header *rtp.Header, headerLen int, plaintext []byte,
	roc uint32, rocInAuthTag bool, sameBuffer bool, payloadLen int,
) error {
	encrypt := func(dst, plaintext []byte, headerLen int) error {
		counter := generateCounter(header.SequenceNumber, roc, header.SSRC, s.srtpSessionSalt)

		return xorBytesCTR(s.srtpBlock, counter[:], dst[headerLen:], plaintext[headerLen:])
	}

	var err error
	switch {
	case s.useCryptex && header.Extension:
		err = encryptCryptexRTP(dst, plaintext, sameBuffer, header, encrypt)
	case s.srtpEncrypted:

		if !sameBuffer {
			copy(dst, plaintext[:headerLen])
		}

		err = encrypt(dst, plaintext, headerLen)
	case !sameBuffer:
		copy(dst, plaintext)
	default:
	}
	if err != nil {
		return err
	}
	n := headerLen + payloadLen

	authTag, err := s.generateSrtpAuthTag(dst[:n], roc, rocInAuthTag)
	if err != nil {
		return err
	}

	if len(s.mki) > 0 {
		copy(dst[n:], s.mki)
		n += len(s.mki)
	}

	copy(dst[n:], authTag)

	return nil
}

func (s *srtpCipherAesCmHmacSha1) decryptRTP(
	dst, ciphertext []byte,
	header *rtp.Header,
	headerLen int,
	roc uint32,
	rocInAuthTag bool,
) ([]byte, error) {

	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}

	actualTag := ciphertext[len(ciphertext)-authTagLen:]
	ciphertext = ciphertext[:len(ciphertext)-len(s.mki)-authTagLen]

	expectedTag, err := s.generateSrtpAuthTag(ciphertext, roc, rocInAuthTag)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, ErrFailedToVerifyAuthTag
	}

	sameBuffer := isSameBuffer(dst, ciphertext)

	err = s.doDecryptRTP(dst, ciphertext, header, headerLen, roc, sameBuffer)
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) doDecryptRTP(dst, ciphertext []byte, header *rtp.Header, headerLen int, roc uint32,
	sameBuffer bool,
) error {
	decrypt := func(dst, ciphertext []byte, headerLen int) error {
		counter := generateCounter(header.SequenceNumber, roc, header.SSRC, s.srtpSessionSalt)

		return xorBytesCTR(s.srtpBlock, counter[:], dst[headerLen:], ciphertext[headerLen:])
	}

	switch {
	case isCryptexPacket(header):
		err := decryptCryptexRTP(dst, ciphertext, sameBuffer, header, headerLen, decrypt)
		if err != nil {
			return err
		}
	case s.srtpEncrypted:

		if !sameBuffer {
			copy(dst, ciphertext[:headerLen])
		}

		err := decrypt(dst, ciphertext, headerLen)
		if err != nil {
			return err
		}
	case !sameBuffer:
		copy(dst, ciphertext)
	default:
	}

	return nil
}

func (s *srtpCipherAesCmHmacSha1) encryptRTCP(dst, decrypted []byte, srtcpIndex uint32, ssrc uint32) ([]byte, error) {
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(s.mki)
	decryptedLen := len(decrypted)
	encryptedLen := decryptedLen + authTagLen + mkiLen + srtcpIndexSize

	dst = growBufferSize(dst, encryptedLen)
	sameBuffer := isSameBuffer(dst, decrypted)

	if !sameBuffer {
		copy(dst, decrypted[:srtcpHeaderSize])
	}

	if s.srtcpEncrypted {
		counter := generateCounter(uint16(srtcpIndex&0xffff), srtcpIndex>>16, ssrc, s.srtcpSessionSalt)
		if err = xorBytesCTR(s.srtcpBlock, counter[:], dst[srtcpHeaderSize:], decrypted[srtcpHeaderSize:]); err != nil {
			return nil, err
		}

		binary.BigEndian.PutUint32(dst[decryptedLen:], srtcpIndex)
		dst[decryptedLen] |= srtcpEncryptionFlag
	} else {

		if !sameBuffer {
			copy(dst[srtcpHeaderSize:], decrypted[srtcpHeaderSize:])
		}

		binary.BigEndian.PutUint32(dst[decryptedLen:], srtcpIndex)
	}

	n := decryptedLen + srtcpIndexSize

	authTag, err := s.generateSrtcpAuthTag(dst[:n])
	if err != nil {
		return nil, err
	}

	if len(s.mki) > 0 {
		copy(dst[n:], s.mki)
		n += mkiLen
	}

	copy(dst[n:], authTag)

	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) decryptRTCP(dst, encrypted []byte, index, ssrc uint32) ([]byte, error) {
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(s.mki)
	encryptedLen := len(encrypted)
	decryptedLen := encryptedLen - (authTagLen + mkiLen + srtcpIndexSize)
	if decryptedLen < 8 {
		return nil, errTooShortRTCP
	}

	expectedTag, err := s.generateSrtcpAuthTag(encrypted[:encryptedLen-mkiLen-authTagLen])
	if err != nil {
		return nil, err
	}

	actualTag := encrypted[encryptedLen-authTagLen:]
	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, ErrFailedToVerifyAuthTag
	}

	dst = growBufferSize(dst, decryptedLen)
	sameBuffer := isSameBuffer(dst, encrypted)

	if !sameBuffer {
		copy(dst, encrypted[:srtcpHeaderSize])
	}

	isEncrypted := encrypted[decryptedLen]&srtcpEncryptionFlag != 0
	if isEncrypted {
		counter := generateCounter(uint16(index&0xffff), index>>16, ssrc, s.srtcpSessionSalt)
		err = xorBytesCTR(s.srtcpBlock, counter[:], dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:decryptedLen])
	} else if !sameBuffer {
		copy(dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:])
	}

	return dst, err
}

func (s *srtpCipherAesCmHmacSha1) generateSrtpAuthTag(buf []byte, roc uint32, rocInAuthTag bool) ([]byte, error) {

	s.srtpSessionAuth.Reset()

	if _, err := s.srtpSessionAuth.Write(buf); err != nil {
		return nil, err
	}

	rocRaw := [4]byte{}
	binary.BigEndian.PutUint32(rocRaw[:], roc)

	_, err := s.srtpSessionAuth.Write(rocRaw[:])
	if err != nil {
		return nil, err
	}

	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}

	var authTag []byte
	if rocInAuthTag {
		authTag = append(authTag, rocRaw[:]...)
	}

	return s.srtpSessionAuth.Sum(authTag)[0:authTagLen], nil
}

func (s *srtpCipherAesCmHmacSha1) generateSrtcpAuthTag(buf []byte) ([]byte, error) {

	s.srtcpSessionAuth.Reset()

	if _, err := s.srtcpSessionAuth.Write(buf); err != nil {
		return nil, err
	}
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}

	return s.srtcpSessionAuth.Sum(nil)[0:authTagLen], nil
}

func (s *srtpCipherAesCmHmacSha1) getRTCPIndex(in []byte) uint32 {
	authTagLen, _ := s.AuthTagRTCPLen()
	tailOffset := len(in) - (authTagLen + srtcpIndexSize + len(s.mki))
	srtcpIndexBuffer := in[tailOffset : tailOffset+srtcpIndexSize]

	return binary.BigEndian.Uint32(srtcpIndexBuffer) &^ (1 << 31)
}

const (
	minSrtpHeaderSize   = 12
	extensionHeaderSize = 4
)

func isCryptexPacket(header *rtp.Header) bool {
	return header.Extension &&
		(header.ExtensionProfile == rtp.CryptexProfileOneByte || header.ExtensionProfile == rtp.CryptexProfileTwoByte)
}

func moveHeaderExtensionBeforeCSRCs(header *rtp.Header, buf []byte) {
	if len(header.CSRC) == 0 || !header.Extension {
		return
	}

	var tmp [extensionHeaderSize]byte
	csrcLen := len(header.CSRC) * 4
	copy(tmp[:], buf[minSrtpHeaderSize+csrcLen:minSrtpHeaderSize+csrcLen+extensionHeaderSize])
	copy(buf[minSrtpHeaderSize+extensionHeaderSize:], buf[minSrtpHeaderSize:minSrtpHeaderSize+csrcLen])
	copy(buf[minSrtpHeaderSize:], tmp[:])
}

func moveCSRCsBeforeHeaderExtension(header *rtp.Header, buf []byte) {
	if len(header.CSRC) == 0 || !header.Extension {
		return
	}

	var tmp [extensionHeaderSize]byte
	csrcLen := len(header.CSRC) * 4
	copy(tmp[:], buf[minSrtpHeaderSize:minSrtpHeaderSize+extensionHeaderSize])
	copy(buf[minSrtpHeaderSize:],
		buf[minSrtpHeaderSize+extensionHeaderSize:minSrtpHeaderSize+csrcLen+extensionHeaderSize])
	copy(buf[minSrtpHeaderSize+csrcLen:], tmp[:])
}

func encryptCryptexRTP(dst, plaintext []byte, sameBuffer bool, header *rtp.Header,
	encrypt func(dst, plaintext []byte, headerLen int) error,
) error {
	moveHeaderExtensionBeforeCSRCs(header, plaintext)

	if header.ExtensionProfile == rtp.ExtensionProfileOneByte {
		binary.BigEndian.PutUint16(plaintext[minSrtpHeaderSize:], rtp.CryptexProfileOneByte)
	} else {
		binary.BigEndian.PutUint16(plaintext[minSrtpHeaderSize:], rtp.CryptexProfileTwoByte)
	}

	err := encrypt(dst, plaintext, minSrtpHeaderSize+extensionHeaderSize)
	if err != nil {
		binary.BigEndian.PutUint16(plaintext[minSrtpHeaderSize:], header.ExtensionProfile)
		moveCSRCsBeforeHeaderExtension(header, plaintext)

		return err
	}

	if !sameBuffer {
		copy(dst, plaintext[:minSrtpHeaderSize+extensionHeaderSize])
		binary.BigEndian.PutUint16(plaintext[minSrtpHeaderSize:], header.ExtensionProfile)
		moveCSRCsBeforeHeaderExtension(header, plaintext)
	}
	moveCSRCsBeforeHeaderExtension(header, dst)

	return nil
}

func decryptCryptexRTP(dst, ciphertext []byte, sameBuffer bool, header *rtp.Header, headerLen int,
	decrypt func(dst, ciphertext []byte, headerLen int) error,
) error {
	moveHeaderExtensionBeforeCSRCs(header, ciphertext)
	err := decrypt(dst, ciphertext, minSrtpHeaderSize+extensionHeaderSize)
	if err != nil {
		moveCSRCsBeforeHeaderExtension(header, ciphertext)

		return err
	}

	if !sameBuffer {
		copy(dst, ciphertext[:minSrtpHeaderSize+extensionHeaderSize])
		moveCSRCsBeforeHeaderExtension(header, dst)
	}
	moveCSRCsBeforeHeaderExtension(header, ciphertext)

	offset := minSrtpHeaderSize + len(header.CSRC)*4
	if header.ExtensionProfile == rtp.CryptexProfileOneByte {
		binary.BigEndian.PutUint16(dst[offset:], rtp.ExtensionProfileOneByte)
	} else {
		binary.BigEndian.PutUint16(dst[offset:], rtp.ExtensionProfileTwoByte)
	}

	n, err := header.Unmarshal(dst)
	if err != nil {
		return err
	}
	if n != headerLen {
		return errHeaderLengthMismatch
	}

	return nil
}

func needsEmptyExtensionHeader(useCryptex bool, header *rtp.Header) bool {
	return useCryptex && len(header.CSRC) > 0 && !header.Extension
}

func insertEmptyExtensionHeader(dst, plaintext []byte, sameBuffer bool, header *rtp.Header) []byte {
	header.Extension = true
	header.ExtensionProfile = rtp.ExtensionProfileOneByte
	header.Extensions = nil

	var emptyExtHdr [extensionHeaderSize]byte
	binary.BigEndian.PutUint16(emptyExtHdr[:], rtp.ExtensionProfileOneByte)

	offset := minSrtpHeaderSize + len(header.CSRC)*4
	plaintextLen := len(plaintext)
	if sameBuffer {
		plaintext = plaintext[:plaintextLen+extensionHeaderSize]
		copy(plaintext[offset+extensionHeaderSize:], plaintext[offset:plaintextLen])
		copy(plaintext[offset:], emptyExtHdr[:])
	} else {
		newPlaintext := dst[:plaintextLen+extensionHeaderSize]
		copy(newPlaintext, plaintext[:offset])
		copy(newPlaintext[offset:], emptyExtHdr[:])
		copy(newPlaintext[offset+extensionHeaderSize:], plaintext[offset:plaintextLen])
		plaintext = newPlaintext
	}

	plaintext[0] |= 0x10

	return plaintext
}

type readStream interface {
	init(child streamSession, ssrc uint32) error
	Read(buf []byte) (int, error)
	GetSSRC() uint32
}

const srtcpBufferSize = 100 * 1000

type ReadStreamSRTCP struct {
	mu       sync.Mutex
	isClosed chan bool
	session  *SessionSRTCP
	ssrc     uint32
	isInited bool
	buffer   io.ReadWriteCloser
}

func (r *ReadStreamSRTCP) write(buf []byte) (n int, err error) {
	n, err = r.buffer.Write(buf)

	if errors.Is(err, transport.ErrFull) {

		return len(buf), nil
	}

	return n, err
}

func newReadStreamSRTCP() readStream {
	return &ReadStreamSRTCP{}
}

func (r *ReadStreamSRTCP) ReadRTCP(buf []byte) (int, *rtcp.Header, error) {
	n, err := r.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	header := &rtcp.Header{}
	err = header.Unmarshal(buf[:n])
	if err != nil {
		return 0, nil, err
	}

	return n, header, nil
}

func (r *ReadStreamSRTCP) Read(buf []byte) (int, error) {
	return r.buffer.Read(buf)
}

func (r *ReadStreamSRTCP) SetReadDeadline(t time.Time) error {
	if b, ok := r.buffer.(interface {
		SetReadDeadline(time.Time) error
	}); ok {
		return b.SetReadDeadline(t)
	}

	return nil
}

func (r *ReadStreamSRTCP) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isInited {
		return errStreamNotInited
	}

	select {
	case <-r.isClosed:
		return errStreamAlreadyClosed
	default:
		err := r.buffer.Close()
		if err != nil {
			return err
		}

		r.session.removeReadStream(r.ssrc)

		return nil
	}
}

func (r *ReadStreamSRTCP) init(child streamSession, ssrc uint32) error {
	sessionSRTCP, ok := child.(*SessionSRTCP)

	r.mu.Lock()
	defer r.mu.Unlock()
	if !ok {
		return errFailedTypeAssertion
	} else if r.isInited {
		return errStreamAlreadyInited
	}

	r.session = sessionSRTCP
	r.ssrc = ssrc
	r.isInited = true
	r.isClosed = make(chan bool)

	if r.session.bufferFactory != nil {
		r.buffer = r.session.bufferFactory(transport.RTCPBufferPacket, ssrc)
	} else {

		buff := transport.NewBuffer()
		buff.SetLimitSize(srtcpBufferSize)
		r.buffer = buff
	}

	return nil
}

func (r *ReadStreamSRTCP) GetSSRC() uint32 {
	return r.ssrc
}

type WriteStreamSRTCP struct {
	session *SessionSRTCP
}

func (w *WriteStreamSRTCP) WriteRTCP(header *rtcp.Header, payload []byte) (int, error) {
	headerRaw, err := header.Marshal()
	if err != nil {
		return 0, err
	}

	return w.session.write(append(headerRaw, payload...))
}

func (w *WriteStreamSRTCP) Write(b []byte) (int, error) {
	return w.session.write(b)
}

func (w *WriteStreamSRTCP) SetWriteDeadline(t time.Time) error {
	return w.session.setWriteDeadline(t)
}

const srtpBufferSize = 1000 * 1000

type ReadStreamSRTP struct {
	mu            sync.Mutex
	isClosed      chan bool
	session       *SessionSRTP
	ssrc          uint32
	isInited      bool
	buffer        io.ReadWriteCloser
	peekedPackets [][]byte
}

func newReadStreamSRTP() readStream {
	return &ReadStreamSRTP{}
}

func (r *ReadStreamSRTP) init(child streamSession, ssrc uint32) error {
	sessionSRTP, ok := child.(*SessionSRTP)

	r.mu.Lock()
	defer r.mu.Unlock()

	if !ok {
		return errFailedTypeAssertion
	} else if r.isInited {
		return errStreamAlreadyInited
	}

	r.session = sessionSRTP
	r.ssrc = ssrc
	r.isInited = true
	r.isClosed = make(chan bool)

	if r.session.bufferFactory != nil {
		r.buffer = r.session.bufferFactory(transport.RTPBufferPacket, ssrc)
	} else {
		buff := transport.NewBuffer()
		buff.SetLimitSize(srtpBufferSize)
		r.buffer = buff
	}

	return nil
}

func (r *ReadStreamSRTP) write(buf []byte) (n int, err error) {
	n, err = r.buffer.Write(buf)

	if errors.Is(err, transport.ErrFull) {

		return len(buf), nil
	}

	return n, err
}

func (r *ReadStreamSRTP) Peek(buf []byte) (n int, err error) {
	n, err = r.buffer.Read(buf)
	if err == nil {
		r.peekedPackets = append(r.peekedPackets, slices.Clone(buf[:n]))
	}

	return
}

func (r *ReadStreamSRTP) Read(buf []byte) (int, error) {
	if len(r.peekedPackets) != 0 {
		if len(r.peekedPackets[0]) > len(buf) {
			return 0, io.ErrShortBuffer
		}

		n := len(r.peekedPackets[0])
		copy(buf, r.peekedPackets[0])
		r.peekedPackets = r.peekedPackets[1:]

		return n, nil
	}

	return r.buffer.Read(buf)
}

func (r *ReadStreamSRTP) ReadRTP(buf []byte) (int, *rtp.Header, error) {
	n, err := r.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	header := &rtp.Header{}

	_, err = header.Unmarshal(buf[:n])
	if err != nil {
		return 0, nil, err
	}

	return n, header, nil
}

func (r *ReadStreamSRTP) SetReadDeadline(t time.Time) error {
	if b, ok := r.buffer.(interface {
		SetReadDeadline(time.Time) error
	}); ok {
		return b.SetReadDeadline(t)
	}

	return nil
}

func (r *ReadStreamSRTP) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isInited {
		return errStreamNotInited
	}

	select {
	case <-r.isClosed:
		return errStreamAlreadyClosed
	default:
		err := r.buffer.Close()
		if err != nil {
			return err
		}

		r.session.removeReadStream(r.ssrc)

		return nil
	}
}

func (r *ReadStreamSRTP) GetSSRC() uint32 {
	return r.ssrc
}

type WriteStreamSRTP struct {
	session *SessionSRTP
}

func (w *WriteStreamSRTP) WriteRTP(header *rtp.Header, payload []byte) (int, error) {
	return w.session.writeRTP(header, payload)
}

func (w *WriteStreamSRTP) Write(b []byte) (int, error) {
	return w.session.write(b)
}

func (w *WriteStreamSRTP) SetWriteDeadline(t time.Time) error {
	return w.session.setWriteDeadline(t)
}

func growBufferSize(buf []byte, size int) []byte {
	if size <= cap(buf) {
		return buf[:size]
	}

	buf2 := make([]byte, size)
	copy(buf2, buf)

	return buf2
}

func isSameBuffer(a, b []byte) bool {

	if a == nil && b == nil {
		return true
	}

	if cap(a) == 0 || cap(b) == 0 {
		return false
	}

	aPtr := unsafe.Pointer(&a[:1][0])
	bPtr := unsafe.Pointer(&b[:1][0])

	return aPtr == bPtr
}
