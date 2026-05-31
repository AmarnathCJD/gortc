// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package dtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amarnathcjd/gortc/webrtc"
	"github.com/amarnathcjd/gortc/webrtc/logging"
	"github.com/amarnathcjd/gortc/webrtc/transport"

	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrConnClosed = &FatalError{Err: errors.New("conn is closed")}

	errDeadlineExceeded   = &TimeoutError{Err: fmt.Errorf("read/write timeout: %w", context.DeadlineExceeded)}
	errInvalidContentType = &TemporaryError{Err: errors.New("invalid content type")}

	errBufferTooSmall = &TemporaryError{Err: errors.New("buffer is too small")}

	errContextUnsupported = &TemporaryError{Err: errors.New("context is not supported for ExportKeyingMaterial")}

	errHandshakeInProgress = &TemporaryError{Err: errors.New("handshake is in progress")}

	errReservedExportKeyingMaterial = &TemporaryError{
		Err: errors.New("ExportKeyingMaterial can not be used with a reserved label"),
	}

	errApplicationDataEpochZero = &TemporaryError{Err: errors.New("ApplicationData with epoch of 0")}

	errUnhandledContextType = &TemporaryError{Err: errors.New("unhandled contentType")}

	errCertificateVerifyNoCertificate = &FatalError{
		Err: errors.New("client sent certificate verify but we have no certificate to verify"),
	}

	errCipherSuiteNoIntersection = &FatalError{Err: errors.New("client+server do not support any shared cipher suites")}

	errClientCertificateNotVerified = &FatalError{Err: errors.New("client sent certificate but did not verify it")}

	errClientCertificateRequired = &FatalError{Err: errors.New("server required client verification, but got none")}

	errClientNoMatchingSRTPProfile = &FatalError{Err: errors.New("server responded with SRTP Profile we do not support")}

	errClientRequiredButNoServerEMS = &FatalError{
		Err: errors.New("client required Extended Master Secret extension, but server does not support it"),
	}

	errCookieMismatch = &FatalError{Err: errors.New("client+server cookie does not match")}

	errIdentityNoPSK = &FatalError{Err: errors.New("PSK Identity Hint provided but PSK is nil")}

	errInvalidCertificate = &FatalError{Err: errors.New("no certificate provided")}

	errInvalidCipherSuite = &FatalError{Err: errors.New("invalid or unknown cipher suite")}

	errInvalidClientAuthType = &FatalError{Err: errors.New("invalid client auth type")}

	errInvalidECDSASignature = &FatalError{Err: errors.New("ECDSA signature contained zero or negative values")}

	errInvalidPrivateKey = &FatalError{Err: errors.New("invalid private key type")}

	errInvalidSignatureAlgorithm = &FatalError{Err: errors.New("invalid signature algorithm")}

	errInvalidExtendedMasterSecretType = &FatalError{Err: errors.New("invalid extended master secret type")}

	errInvalidCertificateSignatureAlgorithm = &FatalError{
		Err: errors.New("certificate uses a signature algorithm that is not allowed"),
	}

	errKeySignatureMismatch = &FatalError{Err: errors.New("expected and actual key signature do not match")}

	errInvalidCertificateOID = &FatalError{Err: errors.New("certificate OID does not match signature algorithm")}

	errNilNextConn = &FatalError{Err: errors.New("Conn can not be created with a nil nextConn")}

	errNoAvailableCipherSuites = &FatalError{
		Err: errors.New("connection can not be created, no CipherSuites satisfy this Config"),
	}

	errNoAvailablePSKCipherSuite = &FatalError{
		Err: errors.New("connection can not be created, pre-shared key present but no compatible CipherSuite"),
	}

	errNoAvailableCertificateCipherSuite = &FatalError{
		Err: errors.New("connection can not be created, certificate present but no compatible CipherSuite"),
	}

	errNoAvailableSignatureSchemes = &FatalError{
		Err: errors.New("connection can not be created, no SignatureScheme satisfy this Config"),
	}

	errNoCertificates = &FatalError{Err: errors.New("no certificates configured")}

	errNoConfigProvided = &FatalError{Err: errors.New("no config provided")}

	errNoSupportedEllipticCurves = &FatalError{
		Err: errors.New("client requested zero or more elliptic curves that are not supported by the server"),
	}

	errUnsupportedProtocolVersion = &FatalError{Err: errors.New("unsupported protocol version")}

	errPSKAndIdentityMustBeSetForClient = &FatalError{
		Err: errors.New("PSK and PSK Identity Hint must both be set for client"),
	}

	errRequestedButNoSRTPExtension = &FatalError{
		Err: errors.New("SRTP support was requested but server did not respond with use_srtp extension"),
	}

	errServerNoMatchingSRTPProfile = &FatalError{Err: errors.New("client requested SRTP but we have no matching profiles")}

	errServerRequiredButNoClientEMS = &FatalError{
		Err: errors.New("server requires the Extended Master Secret extension, but the client does not support it"),
	}

	errVerifyDataMismatch = &FatalError{Err: errors.New("expected and actual verify data does not match")}

	errNotAcceptableCertificateChain = &FatalError{Err: errors.New("certificate chain is not signed by an acceptable CA")}

	errInvalidFlight = &InternalError{Err: errors.New("invalid flight number")}

	errKeySignatureGenerateUnimplemented = &InternalError{
		Err: errors.New("unable to generate key signature, unimplemented"),
	}

	errKeySignatureVerifyUnimplemented = &InternalError{Err: errors.New("unable to verify key signature, unimplemented")}

	errLengthMismatch = &InternalError{Err: errors.New("data length and declared length do not match")}

	errSequenceNumberOverflow = &InternalError{Err: errors.New("sequence number overflow")}

	errInvalidFSMTransition = &InternalError{Err: errors.New("invalid state machine transition")}

	errFailedToAccessPoolReadBuffer = &InternalError{Err: errors.New("failed to access pool read buffer")}

	errFragmentBufferOverflow = &InternalError{Err: errors.New("fragment buffer overflow")}

	errEmptyCertificates = &FatalError{Err: errors.New("certificates option requires at least one certificate")}

	errEmptyCipherSuites = &FatalError{Err: errors.New("cipher suites option requires at least one cipher suite")}

	errNilCustomCipherSuites = &FatalError{Err: errors.New("custom cipher suites option requires a non-nil function")}

	errEmptySRTPProtectionProfiles = &FatalError{
		Err: errors.New("SRTP protection profiles option requires at least one profile"),
	}

	errInvalidFlightInterval = &FatalError{Err: errors.New("flight interval must be positive")}

	errNilVerifyPeerCertificate = &FatalError{
		Err: errors.New("verify peer certificate option requires a non-nil callback"),
	}

	errInvalidReplayProtectionWindow = &FatalError{Err: errors.New("replay protection window must be non-negative")}

	errEmptySupportedProtocols = &FatalError{
		Err: errors.New("supported protocols option requires at least one protocol"),
	}

	errEmptyEllipticCurves = &FatalError{Err: errors.New("elliptic curves option requires at least one curve")}

	errNilClientHelloMessageHook = &FatalError{
		Err: errors.New("client hello message hook option requires a non-nil function"),
	}

	errNilServerHelloMessageHook = &FatalError{
		Err: errors.New("server hello message hook option requires a non-nil function"),
	}

	errNilCertificateRequestMessageHook = &FatalError{
		Err: errors.New("certificate request message hook option requires a non-nil function"),
	}
)

type invalidCipherSuiteError struct {
	id CipherSuiteID
}

func (e *invalidCipherSuiteError) Error() string {
	return fmt.Sprintf("CipherSuite with id(%d) is not valid", e.id)
}

func (e *invalidCipherSuiteError) Is(err error) bool {
	var other *invalidCipherSuiteError
	if errors.As(err, &other) {
		return e.id == other.id
	}

	return false
}

type alertError struct {
	*Alert
}

func (e *alertError) Error() string {
	return fmt.Sprintf("alert: %s", e.Alert.String())
}

func (e *alertError) IsFatalOrCloseNotify() bool {
	return e.Level == Fatal || e.Description == CloseNotify
}

func (e *alertError) Is(err error) bool {
	var other *alertError
	if errors.As(err, &other) {
		return e.Level == other.Level && e.Description == other.Description
	}

	return false
}

func netError(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):

		return err
	}

	var (
		ne      net.Error
		opError *net.OpError
		se      *os.SyscallError
	)

	if errors.As(err, &opError) {
		if errors.As(opError, &se) {
			if se.Timeout() {
				return &TimeoutError{Err: err}
			}
			if isOpErrorTemporary(se) {
				return &TemporaryError{Err: err}
			}
		}
	}

	if errors.As(err, &ne) {
		return err
	}

	return &FatalError{Err: err}
}

type Session struct {
	ID     []byte
	Secret []byte
}

type SessionStore interface {
	Set(key []byte, s Session) error
	Get(key []byte) (Session, error)
	Del(key []byte) error
}

type packet struct {
	record                   *RecordLayer
	shouldEncrypt            bool
	shouldWrapCID            bool
	resetLocalSequenceNumber bool
}

func defaultCompressionMethods() []*CompressionMethod {
	return []*CompressionMethod{
		{},
	}
}

func findMatchingSRTPProfile(a, b []SRTPProtectionProfile) (SRTPProtectionProfile, bool) {
	for _, aProfile := range a {
		if slices.Contains(b, aProfile) {
			return aProfile, true
		}
	}

	return 0, false
}

func findMatchingCipherSuite(a, b []CipherSuite) (CipherSuite, bool) {
	for _, aSuite := range a {
		for _, bSuite := range b {
			if aSuite.ID() == bSuite.ID() {
				return aSuite, true
			}
		}
	}

	return nil, false
}

func splitBytes(bytes []byte, splitLen int) [][]byte {
	splitBytes := make([][]byte, 0)
	numBytes := len(bytes)
	for i := 0; i < numBytes; i += splitLen {
		j := min(i+splitLen, numBytes)

		splitBytes = append(splitBytes, bytes[i:j])
	}

	return splitBytes
}

type flightVal uint8

const (
	flight0 flightVal = iota + 1
	flight1
	flight2
	flight3
	flight4
	flight4b
	flight5
	flight5b
	flight6
)

func (f flightVal) String() string {
	switch f {
	case flight0:
		return "Flight 0"
	case flight1:
		return "Flight 1"
	case flight2:
		return "Flight 2"
	case flight3:
		return "Flight 3"
	case flight4:
		return "Flight 4"
	case flight4b:
		return "Flight 4b"
	case flight5:
		return "Flight 5"
	case flight5b:
		return "Flight 5b"
	case flight6:
		return "Flight 6"
	default:
		return "Invalid Flight"
	}
}

func (f flightVal) isLastSendFlight() bool {
	return f == flight6 || f == flight5b
}

func (f flightVal) isLastRecvFlight() bool {
	return f == flight5 || f == flight4b
}

type flightParser func(
	context.Context,
	flightConn,
	*State,
	*handshakeCache,
	*handshakeConfig,
) (flightVal, *Alert, error)

type flightGenerator func(flightConn, *State, *handshakeCache, *handshakeConfig) ([]*packet, *Alert, error)

func (f flightVal) getFlightParser() (flightParser, error) {
	switch f {
	case flight0:
		return flight0Parse, nil
	case flight1:
		return flight1Parse, nil
	case flight2:
		return flight2Parse, nil
	case flight3:
		return flight3Parse, nil
	case flight4:
		return flight4Parse, nil
	case flight4b:
		return flight4bParse, nil
	case flight5:
		return flight5Parse, nil
	case flight5b:
		return flight5bParse, nil
	case flight6:
		return flight6Parse, nil
	default:
		return nil, errInvalidFlight
	}
}

func (f flightVal) getFlightGenerator() (gen flightGenerator, retransmit bool, err error) {
	switch f {
	case flight0:
		return flight0Generate, true, nil
	case flight1:
		return flight1Generate, true, nil
	case flight2:

		return flight2Generate, false, nil
	case flight3:
		return flight3Generate, true, nil
	case flight4:
		return flight4Generate, true, nil
	case flight4b:
		return flight4bGenerate, true, nil
	case flight5:
		return flight5Generate, true, nil
	case flight5b:
		return flight5bGenerate, true, nil
	case flight6:
		return flight6Generate, true, nil
	default:
		return nil, false, errInvalidFlight
	}
}

const keyLogLabelTLS12 = "CLIENT_RANDOM"

type Config struct {
	Certificates                  []tls.Certificate
	CipherSuites                  []CipherSuiteID
	CustomCipherSuites            func() []CipherSuite
	SignatureSchemes              []tls.SignatureScheme
	CertificateSignatureSchemes   []tls.SignatureScheme
	SRTPProtectionProfiles        []SRTPProtectionProfile
	SRTPMasterKeyIdentifier       []byte
	ClientAuth                    ClientAuthType
	ExtendedMasterSecret          ExtendedMasterSecretType
	FlightInterval                time.Duration
	DisableRetransmitBackoff      bool
	PSK                           PSKCallback
	PSKIdentityHint               []byte
	InsecureSkipVerify            bool
	InsecureHashes                bool
	VerifyPeerCertificate         func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	VerifyConnection              func(*State) error
	RootCAs                       *x509.CertPool
	ClientCAs                     *x509.CertPool
	ServerName                    string
	LoggerFactory                 logging.LoggerFactory
	MTU                           int
	ReplayProtectionWindow        int
	KeyLogWriter                  io.Writer
	SessionStore                  SessionStore
	SupportedProtocols            []string
	EllipticCurves                []Curve
	GetCertificate                func(*ClientHelloInfo) (*tls.Certificate, error)
	GetClientCertificate          func(*CertificateRequestInfo) (*tls.Certificate, error)
	InsecureSkipVerifyHello       bool
	ConnectionIDGenerator         func() []byte
	PaddingLengthGenerator        func(uint) uint
	HelloRandomBytesGenerator     func() [RandomBytesLength]byte
	ClientHelloMessageHook        func(MessageClientHello) Message
	ServerHelloMessageHook        func(MessageServerHello) Message
	CertificateRequestMessageHook func(MessageCertificateRequest) Message
	OnConnectionAttempt           func(net.Addr) error
}

func (c *Config) includeCertificateSuites() bool {
	return c.PSK == nil || len(c.Certificates) > 0 || c.GetCertificate != nil || c.GetClientCertificate != nil
}

const defaultMTU = 1200

var defaultCurves = []Curve{X25519, P256, P384}

type PSKCallback func([]byte) ([]byte, error)

type ClientAuthType int

const (
	NoClientCert ClientAuthType = iota
	RequestClientCert
	RequireAnyClientCert
	VerifyClientCertIfGiven
	RequireAndVerifyClientCert
)

type ExtendedMasterSecretType int

const (
	RequestExtendedMasterSecret ExtendedMasterSecretType = iota
	RequireExtendedMasterSecret
	DisableExtendedMasterSecret
)

func validateConfig(config *Config) error {
	switch {
	case config == nil:
		return errNoConfigProvided
	case config.PSKIdentityHint != nil && config.PSK == nil:
		return errIdentityNoPSK
	}

	for _, cert := range config.Certificates {
		if cert.Certificate == nil {
			return errInvalidCertificate
		}
		if cert.PrivateKey != nil {
			signer, ok := cert.PrivateKey.(crypto.Signer)
			if !ok {
				return errInvalidPrivateKey
			}
			switch signer.Public().(type) {
			case ed25519.PublicKey:
			case *ecdsa.PublicKey:
			case *rsa.PublicKey:
			default:
				return errInvalidPrivateKey
			}
		}
	}

	_, err := parseCipherSuites(
		config.CipherSuites, config.CustomCipherSuites, config.includeCertificateSuites(), config.PSK != nil,
	)

	return err
}

type ServerOption interface {
	applyServer(*dtlsConfig) error
}

type ClientOption interface {
	applyClient(*dtlsConfig) error
}

type Option interface {
	ServerOption
	ClientOption
}

func defensiveCopy[T any](t ...T) []T {
	return append([]T{}, t...)
}

type dtlsConfig struct {
	certificates                  []tls.Certificate
	cipherSuites                  []CipherSuiteID
	customCipherSuites            func() []CipherSuite
	signatureSchemes              []tls.SignatureScheme
	certificateSignatureSchemes   []tls.SignatureScheme
	srtpProtectionProfiles        []SRTPProtectionProfile
	srtpMasterKeyIdentifier       []byte
	clientAuth                    ClientAuthType
	extendedMasterSecret          ExtendedMasterSecretType
	flightInterval                time.Duration
	disableRetransmitBackoff      bool
	psk                           PSKCallback
	pskIdentityHint               []byte
	insecureSkipVerify            bool
	insecureHashes                bool
	verifyPeerCertificate         func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	verifyConnection              func(*State) error
	rootCAs                       *x509.CertPool
	clientCAs                     *x509.CertPool
	serverName                    string
	loggerFactory                 logging.LoggerFactory
	mtu                           int
	replayProtectionWindow        int
	keyLogWriter                  io.Writer
	sessionStore                  SessionStore
	supportedProtocols            []string
	ellipticCurves                []Curve
	getCertificate                func(*ClientHelloInfo) (*tls.Certificate, error)
	getClientCertificate          func(*CertificateRequestInfo) (*tls.Certificate, error)
	insecureSkipVerifyHello       bool
	connectionIDGenerator         func() []byte
	paddingLengthGenerator        func(uint) uint
	helloRandomBytesGenerator     func() [RandomBytesLength]byte
	clientHelloMessageHook        func(MessageClientHello) Message
	serverHelloMessageHook        func(MessageServerHello) Message
	certificateRequestMessageHook func(MessageCertificateRequest) Message
	onConnectionAttempt           func(net.Addr) error
}

func (c *dtlsConfig) applyDefaults() {
	c.extendedMasterSecret = RequestExtendedMasterSecret
	c.flightInterval = time.Second
	c.mtu = defaultMTU
	c.replayProtectionWindow = defaultReplayProtectionWindow
}

func (c *dtlsConfig) toConfig() *Config {
	config := &Config{
		CustomCipherSuites:            c.customCipherSuites,
		ClientAuth:                    c.clientAuth,
		ExtendedMasterSecret:          c.extendedMasterSecret,
		FlightInterval:                c.flightInterval,
		DisableRetransmitBackoff:      c.disableRetransmitBackoff,
		PSK:                           c.psk,
		InsecureSkipVerify:            c.insecureSkipVerify,
		InsecureHashes:                c.insecureHashes,
		VerifyPeerCertificate:         c.verifyPeerCertificate,
		VerifyConnection:              c.verifyConnection,
		RootCAs:                       c.rootCAs,
		ClientCAs:                     c.clientCAs,
		ServerName:                    c.serverName,
		LoggerFactory:                 c.loggerFactory,
		MTU:                           c.mtu,
		ReplayProtectionWindow:        c.replayProtectionWindow,
		KeyLogWriter:                  c.keyLogWriter,
		SessionStore:                  c.sessionStore,
		GetCertificate:                c.getCertificate,
		GetClientCertificate:          c.getClientCertificate,
		InsecureSkipVerifyHello:       c.insecureSkipVerifyHello,
		ConnectionIDGenerator:         c.connectionIDGenerator,
		PaddingLengthGenerator:        c.paddingLengthGenerator,
		HelloRandomBytesGenerator:     c.helloRandomBytesGenerator,
		ClientHelloMessageHook:        c.clientHelloMessageHook,
		ServerHelloMessageHook:        c.serverHelloMessageHook,
		CertificateRequestMessageHook: c.certificateRequestMessageHook,
		OnConnectionAttempt:           c.onConnectionAttempt,
	}

	if len(c.certificates) > 0 {
		config.Certificates = append([]tls.Certificate(nil), c.certificates...)
	}
	if len(c.cipherSuites) > 0 {
		config.CipherSuites = append([]CipherSuiteID(nil), c.cipherSuites...)
	}
	if len(c.signatureSchemes) > 0 {
		config.SignatureSchemes = append([]tls.SignatureScheme(nil), c.signatureSchemes...)
	}
	if len(c.certificateSignatureSchemes) > 0 {
		config.CertificateSignatureSchemes = append([]tls.SignatureScheme(nil), c.certificateSignatureSchemes...)
	}
	if len(c.srtpProtectionProfiles) > 0 {
		config.SRTPProtectionProfiles = append([]SRTPProtectionProfile(nil), c.srtpProtectionProfiles...)
	}
	if len(c.srtpMasterKeyIdentifier) > 0 {
		config.SRTPMasterKeyIdentifier = append([]byte(nil), c.srtpMasterKeyIdentifier...)
	}
	if len(c.pskIdentityHint) > 0 {
		config.PSKIdentityHint = append([]byte(nil), c.pskIdentityHint...)
	}
	if len(c.supportedProtocols) > 0 {
		config.SupportedProtocols = append([]string(nil), c.supportedProtocols...)
	}
	if len(c.ellipticCurves) > 0 {
		config.EllipticCurves = append([]Curve(nil), c.ellipticCurves...)
	}

	return config
}

func buildServerConfig(opts ...ServerOption) (*Config, error) {
	cfg := &dtlsConfig{}
	cfg.applyDefaults()

	for _, opt := range opts {
		if err := opt.applyServer(cfg); err != nil {
			return nil, err
		}
	}

	return cfg.toConfig(), nil
}

func buildClientConfig(opts ...ClientOption) (*Config, error) {
	cfg := &dtlsConfig{}
	cfg.applyDefaults()

	for _, opt := range opts {
		if err := opt.applyClient(cfg); err != nil {
			return nil, err
		}
	}

	return cfg.toConfig(), nil
}

type sharedOption func(*dtlsConfig) error

func (o sharedOption) applyServer(c *dtlsConfig) error { return o(c) }
func (o sharedOption) applyClient(c *dtlsConfig) error { return o(c) }

func WithCertificates(certs ...tls.Certificate) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(certs) == 0 {
			return errEmptyCertificates
		}
		c.certificates = defensiveCopy(certs...)

		return nil
	})
}

func WithCipherSuites(suites ...CipherSuiteID) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(suites) == 0 {
			return errEmptyCipherSuites
		}
		c.cipherSuites = defensiveCopy(suites...)

		return nil
	})
}

func WithCustomCipherSuites(fn func() []CipherSuite) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilCustomCipherSuites
		}
		c.customCipherSuites = fn

		return nil
	})
}

func WithSRTPProtectionProfiles(profiles ...SRTPProtectionProfile) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(profiles) == 0 {
			return errEmptySRTPProtectionProfiles
		}
		c.srtpProtectionProfiles = defensiveCopy(profiles...)

		return nil
	})
}

func WithExtendedMasterSecret(ems ExtendedMasterSecretType) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if ems < RequestExtendedMasterSecret || ems > DisableExtendedMasterSecret {
			return errInvalidExtendedMasterSecretType
		}
		c.extendedMasterSecret = ems

		return nil
	})
}

func WithFlightInterval(interval time.Duration) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if interval <= 0 {
			return errInvalidFlightInterval
		}
		c.flightInterval = interval

		return nil
	})
}

func WithInsecureSkipVerify(skip bool) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.insecureSkipVerify = skip

		return nil
	})
}

func WithVerifyPeerCertificate(fn func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilVerifyPeerCertificate
		}
		c.verifyPeerCertificate = fn

		return nil
	})
}

func WithRootCAs(pool *x509.CertPool) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.rootCAs = pool

		return nil
	})
}

func WithLoggerFactory(factory logging.LoggerFactory) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.loggerFactory = factory

		return nil
	})
}

func WithReplayProtectionWindow(window int) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if window < 0 {
			return errInvalidReplayProtectionWindow
		}
		c.replayProtectionWindow = window

		return nil
	})
}

func WithKeyLogWriter(writer io.Writer) Option {
	return sharedOption(func(c *dtlsConfig) error {
		c.keyLogWriter = writer

		return nil
	})
}

func WithSupportedProtocols(protocols ...string) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(protocols) == 0 {
			return errEmptySupportedProtocols
		}
		c.supportedProtocols = defensiveCopy(protocols...)

		return nil
	})
}

func WithEllipticCurves(curves ...Curve) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if len(curves) == 0 {
			return errEmptyEllipticCurves
		}
		c.ellipticCurves = defensiveCopy(curves...)

		return nil
	})
}

func WithClientHelloMessageHook(fn func(MessageClientHello) Message) Option {
	return sharedOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilClientHelloMessageHook
		}
		c.clientHelloMessageHook = fn

		return nil
	})
}

type serverOnlyOption func(*dtlsConfig) error

func (o serverOnlyOption) applyServer(c *dtlsConfig) error { return o(c) }

func WithClientAuth(auth ClientAuthType) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		if auth < NoClientCert || auth > RequireAndVerifyClientCert {
			return errInvalidClientAuthType
		}
		c.clientAuth = auth

		return nil
	})
}

func WithClientCAs(pool *x509.CertPool) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		c.clientCAs = pool

		return nil
	})
}

func WithInsecureSkipVerifyHello(skip bool) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		c.insecureSkipVerifyHello = skip

		return nil
	})
}

func WithServerHelloMessageHook(fn func(MessageServerHello) Message) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilServerHelloMessageHook
		}
		c.serverHelloMessageHook = fn

		return nil
	})
}

func WithCertificateRequestMessageHook(fn func(MessageCertificateRequest) Message) ServerOption {
	return serverOnlyOption(func(c *dtlsConfig) error {
		if fn == nil {
			return errNilCertificateRequestMessageHook
		}
		c.certificateRequestMessageHook = fn

		return nil
	})
}

type ClientHelloInfo struct {
	ServerName   string
	CipherSuites []CipherSuiteID
	RandomBytes  [RandomBytesLength]byte
}

type CertificateRequestInfo struct {
	AcceptableCAs [][]byte
}

func (cri *CertificateRequestInfo) SupportsCertificate(c *tls.Certificate) error {
	if len(cri.AcceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf

		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range cri.AcceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}

	return errNotAcceptableCertificateChain
}

func (c *handshakeConfig) setNameToCertificateLocked() {
	nameToCertificate := make(map[string]*tls.Certificate)
	for i := range c.localCertificates {
		cert := &c.localCertificates[i]
		x509Cert := cert.Leaf
		if x509Cert == nil {
			var parseErr error
			x509Cert, parseErr = x509.ParseCertificate(cert.Certificate[0])
			if parseErr != nil {
				continue
			}
		}
		if len(x509Cert.Subject.CommonName) > 0 {
			nameToCertificate[strings.ToLower(x509Cert.Subject.CommonName)] = cert
		}
		for _, san := range x509Cert.DNSNames {
			nameToCertificate[strings.ToLower(san)] = cert
		}
	}
	c.nameToCertificate = nameToCertificate
}

func (c *handshakeConfig) getCertificate(clientHelloInfo *ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.localGetCertificate != nil &&
		(len(c.localCertificates) == 0 || len(clientHelloInfo.ServerName) > 0) {
		cert, err := c.localGetCertificate(clientHelloInfo)
		if cert != nil || err != nil {
			return cert, err
		}
	}

	if c.nameToCertificate == nil {
		c.setNameToCertificateLocked()
	}

	if len(c.localCertificates) == 0 {
		return nil, errNoCertificates
	}

	if len(c.localCertificates) == 1 {

		return &c.localCertificates[0], nil
	}

	if len(clientHelloInfo.ServerName) == 0 {
		return &c.localCertificates[0], nil
	}

	name := strings.TrimRight(strings.ToLower(clientHelloInfo.ServerName), ".")

	if cert, ok := c.nameToCertificate[name]; ok {
		return cert, nil
	}

	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := c.nameToCertificate[candidate]; ok {
			return cert, nil
		}
	}

	return &c.localCertificates[0], nil
}

func (c *handshakeConfig) getClientCertificate(cri *CertificateRequestInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.localGetClientCertificate != nil {
		return c.localGetClientCertificate(cri)
	}

	for i := range c.localCertificates {
		chain := c.localCertificates[i]
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}

		return &chain, nil
	}

	return new(tls.Certificate), nil
}

type CipherSuiteID = ID

type CipherSuiteAuthenticationType = AuthenticationType

const (
	CipherSuiteAuthenticationTypeCertificate  CipherSuiteAuthenticationType = AuthenticationTypeCertificate
	CipherSuiteAuthenticationTypePreSharedKey CipherSuiteAuthenticationType = AuthenticationTypePreSharedKey
	CipherSuiteAuthenticationTypeAnonymous    CipherSuiteAuthenticationType = AuthenticationTypeAnonymous
)

type CipherSuiteKeyExchangeAlgorithm = KeyExchangeAlgorithm

const (
	CipherSuiteKeyExchangeAlgorithmNone  CipherSuiteKeyExchangeAlgorithm = KeyExchangeAlgorithmNone
	CipherSuiteKeyExchangeAlgorithmPsk   CipherSuiteKeyExchangeAlgorithm = KeyExchangeAlgorithmPsk
	CipherSuiteKeyExchangeAlgorithmEcdhe CipherSuiteKeyExchangeAlgorithm = KeyExchangeAlgorithmEcdhe
)

var _ = allCipherSuites()

type CipherSuite interface {
	String() string
	ID() CipherSuiteID
	CertificateType() ClientCertificateType
	HashFunc() func() hash.Hash
	AuthenticationType() CipherSuiteAuthenticationType
	KeyExchangeAlgorithm() CipherSuiteKeyExchangeAlgorithm
	ECC() bool
	Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error
	IsInitialized() bool
	Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error)
	Decrypt(h RecordLayerHeader, in []byte) ([]byte, error)
}

func cipherSuiteForID(id CipherSuiteID, customCiphers func() []CipherSuite) CipherSuite {
	switch id {
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return NewTLSEcdheEcdsaWithAes128Ccm()
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return NewTLSEcdheEcdsaWithAes128Ccm8()
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return &TLSEcdheEcdsaWithAes128GcmSha256{}
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return &TLSEcdheRsaWithAes128GcmSha256{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return &TLSEcdheEcdsaWithAes256CbcSha{}
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return &TLSEcdheRsaWithAes256CbcSha{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return &TLSEcdheEcdsaWithAes256GcmSha384{}
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return &TLSEcdheRsaWithAes256GcmSha384{}
	}

	if customCiphers != nil {
		for _, c := range customCiphers() {
			if c.ID() == id {
				return c
			}
		}
	}

	return nil
}

func defaultCipherSuites() []CipherSuite {
	return []CipherSuite{
		&TLSEcdheEcdsaWithAes128GcmSha256{},
		&TLSEcdheRsaWithAes128GcmSha256{},
		&TLSEcdheEcdsaWithAes256CbcSha{},
		&TLSEcdheRsaWithAes256CbcSha{},
		&TLSEcdheEcdsaWithAes256GcmSha384{},
		&TLSEcdheRsaWithAes256GcmSha384{},
	}
}

func allCipherSuites() []CipherSuite {
	return []CipherSuite{
		NewTLSEcdheEcdsaWithAes128Ccm(),
		NewTLSEcdheEcdsaWithAes128Ccm8(),
		&TLSEcdheEcdsaWithAes128GcmSha256{},
		&TLSEcdheRsaWithAes128GcmSha256{},
		&TLSEcdheEcdsaWithAes256CbcSha{},
		&TLSEcdheRsaWithAes256CbcSha{},
		&TLSEcdheEcdsaWithAes256GcmSha384{},
		&TLSEcdheRsaWithAes256GcmSha384{},
	}
}

func cipherSuiteIDs(cipherSuites []CipherSuite) []uint16 {
	rtrn := []uint16{}
	for _, c := range cipherSuites {
		rtrn = append(rtrn, uint16(c.ID()))
	}

	return rtrn
}

func parseCipherSuites(
	userSelectedSuites []CipherSuiteID,
	customCipherSuites func() []CipherSuite,
	includeCertificateSuites, includePSKSuites bool,
) ([]CipherSuite, error) {
	cipherSuitesForIDs := func(ids []CipherSuiteID) ([]CipherSuite, error) {
		cipherSuites := []CipherSuite{}
		for _, id := range ids {
			c := cipherSuiteForID(id, nil)
			if c == nil {
				return nil, &invalidCipherSuiteError{id}
			}
			cipherSuites = append(cipherSuites, c)
		}

		return cipherSuites, nil
	}

	var (
		cipherSuites []CipherSuite
		err          error
		i            int
	)
	if userSelectedSuites != nil {
		cipherSuites, err = cipherSuitesForIDs(userSelectedSuites)
		if err != nil {
			return nil, err
		}
	} else {
		cipherSuites = defaultCipherSuites()
	}

	if customCipherSuites != nil {
		cipherSuites = append(customCipherSuites(), cipherSuites...)
	}

	var foundCertificateSuite, foundPSKSuite, foundAnonymousSuite bool
	for _, c := range cipherSuites {
		switch {
		case includeCertificateSuites && c.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate:
			foundCertificateSuite = true
		case includePSKSuites && c.AuthenticationType() == CipherSuiteAuthenticationTypePreSharedKey:
			foundPSKSuite = true
		case c.AuthenticationType() == CipherSuiteAuthenticationTypeAnonymous:
			foundAnonymousSuite = true
		default:
			continue
		}
		cipherSuites[i] = c
		i++
	}

	switch {
	case includeCertificateSuites && !foundCertificateSuite && !foundAnonymousSuite:
		return nil, errNoAvailableCertificateCipherSuite
	case includePSKSuites && !foundPSKSuite:
		return nil, errNoAvailablePSKCipherSuite
	case i == 0:
		return nil, errNoAvailableCipherSuites
	}

	return cipherSuites[:i], nil
}

func filterCipherSuitesForCertificate(cert *tls.Certificate, cipherSuites []CipherSuite) []CipherSuite {
	if cert == nil || cert.PrivateKey == nil {
		return cipherSuites
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return cipherSuites
	}

	var certType ClientCertificateType
	switch signer.Public().(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey:
		certType = ECDSASign
	case *rsa.PublicKey:
		certType = RSASign
	}

	filtered := []CipherSuite{}
	for _, c := range cipherSuites {
		if c.AuthenticationType() != CipherSuiteAuthenticationTypeCertificate || certType == c.CertificateType() {
			filtered = append(filtered, c)
		}
	}

	return filtered
}

type ecdsaSignature struct {
	R, S *big.Int
}

func valueKeyMessage(clientRandom, serverRandom, publicKey []byte, namedCurve Curve) []byte {
	serverECDHParams := make([]byte, 4)
	serverECDHParams[0] = 3
	binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(namedCurve))
	serverECDHParams[3] = byte(len(publicKey))

	plaintext := []byte{}
	plaintext = append(plaintext, clientRandom...)
	plaintext = append(plaintext, serverRandom...)
	plaintext = append(plaintext, serverECDHParams...)
	plaintext = append(plaintext, publicKey...)

	return plaintext
}

func validateSignatureAlgOID(cert *x509.Certificate, sigAlg SignatureAlgorithm) error {
	if !sigAlg.IsPSS() {
		return nil
	}

	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return err
	}

	certOID := spki.Algorithm.Algorithm

	switch sigAlg {

	case SignatureRSA_PSS_RSAE_SHA256, SignatureRSA_PSS_RSAE_SHA384, SignatureRSA_PSS_RSAE_SHA512:
		oidPublicKeyRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
		if !certOID.Equal(oidPublicKeyRSA) {
			return errInvalidCertificateOID
		}

		return nil

	case SignatureRSA_PSS_PSS_SHA256, SignatureRSA_PSS_PSS_SHA384, SignatureRSA_PSS_PSS_SHA512:
		oidPublicKeyRSAPSS := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
		if !certOID.Equal(oidPublicKeyRSAPSS) {
			return errInvalidCertificateOID
		}

		return nil

	default:
		return nil
	}
}

func generateKeySignature(
	clientRandom, serverRandom, publicKey []byte,
	namedCurve Curve,
	signer crypto.Signer,
	hashAlgorithm HashAlgorithm,
	signatureAlgorithm SignatureAlgorithm,
) ([]byte, error) {
	msg := valueKeyMessage(clientRandom, serverRandom, publicKey, namedCurve)
	switch signer.Public().(type) {
	case ed25519.PublicKey:

		return signer.Sign(rand.Reader, msg, crypto.Hash(0))
	case *ecdsa.PublicKey:
		hashed := hashAlgorithm.Digest(msg)

		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	case *rsa.PublicKey:
		hashed := hashAlgorithm.Digest(msg)

		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}

			return signer.Sign(rand.Reader, hashed, pssOpts)
		}

		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	}

	return nil, errKeySignatureGenerateUnimplemented
}

func verifyKeySignature(
	message, remoteKeySignature []byte,
	hashAlgorithm HashAlgorithm,
	signatureAlgorithm SignatureAlgorithm,
	rawCertificates [][]byte,
) error {
	if len(rawCertificates) == 0 {
		return errLengthMismatch
	}
	certificate, err := x509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return err
	}

	if err := validateSignatureAlgOID(certificate, signatureAlgorithm); err != nil {
		return err
	}

	switch pubKey := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(pubKey, message, remoteKeySignature); !ok {
			return errKeySignatureMismatch
		}

		return nil
	case *ecdsa.PublicKey:
		ecdsaSig := &ecdsaSignature{}
		if _, err := asn1.Unmarshal(remoteKeySignature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errInvalidECDSASignature
		}
		hashed := hashAlgorithm.Digest(message)
		if !ecdsa.Verify(pubKey, hashed, ecdsaSig.R, ecdsaSig.S) {
			return errKeySignatureMismatch
		}

		return nil
	case *rsa.PublicKey:
		hashed := hashAlgorithm.Digest(message)

		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}
			if err := rsa.VerifyPSS(pubKey, hashAlgorithm.CryptoHash(), hashed, remoteKeySignature, pssOpts); err != nil {
				return errKeySignatureMismatch
			}

			return nil
		}

		if rsa.VerifyPKCS1v15(pubKey, hashAlgorithm.CryptoHash(), hashed, remoteKeySignature) != nil {
			return errKeySignatureMismatch
		}

		return nil
	}

	return errKeySignatureVerifyUnimplemented
}

func generateCertificateVerify(
	handshakeBodies []byte,
	signer crypto.Signer,
	hashAlgorithm HashAlgorithm,
	signatureAlgorithm SignatureAlgorithm,
) ([]byte, error) {
	if _, ok := signer.Public().(ed25519.PublicKey); ok {

		return signer.Sign(rand.Reader, handshakeBodies, crypto.Hash(0))
	}

	hashed := hashAlgorithm.Digest(handshakeBodies)

	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	case *rsa.PublicKey:

		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}

			return signer.Sign(rand.Reader, hashed, pssOpts)
		}

		return signer.Sign(rand.Reader, hashed, hashAlgorithm.CryptoHash())
	}

	return nil, errInvalidSignatureAlgorithm
}

func verifyCertificateVerify(
	handshakeBodies []byte,
	hashAlgorithm HashAlgorithm,
	signatureAlgorithm SignatureAlgorithm,
	remoteKeySignature []byte,
	rawCertificates [][]byte,
) error {
	if len(rawCertificates) == 0 {
		return errLengthMismatch
	}
	certificate, err := x509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return err
	}

	if err := validateSignatureAlgOID(certificate, signatureAlgorithm); err != nil {
		return err
	}

	switch pubKey := certificate.PublicKey.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(pubKey, handshakeBodies, remoteKeySignature); !ok {
			return errKeySignatureMismatch
		}

		return nil
	case *ecdsa.PublicKey:
		ecdsaSig := &ecdsaSignature{}
		if _, err := asn1.Unmarshal(remoteKeySignature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errInvalidECDSASignature
		}
		hash := hashAlgorithm.Digest(handshakeBodies)
		if !ecdsa.Verify(pubKey, hash, ecdsaSig.R, ecdsaSig.S) {
			return errKeySignatureMismatch
		}

		return nil
	case *rsa.PublicKey:
		hash := hashAlgorithm.Digest(handshakeBodies)

		if signatureAlgorithm.IsPSS() {
			pssOpts := &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlgorithm.CryptoHash(),
			}
			if err := rsa.VerifyPSS(pubKey, hashAlgorithm.CryptoHash(), hash, remoteKeySignature, pssOpts); err != nil {
				return errKeySignatureMismatch
			}

			return nil
		}

		if rsa.VerifyPKCS1v15(pubKey, hashAlgorithm.CryptoHash(), hash, remoteKeySignature) != nil {
			return errKeySignatureMismatch
		}

		return nil
	}

	return errKeySignatureVerifyUnimplemented
}

func loadCerts(rawCertificates [][]byte) ([]*x509.Certificate, error) {
	if len(rawCertificates) == 0 {
		return nil, errLengthMismatch
	}

	certs := make([]*x509.Certificate, 0, len(rawCertificates))
	for _, rawCert := range rawCertificates {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func verifyClientCert(
	rawCertificates [][]byte,
	roots *x509.CertPool,
	certSignatureSchemes []SignatureHashAlgorithm,
) (chains [][]*x509.Certificate, err error) {
	certificate, err := loadCerts(rawCertificates)
	if err != nil {
		return nil, err
	}
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certificate[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		Intermediates: intermediateCAPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	chains, err = certificate[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	if len(certSignatureSchemes) > 0 && len(chains) > 0 {
		var validChainFound bool
		for _, chain := range chains {
			if err := validateCertificateSignatureAlgorithms(chain, certSignatureSchemes); err == nil {
				validChainFound = true

				break
			}
		}
		if !validChainFound {
			return nil, errInvalidCertificateSignatureAlgorithm
		}
	}

	return chains, nil
}

func verifyServerCert(
	rawCertificates [][]byte,
	roots *x509.CertPool,
	serverName string,
	certSignatureSchemes []SignatureHashAlgorithm,
) (chains [][]*x509.Certificate, err error) {
	certificate, err := loadCerts(rawCertificates)
	if err != nil {
		return nil, err
	}
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certificate[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		DNSName:       serverName,
		Intermediates: intermediateCAPool,
	}

	chains, err = certificate[0].Verify(opts)
	if err != nil {
		return nil, err
	}

	if len(certSignatureSchemes) > 0 && len(chains) > 0 {
		var validChainFound bool
		for _, chain := range chains {
			if err := validateCertificateSignatureAlgorithms(chain, certSignatureSchemes); err == nil {
				validChainFound = true

				break
			}
		}
		if !validChainFound {
			return nil, errInvalidCertificateSignatureAlgorithm
		}
	}

	return chains, nil
}

func validateCertificateSignatureAlgorithms(
	certs []*x509.Certificate,
	allowedAlgorithms []SignatureHashAlgorithm,
) error {
	if len(allowedAlgorithms) == 0 {

		return nil
	}

	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		certAlg, err := FromCertificate(cert)
		if err != nil {
			return err
		}

		found := false
		for _, allowed := range allowedAlgorithms {
			if certAlg.Hash == allowed.Hash && certAlg.Signature == allowed.Signature {
				found = true

				break
			}
		}

		if !found {
			return errInvalidCertificateSignatureAlgorithm
		}
	}

	return nil
}

type State struct {
	localEpoch, remoteEpoch       atomic.Value
	localSequenceNumber           []uint64
	localRandom, remoteRandom     Random
	masterSecret                  []byte
	cipherSuite                   CipherSuite
	CipherSuiteID                 CipherSuiteID
	remoteSupportsRenegotiation   bool
	srtpProtectionProfile         atomic.Value
	remoteSRTPMasterKeyIdentifier []byte
	PeerCertificates              [][]byte
	IdentityHint                  []byte
	SessionID                     []byte
	localConnectionID             atomic.Value
	remoteConnectionID            []byte
	isClient                      bool
	preMasterSecret               []byte
	extendedMasterSecret          bool
	namedCurve                    Curve
	localKeypair                  *Keypair
	cookie                        []byte
	handshakeSendSequence         int
	handshakeRecvSequence         int
	serverName                    string
	remoteCertRequestAlgs         []SignatureHashAlgorithm
	remoteCertSignatureSchemes    []SignatureHashAlgorithm
	remoteRequestedCertificate    bool
	localCertificatesVerify       []byte
	localVerifyData               []byte
	localKeySignature             []byte
	peerCertificatesVerified      bool
	replayDetector                []transport.ReplayDetector
	peerSupportedProtocols        []string
	NegotiatedProtocol            string
}

type serializedState struct {
	LocalEpoch            uint16
	RemoteEpoch           uint16
	LocalRandom           [RandomLength]byte
	RemoteRandom          [RandomLength]byte
	CipherSuiteID         uint16
	MasterSecret          []byte
	SequenceNumber        uint64
	SRTPProtectionProfile uint16
	PeerCertificates      [][]byte
	IdentityHint          []byte
	SessionID             []byte
	LocalConnectionID     []byte
	RemoteConnectionID    []byte
	IsClient              bool
	NegotiatedProtocol    string
}

var errCipherSuiteNotSet = &InternalError{Err: errors.New("cipher suite not set")}

func (s *State) clone() (*State, error) {
	serialized, err := s.serialize()
	if err != nil {
		return nil, err
	}
	state := &State{}
	state.deserialize(*serialized)

	return state, err
}

func (s *State) serialize() (*serializedState, error) {
	if s.cipherSuite == nil {
		return nil, errCipherSuiteNotSet
	}
	cipherSuiteID := uint16(s.cipherSuite.ID())

	localRnd := s.localRandom.MarshalFixed()
	remoteRnd := s.remoteRandom.MarshalFixed()

	epoch := s.getLocalEpoch()

	return &serializedState{
		LocalEpoch:            s.getLocalEpoch(),
		RemoteEpoch:           s.getRemoteEpoch(),
		CipherSuiteID:         cipherSuiteID,
		MasterSecret:          s.masterSecret,
		SequenceNumber:        atomic.LoadUint64(&s.localSequenceNumber[epoch]),
		LocalRandom:           localRnd,
		RemoteRandom:          remoteRnd,
		SRTPProtectionProfile: uint16(s.getSRTPProtectionProfile()),
		PeerCertificates:      s.PeerCertificates,
		IdentityHint:          s.IdentityHint,
		SessionID:             s.SessionID,
		LocalConnectionID:     s.getLocalConnectionID(),
		RemoteConnectionID:    s.remoteConnectionID,
		IsClient:              s.isClient,
		NegotiatedProtocol:    s.NegotiatedProtocol,
	}, nil
}

func (s *State) deserialize(serialized serializedState) {

	epoch := serialized.LocalEpoch
	s.localEpoch.Store(serialized.LocalEpoch)
	s.remoteEpoch.Store(serialized.RemoteEpoch)

	for len(s.localSequenceNumber) <= int(epoch) {
		s.localSequenceNumber = append(s.localSequenceNumber, uint64(0))
	}

	localRandom := &Random{}
	localRandom.UnmarshalFixed(serialized.LocalRandom)
	s.localRandom = *localRandom

	remoteRandom := &Random{}
	remoteRandom.UnmarshalFixed(serialized.RemoteRandom)
	s.remoteRandom = *remoteRandom

	s.isClient = serialized.IsClient

	s.masterSecret = serialized.MasterSecret

	s.CipherSuiteID = CipherSuiteID(serialized.CipherSuiteID)
	s.cipherSuite = cipherSuiteForID(s.CipherSuiteID, nil)

	atomic.StoreUint64(&s.localSequenceNumber[epoch], serialized.SequenceNumber)
	s.setSRTPProtectionProfile(SRTPProtectionProfile(serialized.SRTPProtectionProfile))

	s.PeerCertificates = serialized.PeerCertificates

	s.IdentityHint = serialized.IdentityHint

	s.setLocalConnectionID(serialized.LocalConnectionID)
	s.remoteConnectionID = serialized.RemoteConnectionID

	s.SessionID = serialized.SessionID

	s.NegotiatedProtocol = serialized.NegotiatedProtocol
}

func (s *State) initCipherSuite() error {
	if s.cipherSuite.IsInitialized() {
		return nil
	}

	localRandom := s.localRandom.MarshalFixed()
	remoteRandom := s.remoteRandom.MarshalFixed()

	var err error
	if s.isClient {
		err = s.cipherSuite.Init(s.masterSecret, localRandom[:], remoteRandom[:], true)
	} else {
		err = s.cipherSuite.Init(s.masterSecret, remoteRandom[:], localRandom[:], false)
	}
	if err != nil {
		return err
	}

	return nil
}

func (s *State) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	if s.getLocalEpoch() == 0 {
		return nil, errHandshakeInProgress
	} else if len(context) != 0 {
		return nil, errContextUnsupported
	} else if _, ok := invalidKeyingLabels()[label]; ok {
		return nil, errReservedExportKeyingMaterial
	}

	localRandom := s.localRandom.MarshalFixed()
	remoteRandom := s.remoteRandom.MarshalFixed()

	seed := []byte(label)
	if s.isClient {
		seed = append(append(seed, localRandom[:]...), remoteRandom[:]...)
	} else {
		seed = append(append(seed, remoteRandom[:]...), localRandom[:]...)
	}

	return PHash(s.masterSecret, seed, length, s.cipherSuite.HashFunc())
}

func (s *State) getRemoteEpoch() uint16 {
	if remoteEpoch, ok := s.remoteEpoch.Load().(uint16); ok {
		return remoteEpoch
	}

	return 0
}

func (s *State) getLocalEpoch() uint16 {
	if localEpoch, ok := s.localEpoch.Load().(uint16); ok {
		return localEpoch
	}

	return 0
}

func (s *State) setSRTPProtectionProfile(profile SRTPProtectionProfile) {
	s.srtpProtectionProfile.Store(profile)
}

func (s *State) getSRTPProtectionProfile() SRTPProtectionProfile {
	if val, ok := s.srtpProtectionProfile.Load().(SRTPProtectionProfile); ok {
		return val
	}

	return 0
}

func (s *State) getLocalConnectionID() []byte {
	if val, ok := s.localConnectionID.Load().([]byte); ok {
		return val
	}

	return nil
}

func (s *State) setLocalConnectionID(v []byte) {
	s.localConnectionID.Store(v)
}

type handshakeCacheItem struct {
	typ             HandshakeType
	isClient        bool
	epoch           uint16
	messageSequence uint16
	data            []byte
}

type handshakeCachePullRule struct {
	typ      HandshakeType
	epoch    uint16
	isClient bool
	optional bool
}

type handshakeCache struct {
	cache []*handshakeCacheItem
	mu    sync.Mutex
}

func newHandshakeCache() *handshakeCache {
	return &handshakeCache{}
}

func (h *handshakeCache) push(data []byte, epoch, messageSequence uint16, typ HandshakeType, isClient bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cache = append(h.cache, &handshakeCacheItem{
		data:            append([]byte{}, data...),
		epoch:           epoch,
		messageSequence: messageSequence,
		typ:             typ,
		isClient:        isClient,
	})
}

func (h *handshakeCache) pull(rules ...handshakeCachePullRule) []*handshakeCacheItem {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]*handshakeCacheItem, len(rules))
	for i, r := range rules {
		for _, c := range h.cache {
			if c.typ == r.typ && c.isClient == r.isClient && c.epoch == r.epoch {
				switch {
				case out[i] == nil:
					out[i] = c
				case out[i].messageSequence < c.messageSequence:
					out[i] = c
				}
			}
		}
	}

	return out
}

func (h *handshakeCache) fullPullMap(
	startSeq int,
	cipherSuite CipherSuite,
	rules ...handshakeCachePullRule,
) (int, map[HandshakeType]Message, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ci := make(map[HandshakeType]*handshakeCacheItem)
	for _, rule := range rules {
		var item *handshakeCacheItem
		for _, c := range h.cache {
			if c.typ == rule.typ && c.isClient == rule.isClient && c.epoch == rule.epoch {
				switch {
				case item == nil:
					item = c
				case item.messageSequence < c.messageSequence:
					item = c
				}
			}
		}
		if !rule.optional && item == nil {

			return startSeq, nil, false
		}
		ci[rule.typ] = item
	}
	out := make(map[HandshakeType]Message)
	seq := startSeq
	ok := false
	for _, r := range rules {
		typ := r.typ
		i := ci[typ]
		if i == nil {
			continue
		}
		var keyExchangeAlgorithm CipherSuiteKeyExchangeAlgorithm
		if cipherSuite != nil {
			keyExchangeAlgorithm = cipherSuite.KeyExchangeAlgorithm()
		}
		rawHandshake := &Handshake{
			KeyExchangeAlgorithm: keyExchangeAlgorithm,
		}
		if err := rawHandshake.Unmarshal(i.data); err != nil {
			return startSeq, nil, false
		}
		if uint16(seq) != rawHandshake.Header.MessageSequence {

			return startSeq, nil, false
		}
		seq++
		ok = true
		out[typ] = rawHandshake.Message
	}
	if !ok {
		return seq, nil, false
	}

	return seq, out, true
}

func (h *handshakeCache) pullAndMerge(rules ...handshakeCachePullRule) []byte {
	merged := []byte{}

	for _, p := range h.pull(rules...) {
		if p != nil {
			merged = append(merged, p.data...)
		}
	}

	return merged
}

func (h *handshakeCache) sessionHash(hf HashFunc, epoch uint16, additional ...[]byte) ([]byte, error) {
	merged := []byte{}

	handshakeBuffer := h.pull(
		handshakeCachePullRule{TypeClientHello, epoch, true, false},
		handshakeCachePullRule{TypeServerHello, epoch, false, false},
		handshakeCachePullRule{TypeCertificate, epoch, false, false},
		handshakeCachePullRule{TypeServerKeyExchange, epoch, false, false},
		handshakeCachePullRule{TypeCertificateRequest, epoch, false, false},
		handshakeCachePullRule{TypeServerHelloDone, epoch, false, false},
		handshakeCachePullRule{TypeCertificate, epoch, true, false},
		handshakeCachePullRule{TypeClientKeyExchange, epoch, true, false},
	)

	for _, p := range handshakeBuffer {
		if p == nil {
			continue
		}

		merged = append(merged, p.data...)
	}
	for _, a := range additional {
		merged = append(merged, a...)
	}

	hash := hf()
	if _, err := hash.Write(merged); err != nil {
		return []byte{}, err
	}

	return hash.Sum(nil), nil
}

const (
	fragmentBufferMaxSize  = 2000000
	fragmentBufferMaxCount = 1000
)

type fragment struct {
	recordLayerHeader RecordLayerHeader
	handshakeHeader   HandshakeHeader
	data              []byte
}

type fragments struct {
	fragmentByOffset map[uint32]*fragment
	fragmentsLength  uint32
	handshakeLength  uint32
}

type fragmentBuffer struct {
	cache                        map[uint16]*fragments
	currentMessageSequenceNumber uint16
	totalBufferSize              int
	totalFragmentCount           int
}

func newFragmentBuffer() *fragmentBuffer {
	return &fragmentBuffer{cache: map[uint16]*fragments{}}
}

func (f *fragmentBuffer) size() int {
	return f.totalBufferSize
}

func (f *fragmentBuffer) push(buf []byte) (isHandshake, isRetransmit bool, err error) {
	if f.size()+len(buf) >= fragmentBufferMaxSize || f.totalFragmentCount >= fragmentBufferMaxCount {
		return false, false, errFragmentBufferOverflow
	}

	recordLayerHeader := RecordLayerHeader{}
	if err := recordLayerHeader.Unmarshal(buf); err != nil {
		return false, false, err
	}

	if recordLayerHeader.ContentType != ContentTypeHandshake {
		return false, false, nil
	}

	frag := new(fragment)
	for buf = buf[FixedHeaderSize:]; len(buf) != 0; frag = new(fragment) {
		if err := frag.handshakeHeader.Unmarshal(buf); err != nil {
			return false, false, err
		}

		isRetransmit = frag.handshakeHeader.FragmentOffset == 0 &&
			frag.handshakeHeader.MessageSequence < f.currentMessageSequenceNumber

		end := int(HandshakeHeaderLength + frag.handshakeHeader.FragmentLength)
		if end > len(buf) {
			return false, false, errBufferTooSmall
		}
		if frag.handshakeHeader.MessageSequence < f.currentMessageSequenceNumber {
			buf = buf[end:]

			continue
		}

		messageFragments, ok := f.cache[frag.handshakeHeader.MessageSequence]
		if !ok {
			messageFragments = &fragments{
				fragmentByOffset: map[uint32]*fragment{}, handshakeLength: frag.handshakeHeader.Length,
			}
			f.cache[frag.handshakeHeader.MessageSequence] = messageFragments
		}

		frag.data = append([]byte{}, buf[HandshakeHeaderLength:end]...)
		frag.recordLayerHeader = recordLayerHeader

		if _, ok = messageFragments.fragmentByOffset[frag.handshakeHeader.FragmentOffset]; !ok {
			messageFragments.fragmentByOffset[frag.handshakeHeader.FragmentOffset] = frag
			messageFragments.fragmentsLength += frag.handshakeHeader.FragmentLength
			f.totalBufferSize += int(frag.handshakeHeader.FragmentLength)
			f.totalFragmentCount++
		}
		buf = buf[end:]
	}

	return true, isRetransmit, nil
}

func (f *fragmentBuffer) pop() (content []byte, epoch uint16) {
	frags, ok := f.cache[f.currentMessageSequenceNumber]
	if !ok {
		return nil, 0
	}

	if frags.fragmentsLength != frags.handshakeLength {
		return nil, 0
	}

	var rawMessage []byte
	targetOffset := uint32(0)
	for i := 0; i < len(frags.fragmentByOffset) && targetOffset < frags.handshakeLength; i++ {
		if frag, ok := frags.fragmentByOffset[targetOffset]; ok {
			rawMessage = append(rawMessage, frag.data...)
			targetOffset = frag.handshakeHeader.FragmentOffset + frag.handshakeHeader.FragmentLength
		} else {
			return nil, 0
		}
	}

	if int(frags.handshakeLength) != len(rawMessage) {
		return nil, 0
	}

	firstHeader := frags.fragmentByOffset[0].handshakeHeader
	firstHeader.FragmentOffset = 0
	firstHeader.FragmentLength = firstHeader.Length

	rawHeader, _ := firstHeader.Marshal()

	messageEpoch := frags.fragmentByOffset[0].recordLayerHeader.Epoch

	f.totalBufferSize -= int(frags.fragmentsLength)
	f.totalFragmentCount -= len(frags.fragmentByOffset)

	delete(f.cache, f.currentMessageSequenceNumber)
	f.currentMessageSequenceNumber++

	return append(rawHeader, rawMessage...), messageEpoch
}

type handshakeState uint8

const (
	handshakeErrored handshakeState = iota
	handshakePreparing
	handshakeSending
	handshakeWaiting
	handshakeFinished
)

func (s handshakeState) String() string {
	switch s {
	case handshakeErrored:
		return "Errored"
	case handshakePreparing:
		return "Preparing"
	case handshakeSending:
		return "Sending"
	case handshakeWaiting:
		return "Waiting"
	case handshakeFinished:
		return "Finished"
	default:
		return "Unknown"
	}
}

type handshakeFSM struct {
	currentFlight      flightVal
	flights            []*packet
	retransmit         bool
	retransmitInterval time.Duration
	state              *State
	cache              *handshakeCache
	cfg                *handshakeConfig
	closed             chan struct{}
}

type handshakeConfig struct {
	localPSKCallback              PSKCallback
	localPSKIdentityHint          []byte
	localCipherSuites             []CipherSuite
	localSignatureSchemes         []SignatureHashAlgorithm
	localCertSignatureSchemes     []SignatureHashAlgorithm
	extendedMasterSecret          ExtendedMasterSecretType
	localSRTPProtectionProfiles   []SRTPProtectionProfile
	localSRTPMasterKeyIdentifier  []byte
	serverName                    string
	supportedProtocols            []string
	clientAuth                    ClientAuthType
	localCertificates             []tls.Certificate
	nameToCertificate             map[string]*tls.Certificate
	insecureSkipVerify            bool
	verifyPeerCertificate         func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	verifyConnection              func(*State) error
	sessionStore                  SessionStore
	rootCAs                       *x509.CertPool
	clientCAs                     *x509.CertPool
	initialRetransmitInterval     time.Duration
	disableRetransmitBackoff      bool
	customCipherSuites            func() []CipherSuite
	ellipticCurves                []Curve
	insecureSkipHelloVerify       bool
	connectionIDGenerator         func() []byte
	helloRandomBytesGenerator     func() [RandomBytesLength]byte
	onFlightState                 func(flightVal, handshakeState)
	log                           logging.LeveledLogger
	keyLogWriter                  io.Writer
	localGetCertificate           func(*ClientHelloInfo) (*tls.Certificate, error)
	localGetClientCertificate     func(*CertificateRequestInfo) (*tls.Certificate, error)
	initialEpoch                  uint16
	mu                            sync.Mutex
	clientHelloMessageHook        func(MessageClientHello) Message
	serverHelloMessageHook        func(MessageServerHello) Message
	certificateRequestMessageHook func(MessageCertificateRequest) Message
	resumeState                   *State
}

type flightConn interface {
	notify(ctx context.Context, level Level, desc Description) error
	writePackets(context.Context, []*packet) error
	recvHandshake() <-chan recvHandshakeState
	setLocalEpoch(epoch uint16)
	handleQueuedPackets(context.Context) error
	sessionKey() []byte
}

func (c *handshakeConfig) writeKeyLog(label string, clientRandom, secret []byte) {
	if c.keyLogWriter == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := fmt.Fprintf(c.keyLogWriter, "%s %x %x\n", label, clientRandom, secret)
	if err != nil {
		c.log.Debugf("failed to write key log file: %s", err)
	}
}

func srvCliStr(isClient bool) string {
	if isClient {
		return "client"
	}

	return "server"
}

func newHandshakeFSM(
	s *State, cache *handshakeCache, cfg *handshakeConfig,
	initialFlight flightVal,
) *handshakeFSM {
	return &handshakeFSM{
		currentFlight:      initialFlight,
		state:              s,
		cache:              cache,
		cfg:                cfg,
		retransmitInterval: cfg.initialRetransmitInterval,
		closed:             make(chan struct{}),
	}
}

func (s *handshakeFSM) Run(ctx context.Context, conn flightConn, initialState handshakeState) error {
	state := initialState
	defer func() {
		close(s.closed)
	}()
	for {
		s.cfg.log.Tracef("[handshake:%s] %s: %s", srvCliStr(s.state.isClient), s.currentFlight.String(), state.String())
		if s.cfg.onFlightState != nil {
			s.cfg.onFlightState(s.currentFlight, state)
		}
		var err error
		switch state {
		case handshakePreparing:
			state, err = s.prepare(ctx, conn)
		case handshakeSending:
			state, err = s.send(ctx, conn)
		case handshakeWaiting:
			state, err = s.wait(ctx, conn)
		case handshakeFinished:
			state, err = s.finish(ctx, conn)
		default:
			return errInvalidFSMTransition
		}
		if err != nil {
			return err
		}
	}
}

func (s *handshakeFSM) Done() <-chan struct{} {
	return s.closed
}

func (s *handshakeFSM) prepare(ctx context.Context, conn flightConn) (handshakeState, error) {
	s.flights = nil

	var (
		dtlsAlert *Alert
		err       error
		pkts      []*packet
	)
	gen, retransmit, errFlight := s.currentFlight.getFlightGenerator()
	if errFlight != nil {
		err = errFlight
		dtlsAlert = &Alert{Level: Fatal, Description: AlertInternalError}
	} else {
		pkts, dtlsAlert, err = gen(conn, s.state, s.cache, s.cfg)
		s.retransmit = retransmit
	}
	if dtlsAlert != nil {
		if alertErr := conn.notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
			if err != nil {
				err = alertErr
			}
		}
	}
	if err != nil {
		return handshakeErrored, err
	}

	s.flights = pkts
	epoch := s.cfg.initialEpoch
	nextEpoch := epoch
	for _, p := range s.flights {
		p.record.Header.Epoch += epoch
		if p.record.Header.Epoch > nextEpoch {
			nextEpoch = p.record.Header.Epoch
		}
		if h, ok := p.record.Content.(*Handshake); ok {
			h.Header.MessageSequence = uint16(s.state.handshakeSendSequence)
			s.state.handshakeSendSequence++
		}
	}
	if epoch != nextEpoch {
		s.cfg.log.Tracef("[handshake:%s] -> changeCipherSpec (epoch: %d)", srvCliStr(s.state.isClient), nextEpoch)
		conn.setLocalEpoch(nextEpoch)
	}

	return handshakeSending, nil
}

func (s *handshakeFSM) send(ctx context.Context, c flightConn) (handshakeState, error) {

	if err := c.writePackets(ctx, s.flights); err != nil {
		return handshakeErrored, err
	}

	if s.currentFlight.isLastSendFlight() {
		return handshakeFinished, nil
	}

	return handshakeWaiting, nil
}

func (s *handshakeFSM) wait(ctx context.Context, conn flightConn) (handshakeState, error) {
	parse, errFlight := s.currentFlight.getFlightParser()
	if errFlight != nil {
		if alertErr := conn.notify(ctx, Fatal, AlertInternalError); alertErr != nil {
			return handshakeErrored, alertErr
		}

		return handshakeErrored, errFlight
	}

	retransmitTimer := time.NewTimer(s.retransmitInterval)
	for {
		select {
		case state := <-conn.recvHandshake():
			if state.isRetransmit {
				close(state.done)

				continue
			}

			nextFlight, dtlsAlert, err := parse(ctx, conn, s.state, s.cache, s.cfg)
			s.retransmitInterval = s.cfg.initialRetransmitInterval
			close(state.done)
			if dtlsAlert != nil {
				if alertErr := conn.notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
					if err != nil {
						err = alertErr
					}
				}
			}
			if err != nil {
				return handshakeErrored, err
			}
			if nextFlight == 0 {
				break
			}
			s.cfg.log.Tracef(
				"[handshake:%s] %s -> %s",
				srvCliStr(s.state.isClient),
				s.currentFlight.String(),
				nextFlight.String(),
			)
			if nextFlight.isLastRecvFlight() && s.currentFlight == nextFlight {
				return handshakeFinished, nil
			}
			s.currentFlight = nextFlight

			return handshakePreparing, nil

		case <-retransmitTimer.C:
			if !s.retransmit {
				return handshakeWaiting, nil
			}

			if !s.cfg.disableRetransmitBackoff {
				s.retransmitInterval *= 2
			}
			if s.retransmitInterval > time.Second*60 {
				s.retransmitInterval = time.Second * 60
			}

			return handshakeSending, nil
		case <-ctx.Done():
			s.retransmitInterval = s.cfg.initialRetransmitInterval

			return handshakeErrored, ctx.Err()
		}
	}
}

func (s *handshakeFSM) finish(ctx context.Context, c flightConn) (handshakeState, error) {
	select {
	case state := <-c.recvHandshake():
		close(state.done)
		if s.state.isClient {
			return handshakeFinished, nil
		} else {
			return handshakeSending, nil
		}
	case <-ctx.Done():
		return handshakeErrored, ctx.Err()
	}
}

const (
	initialTickerInterval = time.Second
	cookieLength          = 20
	sessionLength         = 32
	defaultNamedCurve     = X25519
	inboundBufferSize     = 8192

	defaultReplayProtectionWindow = 64

	maxAppDataPacketQueueSize = 100
)

func invalidKeyingLabels() map[string]bool {
	return map[string]bool{
		"client finished": true,
		"server finished": true,
		"master secret":   true,
		"key expansion":   true,
	}
}

type addrPkt struct {
	rAddr net.Addr
	data  []byte
}

type recvHandshakeState struct {
	done         chan struct{}
	isRetransmit bool
}

type Conn struct {
	lock                           sync.RWMutex
	nextConn                       transport.PacketConn
	fragmentBuffer                 *fragmentBuffer
	handshakeCache                 *handshakeCache
	decrypted                      chan any
	rAddr                          net.Addr
	state                          State
	maximumTransmissionUnit        int
	paddingLengthGenerator         func(uint) uint
	handshakeCompletedSuccessfully atomic.Bool
	handshakeMutex                 sync.Mutex
	handshakeDone                  chan struct{}
	encryptedPackets               []addrPkt
	connectionClosedByUser         bool
	closeLock                      sync.Mutex
	closed                         *Closer
	readDeadline                   *transport.Deadline
	writeDeadline                  *transport.Deadline
	log                            logging.LeveledLogger
	reading                        chan struct{}
	handshakeRecv                  chan recvHandshakeState
	cancelHandshaker               func()
	cancelHandshakeReader          func()
	fsm                            *handshakeFSM
	replayProtectionWindow         uint
	handshakeConfig                *handshakeConfig
}

func createConn(
	nextConn net.PacketConn,
	rAddr net.Addr,
	config *Config,
	isClient bool,
	resumeState *State,
) (*Conn, error) {
	if nextConn == nil {
		return nil, errNilNextConn
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	logger := loggerFactory.NewLogger("dtls")

	mtu := config.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	replayProtectionWindow := config.ReplayProtectionWindow
	if replayProtectionWindow <= 0 {
		replayProtectionWindow = defaultReplayProtectionWindow
	}

	paddingLengthGenerator := config.PaddingLengthGenerator
	if paddingLengthGenerator == nil {
		paddingLengthGenerator = func(uint) uint { return 0 }
	}

	cipherSuites, err := parseCipherSuites(
		config.CipherSuites,
		config.CustomCipherSuites,
		config.includeCertificateSuites(),
		config.PSK != nil,
	)
	if err != nil {
		return nil, err
	}

	signatureSchemes, err := ParseSignatureSchemes(config.SignatureSchemes, config.InsecureHashes)
	if err != nil {
		return nil, err
	}

	var certSignatureSchemes []SignatureHashAlgorithm
	if len(config.CertificateSignatureSchemes) > 0 {
		certSignatureSchemes, err = ParseSignatureSchemes(
			config.CertificateSignatureSchemes,
			config.InsecureHashes,
		)
		if err != nil {
			return nil, err
		}
	}

	workerInterval := initialTickerInterval
	if config.FlightInterval > 0 {
		workerInterval = config.FlightInterval
	}

	serverName := config.ServerName

	if net.ParseIP(serverName) != nil {
		serverName = ""
	}

	curves := config.EllipticCurves
	if len(curves) == 0 {
		curves = defaultCurves
	}

	handshakeConfig := &handshakeConfig{
		localPSKCallback:              config.PSK,
		localPSKIdentityHint:          config.PSKIdentityHint,
		localCipherSuites:             cipherSuites,
		localSignatureSchemes:         signatureSchemes,
		localCertSignatureSchemes:     certSignatureSchemes,
		extendedMasterSecret:          config.ExtendedMasterSecret,
		localSRTPProtectionProfiles:   config.SRTPProtectionProfiles,
		localSRTPMasterKeyIdentifier:  config.SRTPMasterKeyIdentifier,
		serverName:                    serverName,
		supportedProtocols:            config.SupportedProtocols,
		clientAuth:                    config.ClientAuth,
		localCertificates:             config.Certificates,
		insecureSkipVerify:            config.InsecureSkipVerify,
		verifyPeerCertificate:         config.VerifyPeerCertificate,
		verifyConnection:              config.VerifyConnection,
		rootCAs:                       config.RootCAs,
		clientCAs:                     config.ClientCAs,
		customCipherSuites:            config.CustomCipherSuites,
		initialRetransmitInterval:     workerInterval,
		disableRetransmitBackoff:      config.DisableRetransmitBackoff,
		log:                           logger,
		initialEpoch:                  0,
		keyLogWriter:                  config.KeyLogWriter,
		sessionStore:                  config.SessionStore,
		ellipticCurves:                curves,
		localGetCertificate:           config.GetCertificate,
		localGetClientCertificate:     config.GetClientCertificate,
		insecureSkipHelloVerify:       config.InsecureSkipVerifyHello,
		connectionIDGenerator:         config.ConnectionIDGenerator,
		helloRandomBytesGenerator:     config.HelloRandomBytesGenerator,
		clientHelloMessageHook:        config.ClientHelloMessageHook,
		serverHelloMessageHook:        config.ServerHelloMessageHook,
		certificateRequestMessageHook: config.CertificateRequestMessageHook,
		resumeState:                   resumeState,
	}

	conn := &Conn{
		rAddr:                   rAddr,
		nextConn:                transport.NewPacketConn(nextConn),
		handshakeConfig:         handshakeConfig,
		fragmentBuffer:          newFragmentBuffer(),
		handshakeCache:          newHandshakeCache(),
		maximumTransmissionUnit: mtu,
		paddingLengthGenerator:  paddingLengthGenerator,

		decrypted: make(chan any, 1),
		log:       logger,

		readDeadline:  transport.NewDeadline(),
		writeDeadline: transport.NewDeadline(),

		reading:               make(chan struct{}, 1),
		handshakeRecv:         make(chan recvHandshakeState),
		closed:                NewCloser(),
		cancelHandshaker:      func() {},
		cancelHandshakeReader: func() {},

		replayProtectionWindow: uint(replayProtectionWindow),

		state: State{
			isClient: isClient,
		},
	}

	conn.setRemoteEpoch(0)
	conn.setLocalEpoch(0)

	return conn, nil
}

func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

func (c *Conn) HandshakeContext(ctx context.Context) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.isHandshakeCompletedSuccessfully() {
		return nil
	}

	handshakeDone := make(chan struct{})
	defer close(handshakeDone)
	c.closeLock.Lock()
	c.handshakeDone = handshakeDone
	c.closeLock.Unlock()

	if !c.state.isClient {
		cert, err := c.handshakeConfig.getCertificate(&ClientHelloInfo{})
		if err != nil && !errors.Is(err, errNoCertificates) {
			return err
		}
		c.handshakeConfig.localCipherSuites = filterCipherSuitesForCertificate(cert, c.handshakeConfig.localCipherSuites)
	}

	var initialFlight flightVal
	var initialFSMState handshakeState

	if c.handshakeConfig.resumeState != nil {
		if c.state.isClient {
			initialFlight = flight5
		} else {
			initialFlight = flight6
		}
		initialFSMState = handshakeFinished

		c.state = *c.handshakeConfig.resumeState
	} else {
		if c.state.isClient {
			initialFlight = flight1
		} else {
			initialFlight = flight0
		}
		initialFSMState = handshakePreparing
	}

	if err := c.handshake(ctx, c.handshakeConfig, initialFlight, initialFSMState); err != nil {
		return err
	}

	c.log.Trace("Handshake Completed")

	return nil
}

func Client(conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	switch {
	case config == nil:
		return nil, errNoConfigProvided
	case config.PSK != nil && config.PSKIdentityHint == nil:
		return nil, errPSKAndIdentityMustBeSetForClient
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return createConn(conn, rAddr, config, true, nil)
}

func ClientWithOptions(conn net.PacketConn, rAddr net.Addr, opts ...ClientOption) (*Conn, error) {
	config, err := buildClientConfig(opts...)
	if err != nil {
		return nil, err
	}

	return Client(conn, rAddr, config)
}

func serverWithConfig(conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	if config == nil {
		return nil, errNoConfigProvided
	}
	if config.OnConnectionAttempt != nil {
		if err := config.OnConnectionAttempt(rAddr); err != nil {
			return nil, err
		}
	}

	return createConn(conn, rAddr, config, false, nil)
}

func Server(conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	if config == nil {
		return nil, errNoConfigProvided
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return serverWithConfig(conn, rAddr, config)
}

func ServerWithOptions(conn net.PacketConn, rAddr net.Addr, opts ...ServerOption) (*Conn, error) {
	config, err := buildServerConfig(opts...)
	if err != nil {
		return nil, err
	}

	return Server(conn, rAddr, config)
}

func (c *Conn) Read(buff []byte) (n int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	select {
	case <-c.readDeadline.Done():
		return 0, errDeadlineExceeded
	default:
	}

	for {
		select {
		case <-c.readDeadline.Done():
			return 0, errDeadlineExceeded
		case out, ok := <-c.decrypted:
			if !ok {
				return 0, io.EOF
			}
			switch val := out.(type) {
			case ([]byte):
				if len(buff) < len(val) {
					return 0, errBufferTooSmall
				}
				copy(buff, val)

				return len(val), nil
			case (error):
				return 0, val
			}
		}
	}
}

func (c *Conn) Write(payload []byte) (int, error) {
	if c.isConnectionClosed() {
		return 0, ErrConnClosed
	}

	select {
	case <-c.writeDeadline.Done():
		return 0, errDeadlineExceeded
	default:
	}

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	return len(payload), c.writePackets(c.writeDeadline, []*packet{
		{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Epoch:   c.state.getLocalEpoch(),
					Version: Version1_2,
				},
				Content: &ApplicationData{
					Data: payload,
				},
			},
			shouldWrapCID: len(c.state.remoteConnectionID) > 0,
			shouldEncrypt: true,
		},
	})
}

func (c *Conn) Close() error {
	err := c.close(true)
	c.closeLock.Lock()
	handshakeDone := c.handshakeDone
	c.closeLock.Unlock()
	if handshakeDone != nil {
		<-handshakeDone
	}

	return err
}

func (c *Conn) ConnectionState() (State, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	stateClone, err := c.state.clone()
	if err != nil {
		return State{}, false
	}

	return *stateClone, true
}

func (c *Conn) SelectedSRTPProtectionProfile() (SRTPProtectionProfile, bool) {
	profile := c.state.getSRTPProtectionProfile()
	if profile == 0 {
		return 0, false
	}

	return profile, true
}

func (c *Conn) writePackets(ctx context.Context, pkts []*packet) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	var rawPackets [][]byte

	for _, pkt := range pkts {
		if dtlsHandshake, ok := pkt.record.Content.(*Handshake); ok {
			handshakeRaw, err := pkt.record.Marshal()
			if err != nil {
				return err
			}

			c.log.Tracef("[handshake:%v] -> %s (epoch: %d, seq: %d)",
				srvCliStr(c.state.isClient), dtlsHandshake.Header.Type.String(),
				pkt.record.Header.Epoch, dtlsHandshake.Header.MessageSequence)

			c.handshakeCache.push(
				handshakeRaw[FixedHeaderSize:],
				pkt.record.Header.Epoch,
				dtlsHandshake.Header.MessageSequence,
				dtlsHandshake.Header.Type,
				c.state.isClient,
			)

			rawHandshakePackets, err := c.processHandshakePacket(pkt, dtlsHandshake)
			if err != nil {
				return err
			}
			rawPackets = append(rawPackets, rawHandshakePackets...)
		} else {
			rawPacket, err := c.processPacket(pkt)
			if err != nil {
				return err
			}
			rawPackets = append(rawPackets, rawPacket)
		}
	}
	if len(rawPackets) == 0 {
		return nil
	}
	compactedRawPackets := c.compactRawPackets(rawPackets)

	for _, compactedRawPackets := range compactedRawPackets {
		if _, err := c.nextConn.WriteToContext(ctx, compactedRawPackets, c.rAddr); err != nil {
			return netError(err)
		}
	}

	return nil
}

func (c *Conn) compactRawPackets(rawPackets [][]byte) [][]byte {

	if len(rawPackets) == 1 {
		return rawPackets
	}

	combinedRawPackets := make([][]byte, 0)
	currentCombinedRawPacket := make([]byte, 0)

	for _, rawPacket := range rawPackets {
		if len(currentCombinedRawPacket) > 0 && len(currentCombinedRawPacket)+len(rawPacket) >= c.maximumTransmissionUnit {
			combinedRawPackets = append(combinedRawPackets, currentCombinedRawPacket)
			currentCombinedRawPacket = []byte{}
		}
		currentCombinedRawPacket = append(currentCombinedRawPacket, rawPacket...)
	}

	combinedRawPackets = append(combinedRawPackets, currentCombinedRawPacket)

	return combinedRawPackets
}

func (c *Conn) processPacket(pkt *packet) ([]byte, error) {
	epoch := pkt.record.Header.Epoch
	for len(c.state.localSequenceNumber) <= int(epoch) {
		c.state.localSequenceNumber = append(c.state.localSequenceNumber, uint64(0))
	}
	seq := atomic.AddUint64(&c.state.localSequenceNumber[epoch], 1) - 1
	if seq > MaxSequenceNumber {

		return nil, errSequenceNumberOverflow
	}
	pkt.record.Header.SequenceNumber = seq

	var rawPacket []byte
	if pkt.shouldWrapCID {

		if _, err := pkt.record.Marshal(); err != nil {
			return nil, err
		}
		content, err := pkt.record.Content.Marshal()
		if err != nil {
			return nil, err
		}
		inner := &InnerPlaintext{
			Content:  content,
			RealType: pkt.record.Header.ContentType,
		}
		rawInner, err := inner.Marshal()
		if err != nil {
			return nil, err
		}
		cidHeader := &RecordLayerHeader{
			Version:        pkt.record.Header.Version,
			ContentType:    ContentTypeConnectionID,
			Epoch:          pkt.record.Header.Epoch,
			ContentLen:     uint16(len(rawInner)),
			ConnectionID:   c.state.remoteConnectionID,
			SequenceNumber: pkt.record.Header.SequenceNumber,
		}
		rawPacket, err = cidHeader.Marshal()
		if err != nil {
			return nil, err
		}
		pkt.record.Header = *cidHeader
		rawPacket = append(rawPacket, rawInner...)
	} else {
		var err error
		rawPacket, err = pkt.record.Marshal()
		if err != nil {
			return nil, err
		}
	}

	if pkt.shouldEncrypt {
		var err error
		rawPacket, err = c.state.cipherSuite.Encrypt(pkt.record, rawPacket)
		if err != nil {
			return nil, err
		}
	}

	return rawPacket, nil
}

func (c *Conn) processHandshakePacket(pkt *packet, dtlsHandshake *Handshake) ([][]byte, error) {
	rawPackets := make([][]byte, 0)

	handshakeFragments, err := c.fragmentHandshake(dtlsHandshake)
	if err != nil {
		return nil, err
	}
	epoch := pkt.record.Header.Epoch
	for len(c.state.localSequenceNumber) <= int(epoch) {
		c.state.localSequenceNumber = append(c.state.localSequenceNumber, uint64(0))
	}

	for _, handshakeFragment := range handshakeFragments {
		seq := atomic.AddUint64(&c.state.localSequenceNumber[epoch], 1) - 1
		if seq > MaxSequenceNumber {
			return nil, errSequenceNumberOverflow
		}

		var rawPacket []byte
		if pkt.shouldWrapCID {
			inner := &InnerPlaintext{
				Content:  handshakeFragment,
				RealType: ContentTypeHandshake,
				Zeros:    c.paddingLengthGenerator(uint(len(handshakeFragment))),
			}
			rawInner, err := inner.Marshal()
			if err != nil {
				return nil, err
			}
			cidHeader := &RecordLayerHeader{
				Version:        pkt.record.Header.Version,
				ContentType:    ContentTypeConnectionID,
				Epoch:          pkt.record.Header.Epoch,
				ContentLen:     uint16(len(rawInner)),
				ConnectionID:   c.state.remoteConnectionID,
				SequenceNumber: pkt.record.Header.SequenceNumber,
			}
			rawPacket, err = cidHeader.Marshal()
			if err != nil {
				return nil, err
			}
			pkt.record.Header = *cidHeader
			rawPacket = append(rawPacket, rawInner...)
		} else {
			recordlayerHeader := &RecordLayerHeader{
				Version:        pkt.record.Header.Version,
				ContentType:    pkt.record.Header.ContentType,
				ContentLen:     uint16(len(handshakeFragment)),
				Epoch:          pkt.record.Header.Epoch,
				SequenceNumber: seq,
			}

			rawPacket, err = recordlayerHeader.Marshal()
			if err != nil {
				return nil, err
			}

			pkt.record.Header = *recordlayerHeader
			rawPacket = append(rawPacket, handshakeFragment...)
		}

		if pkt.shouldEncrypt {
			var err error
			rawPacket, err = c.state.cipherSuite.Encrypt(pkt.record, rawPacket)
			if err != nil {
				return nil, err
			}
		}

		rawPackets = append(rawPackets, rawPacket)
	}

	return rawPackets, nil
}

func (c *Conn) fragmentHandshake(dtlsHandshake *Handshake) ([][]byte, error) {
	content, err := dtlsHandshake.Message.Marshal()
	if err != nil {
		return nil, err
	}

	fragmentedHandshakes := make([][]byte, 0)

	contentFragments := splitBytes(content, c.maximumTransmissionUnit)
	if len(contentFragments) == 0 {
		contentFragments = [][]byte{
			{},
		}
	}

	offset := 0
	for _, contentFragment := range contentFragments {
		contentFragmentLen := len(contentFragment)

		headerFragment := &HandshakeHeader{
			Type:            dtlsHandshake.Header.Type,
			Length:          dtlsHandshake.Header.Length,
			MessageSequence: dtlsHandshake.Header.MessageSequence,
			FragmentOffset:  uint32(offset),
			FragmentLength:  uint32(contentFragmentLen),
		}

		offset += contentFragmentLen

		fragmentedHandshake, err := headerFragment.Marshal()
		if err != nil {
			return nil, err
		}

		fragmentedHandshake = append(fragmentedHandshake, contentFragment...)
		fragmentedHandshakes = append(fragmentedHandshakes, fragmentedHandshake)
	}

	return fragmentedHandshakes, nil
}

var poolReadBuffer = sync.Pool{
	New: func() any {
		b := make([]byte, inboundBufferSize)

		return &b
	},
}

func (c *Conn) readAndBuffer(ctx context.Context) error {
	bufptr, ok := poolReadBuffer.Get().(*[]byte)
	if !ok {
		return errFailedToAccessPoolReadBuffer
	}
	defer poolReadBuffer.Put(bufptr)

	b := *bufptr
	i, rAddr, err := c.nextConn.ReadFromContext(ctx, b)
	if err != nil {
		return netError(err)
	}

	pkts, err := ContentAwareUnpackDatagram(b[:i], len(c.state.getLocalConnectionID()))
	if err != nil {
		return err
	}

	var hasHandshake, isRetransmit bool
	for _, p := range pkts {
		hs, rtx, dtlsAlert, err := c.handleIncomingPacket(ctx, p, rAddr, true)
		if dtlsAlert != nil {
			if alertErr := c.notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
				if err == nil {
					err = alertErr
				}
			}
		}

		var e *alertError
		if errors.As(err, &e) && e.IsFatalOrCloseNotify() {
			return e
		}
		if err != nil {
			return err
		}
		if hs {
			hasHandshake = true
		}
		if rtx {
			isRetransmit = true
		}
	}
	if hasHandshake {
		s := recvHandshakeState{
			done:         make(chan struct{}),
			isRetransmit: isRetransmit,
		}
		select {
		case c.handshakeRecv <- s:

			<-s.done
		case <-c.fsm.Done():
		}
	}

	return nil
}

func (c *Conn) handleQueuedPackets(ctx context.Context) error {
	c.lock.Lock()
	pkts := c.encryptedPackets
	c.encryptedPackets = nil
	c.lock.Unlock()

	for _, p := range pkts {
		_, _, dtlsAlert, err := c.handleIncomingPacket(ctx, p.data, p.rAddr, false)
		if dtlsAlert != nil {
			if alertErr := c.notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil {
				if err == nil {
					err = alertErr
				}
			}
		}
		var e *alertError
		if errors.As(err, &e) && e.IsFatalOrCloseNotify() {
			return e
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) enqueueEncryptedPackets(packet addrPkt) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	if len(c.encryptedPackets) < maxAppDataPacketQueueSize {
		c.encryptedPackets = append(c.encryptedPackets, packet)

		return true
	}

	return false
}

func (c *Conn) handleIncomingPacket(
	ctx context.Context,
	buf []byte,
	rAddr net.Addr,
	enqueue bool,
) (bool, bool, *Alert, error) {
	header := &RecordLayerHeader{}

	if len(c.state.getLocalConnectionID()) > 0 {
		header.ConnectionID = make([]byte, len(c.state.getLocalConnectionID()))
	}
	if err := header.Unmarshal(buf); err != nil {

		c.log.Debugf("discarded broken packet: %v", err)

		return false, false, nil, nil
	}

	remoteEpoch := c.state.getRemoteEpoch()
	if header.Epoch > remoteEpoch {
		if header.Epoch > remoteEpoch+1 {
			c.log.Debugf("discarded future packet (epoch: %d, seq: %d)",
				header.Epoch, header.SequenceNumber,
			)

			return false, false, nil, nil
		}
		if enqueue {
			if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
				c.log.Debug("received packet of next epoch, queuing packet")
			}
		}

		return false, false, nil, nil
	}

	for len(c.state.replayDetector) <= int(header.Epoch) {
		c.state.replayDetector = append(c.state.replayDetector,
			transport.NewReplayDetector(c.replayProtectionWindow, MaxSequenceNumber),
		)
	}
	markPacketAsValid, ok := c.state.replayDetector[int(header.Epoch)].Check(header.SequenceNumber)
	if !ok {
		c.log.Debugf("discarded duplicated packet (epoch: %d, seq: %d)",
			header.Epoch, header.SequenceNumber,
		)

		return false, false, nil, nil
	}

	originalCID := false

	if header.Epoch != 0 {
		if c.state.cipherSuite == nil || !c.state.cipherSuite.IsInitialized() {
			if enqueue {
				if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
					c.log.Debug("handshake not finished, queuing packet")
				}
			}

			return false, false, nil, nil
		}

		if len(c.state.getLocalConnectionID()) > 0 && header.ContentType != ContentTypeConnectionID {
			c.log.Debug("discarded packet missing connection ID after value negotiated")

			return false, false, nil, nil
		}

		var err error
		var hdr RecordLayerHeader
		if header.ContentType == ContentTypeConnectionID {
			hdr.ConnectionID = make([]byte, len(c.state.getLocalConnectionID()))
		}
		buf, err = c.state.cipherSuite.Decrypt(hdr, buf)
		if err != nil {
			c.log.Debugf("%s: decrypt failed: %s", srvCliStr(c.state.isClient), err)

			return false, false, nil, nil
		}

		if header.ContentType == ContentTypeConnectionID {
			originalCID = true
			ip := &InnerPlaintext{}
			if err := ip.Unmarshal(buf[header.Size():]); err != nil {
				c.log.Debugf("unpacking inner plaintext failed: %s", err)

				return false, false, nil, nil
			}
			unpacked := &RecordLayerHeader{
				ContentType:    ip.RealType,
				ContentLen:     uint16(len(ip.Content)),
				Version:        header.Version,
				Epoch:          header.Epoch,
				SequenceNumber: header.SequenceNumber,
			}
			buf, err = unpacked.Marshal()
			if err != nil {
				c.log.Debugf("converting CID record to inner plaintext failed: %s", err)

				return false, false, nil, nil
			}
			buf = append(buf, ip.Content...)
		}

		if !bytes.Equal(c.state.getLocalConnectionID(), header.ConnectionID) {
			c.log.Debug("unexpected connection ID")

			return false, false, nil, nil
		}
	}

	isHandshake, isRetransmit, err := c.fragmentBuffer.push(append([]byte{}, buf...))
	if err != nil {

		c.log.Debugf("defragment failed: %s", err)

		return false, false, nil, nil
	} else if isHandshake {
		markPacketAsValid()

		for out, epoch := c.fragmentBuffer.pop(); out != nil; out, epoch = c.fragmentBuffer.pop() {
			header := &HandshakeHeader{}
			if err := header.Unmarshal(out); err != nil {
				c.log.Debugf("%s: handshake parse failed: %s", srvCliStr(c.state.isClient), err)

				continue
			}
			c.handshakeCache.push(out, epoch, header.MessageSequence, header.Type, !c.state.isClient)
		}

		return true, isRetransmit, nil, nil
	}

	r := &RecordLayer{}
	if err := r.Unmarshal(buf); err != nil {
		return false, false, &Alert{Level: Fatal, Description: DecodeError}, err
	}

	isLatestSeqNum := false
	switch content := r.Content.(type) {
	case *Alert:
		c.log.Tracef("%s: <- %s", srvCliStr(c.state.isClient), content.String())
		var a *Alert
		if content.Description == CloseNotify {

			a = &Alert{Level: Warning, Description: CloseNotify}
		}
		_ = markPacketAsValid()

		return false, false, a, &alertError{content}
	case *ChangeCipherSpec:
		if c.state.cipherSuite == nil || !c.state.cipherSuite.IsInitialized() {
			if enqueue {
				if ok := c.enqueueEncryptedPackets(addrPkt{rAddr, buf}); ok {
					c.log.Debugf("CipherSuite not initialized, queuing packet")
				}
			}

			return false, false, nil, nil
		}

		newRemoteEpoch := header.Epoch + 1
		c.log.Tracef("%s: <- ChangeCipherSpec (epoch: %d)", srvCliStr(c.state.isClient), newRemoteEpoch)

		if c.state.getRemoteEpoch()+1 == newRemoteEpoch {
			c.setRemoteEpoch(newRemoteEpoch)
			isLatestSeqNum = markPacketAsValid()
		}
	case *ApplicationData:
		if header.Epoch == 0 {
			return false, false, &Alert{
				Level: Fatal, Description: UnexpectedMessage,
			}, errApplicationDataEpochZero
		}

		isLatestSeqNum = markPacketAsValid()

		select {
		case c.decrypted <- content.Data:
		case <-c.closed.Done():
		case <-ctx.Done():
		}

	default:
		return false, false, &Alert{
			Level: Fatal, Description: UnexpectedMessage,
		}, fmt.Errorf("%w: %d", errUnhandledContextType, content.ContentType())
	}

	if originalCID && isLatestSeqNum {
		if rAddr != c.RemoteAddr() {
			c.lock.Lock()
			c.rAddr = rAddr
			c.lock.Unlock()
		}
	}

	return false, false, nil, nil
}

func (c *Conn) recvHandshake() <-chan recvHandshakeState {
	return c.handshakeRecv
}

func (c *Conn) notify(ctx context.Context, level Level, desc Description) error {
	if level == Fatal && len(c.state.SessionID) > 0 {

		if ss := c.fsm.cfg.sessionStore; ss != nil {
			c.log.Tracef("clean invalid session: %s", c.state.SessionID)
			if err := ss.Del(c.sessionKey()); err != nil {
				return err
			}
		}
	}

	return c.writePackets(ctx, []*packet{
		{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Epoch:   c.state.getLocalEpoch(),
					Version: Version1_2,
				},
				Content: &Alert{
					Level:       level,
					Description: desc,
				},
			},
			shouldWrapCID: len(c.state.remoteConnectionID) > 0,
			shouldEncrypt: c.isHandshakeCompletedSuccessfully(),
		},
	})
}

func (c *Conn) setHandshakeCompletedSuccessfully() bool {
	return c.handshakeCompletedSuccessfully.CompareAndSwap(false, true)
}

func (c *Conn) isHandshakeCompletedSuccessfully() bool {
	return c.handshakeCompletedSuccessfully.Load()
}

func (c *Conn) handshake(
	ctx context.Context,
	cfg *handshakeConfig,
	initialFlight flightVal,
	initialState handshakeState,
) error {
	c.fsm = newHandshakeFSM(&c.state, c.handshakeCache, cfg, initialFlight)

	done := make(chan struct{})
	ctxRead, cancelRead := context.WithCancel(context.Background())
	cfg.onFlightState = func(_ flightVal, s handshakeState) {
		if s == handshakeFinished && c.setHandshakeCompletedSuccessfully() {
			close(done)
		}
	}

	ctxHs, cancel := context.WithCancel(context.Background())

	c.closeLock.Lock()
	c.cancelHandshaker = cancel
	c.cancelHandshakeReader = cancelRead
	c.closeLock.Unlock()

	firstErr := make(chan error, 1)

	var handshakeLoopsFinished sync.WaitGroup
	handshakeLoopsFinished.Add(2)

	go func() {
		defer handshakeLoopsFinished.Done()
		err := c.fsm.Run(ctxHs, c, initialState)
		if !errors.Is(err, context.Canceled) {
			select {
			case firstErr <- err:
			default:
			}
		}
	}()
	go func() {
		defer func() {
			if c.isHandshakeCompletedSuccessfully() {

				close(c.decrypted)
			}

			cancel()
		}()
		defer handshakeLoopsFinished.Done()
		for {
			if err := c.readAndBuffer(ctxRead); err != nil {
				var alertErr *alertError
				if errors.As(err, &alertErr) {
					if !alertErr.IsFatalOrCloseNotify() {
						if c.isHandshakeCompletedSuccessfully() {

							select {
							case c.decrypted <- err:
							case <-c.closed.Done():
							case <-ctxRead.Done():
							}
						}

						continue
					}
				} else {
					switch {
					case errors.Is(err, context.DeadlineExceeded),
						errors.Is(err, context.Canceled),
						errors.Is(err, io.EOF),
						errors.Is(err, net.ErrClosed):
					case errors.Is(err, ErrInvalidPacketLength):

						continue
					default:
						if c.isHandshakeCompletedSuccessfully() {

							select {
							case c.decrypted <- err:
							case <-c.closed.Done():
							case <-ctxRead.Done():
							}

							continue
						}
					}
				}

				select {
				case firstErr <- err:
				default:
				}

				if alertErr != nil {
					if alertErr.IsFatalOrCloseNotify() {
						_ = c.close(false)
					}
				}
				if !c.isConnectionClosed() && errors.Is(err, context.Canceled) {
					c.log.Trace("handshake timeouts - closing underline connection")
					_ = c.close(false)
				}

				return
			}
		}
	}()

	select {
	case err := <-firstErr:
		cancelRead()
		cancel()
		handshakeLoopsFinished.Wait()

		return c.translateHandshakeCtxError(err)
	case <-ctx.Done():
		cancelRead()
		cancel()
		handshakeLoopsFinished.Wait()

		return c.translateHandshakeCtxError(ctx.Err())
	case <-done:
		return nil
	}
}

func (c *Conn) translateHandshakeCtxError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) && c.isHandshakeCompletedSuccessfully() {
		return nil
	}

	return &HandshakeError{Err: err}
}

func (c *Conn) close(byUser bool) error {
	c.closeLock.Lock()
	cancelHandshaker := c.cancelHandshaker
	cancelHandshakeReader := c.cancelHandshakeReader
	c.closeLock.Unlock()

	cancelHandshaker()
	cancelHandshakeReader()

	if c.isHandshakeCompletedSuccessfully() && byUser {

		_ = c.notify(context.Background(), Warning, CloseNotify)
	}

	c.closeLock.Lock()

	closedByUser := c.connectionClosedByUser
	if byUser {
		c.connectionClosedByUser = true
	}
	isClosed := c.isConnectionClosed()
	c.closed.Close()
	c.closeLock.Unlock()

	if closedByUser {
		return ErrConnClosed
	}

	if isClosed {
		return nil
	}

	return c.nextConn.Close()
}

func (c *Conn) isConnectionClosed() bool {
	select {
	case <-c.closed.Done():
		return true
	default:
		return false
	}
}

func (c *Conn) setLocalEpoch(epoch uint16) {
	c.state.localEpoch.Store(epoch)
}

func (c *Conn) setRemoteEpoch(epoch uint16) {
	c.state.remoteEpoch.Store(epoch)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.nextConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.rAddr
}

func (c *Conn) sessionKey() []byte {
	if c.state.isClient {

		return []byte(c.rAddr.String() + "_" + c.fsm.cfg.serverName)
	}

	return c.state.SessionID
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)

	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)

	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)

	return nil
}

const renegotiationInfoSCSV uint16 = 0x00ff

func flight0Parse(
	_ context.Context,
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {
	seq, msgs, ok := cache.fullPullMap(0, state.cipherSuite,
		handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
	)
	if !ok {

		return 0, nil, nil
	}

	state.setLocalConnectionID(nil)
	state.remoteConnectionID = nil

	state.handshakeRecvSequence = seq

	var clientHello *MessageClientHello

	if clientHello, ok = msgs[TypeClientHello].(*MessageClientHello); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}

	if !clientHello.Version.Equal(Version1_2) {
		return 0, &Alert{Level: Fatal, Description: ProtocolVersion}, errUnsupportedProtocolVersion
	}

	state.remoteRandom = clientHello.Random

	cipherSuites := []CipherSuite{}
	for _, id := range clientHello.CipherSuiteIDs {
		if id == renegotiationInfoSCSV {
			state.remoteSupportsRenegotiation = true

			continue
		}
		if c := cipherSuiteForID(CipherSuiteID(id), cfg.customCipherSuites); c != nil {
			cipherSuites = append(cipherSuites, c)
		}
	}

	if state.cipherSuite, ok = findMatchingCipherSuite(cipherSuites, cfg.localCipherSuites); !ok {
		return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errCipherSuiteNoIntersection
	}

	for _, val := range clientHello.Extensions {
		switch ext := val.(type) {
		case *SupportedEllipticCurves:
			if len(ext.EllipticCurves) == 0 {
				return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errNoSupportedEllipticCurves
			}
			state.namedCurve = ext.EllipticCurves[0]
		case *UseSRTP:
			profile, ok := findMatchingSRTPProfile(cfg.localSRTPProtectionProfiles, ext.ProtectionProfiles)
			if !ok {
				return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errServerNoMatchingSRTPProfile
			}
			state.setSRTPProtectionProfile(profile)
			state.remoteSRTPMasterKeyIdentifier = ext.MasterKeyIdentifier
		case *UseExtendedMasterSecret:
			if cfg.extendedMasterSecret != DisableExtendedMasterSecret {
				state.extendedMasterSecret = true
			}
		case *ServerName:
			state.serverName = ext.ServerName
		case *RenegotiationInfo:
			state.remoteSupportsRenegotiation = true
		case *ALPN:
			state.peerSupportedProtocols = ext.ProtocolNameList
		case *ConnectionID:

			if cfg.connectionIDGenerator != nil {
				state.remoteConnectionID = ext.CID
			}
		case *SignatureAlgorithmsCert:

			state.remoteCertSignatureSchemes = ext.SignatureHashAlgorithms
		}
	}

	if state.remoteConnectionID == nil {
		state.setLocalConnectionID(nil)
	}

	if cfg.extendedMasterSecret == RequireExtendedMasterSecret && !state.extendedMasterSecret {
		return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errServerRequiredButNoClientEMS
	}

	if state.localKeypair == nil {
		var err error
		state.localKeypair, err = GenerateKeypair(state.namedCurve)
		if err != nil {
			return 0, &Alert{Level: Fatal, Description: IllegalParameter}, err
		}
	}

	nextFlight := flight2

	if cfg.insecureSkipHelloVerify {
		nextFlight = flight4
	}

	return handleHelloResume(clientHello.SessionID, state, cfg, nextFlight)
}

func handleHelloResume(
	sessionID []byte,
	state *State,
	cfg *handshakeConfig,
	next flightVal,
) (flightVal, *Alert, error) {
	if len(sessionID) > 0 && cfg.sessionStore != nil {
		if s, err := cfg.sessionStore.Get(sessionID); err != nil {
			return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
		} else if s.ID != nil {
			cfg.log.Tracef("[handshake] resume session: %x", sessionID)

			state.SessionID = sessionID
			state.masterSecret = s.Secret

			if err := state.initCipherSuite(); err != nil {
				return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
			}

			clientRandom := state.localRandom.MarshalFixed()
			cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)

			return flight4b, nil, nil
		}
	}

	return next, nil, nil
}

func flight0Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *Alert, error) {

	if !cfg.insecureSkipHelloVerify {
		state.cookie = make([]byte, cookieLength)
		if _, err := rand.Read(state.cookie); err != nil {
			return nil, nil, err
		}
	}

	var zeroEpoch uint16
	state.localEpoch.Store(zeroEpoch)
	state.remoteEpoch.Store(zeroEpoch)
	state.namedCurve = defaultNamedCurve

	if err := state.localRandom.Populate(); err != nil {
		return nil, nil, err
	}

	return nil, nil, nil
}

func flight1Parse(
	ctx context.Context,
	conn flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {

	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{TypeHelloVerifyRequest, cfg.initialEpoch, false, true},
		handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, true},
	)
	if !ok {

		return 0, nil, nil
	}

	if _, ok := msgs[TypeServerHello]; ok {

		return flight3Parse(ctx, conn, state, cache, cfg)
	}

	if h, ok := msgs[TypeHelloVerifyRequest].(*MessageHelloVerifyRequest); ok {

		if !h.Version.Equal(Version1_0) && !h.Version.Equal(Version1_2) {
			return 0, &Alert{Level: Fatal, Description: ProtocolVersion}, errUnsupportedProtocolVersion
		}
		state.cookie = append([]byte{}, h.Cookie...)
		state.handshakeRecvSequence = seq

		return flight3, nil, nil
	}

	return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
}

func flight1Generate(
	conn flightConn,
	state *State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *Alert, error) {
	var zeroEpoch uint16
	state.localEpoch.Store(zeroEpoch)
	state.remoteEpoch.Store(zeroEpoch)
	state.namedCurve = defaultNamedCurve
	state.cookie = nil

	if err := state.localRandom.Populate(); err != nil {
		return nil, nil, err
	}

	if cfg.helloRandomBytesGenerator != nil {
		state.localRandom.RandomBytes = cfg.helloRandomBytesGenerator()
	}

	extensions := []Extension{
		&SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.localSignatureSchemes,
		},
		&RenegotiationInfo{
			RenegotiatedConnection: 0,
		},
	}

	if len(cfg.localCertSignatureSchemes) > 0 {
		extensions = append(extensions, &SignatureAlgorithmsCert{
			SignatureHashAlgorithms: cfg.localCertSignatureSchemes,
		})
	}

	var setEllipticCurveCryptographyClientHelloExtensions bool
	for _, c := range cfg.localCipherSuites {
		if c.ECC() {
			setEllipticCurveCryptographyClientHelloExtensions = true

			break
		}
	}

	if setEllipticCurveCryptographyClientHelloExtensions {
		extensions = append(extensions, []Extension{
			&SupportedEllipticCurves{
				EllipticCurves: cfg.ellipticCurves,
			},
			&SupportedPointFormats{
				PointFormats: []CurvePointFormat{CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.localSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &UseSRTP{
			ProtectionProfiles:  cfg.localSRTPProtectionProfiles,
			MasterKeyIdentifier: cfg.localSRTPMasterKeyIdentifier,
		})
	}

	if cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret {
		extensions = append(extensions, &UseExtendedMasterSecret{
			Supported: true,
		})
	}

	if len(cfg.serverName) > 0 {
		extensions = append(extensions, &ServerName{ServerName: cfg.serverName})
	}

	if len(cfg.supportedProtocols) > 0 {
		extensions = append(extensions, &ALPN{ProtocolNameList: cfg.supportedProtocols})
	}

	if cfg.sessionStore != nil {
		cfg.log.Tracef("[handshake] try to resume session")
		if s, err := cfg.sessionStore.Get(conn.sessionKey()); err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		} else if s.ID != nil {
			cfg.log.Tracef("[handshake] get saved session: %x", s.ID)

			state.SessionID = s.ID
			state.masterSecret = s.Secret
		}
	}

	if cfg.connectionIDGenerator != nil {
		state.setLocalConnectionID(cfg.connectionIDGenerator())

		if state.getLocalConnectionID() == nil {
			state.setLocalConnectionID([]byte{})
		}
		extensions = append(extensions, &ConnectionID{CID: state.getLocalConnectionID()})
	}

	clientHello := &MessageClientHello{
		Version:            Version1_2,
		SessionID:          state.SessionID,
		Cookie:             state.cookie,
		Random:             state.localRandom,
		CipherSuiteIDs:     cipherSuiteIDs(cfg.localCipherSuites),
		CompressionMethods: defaultCompressionMethods(),
		Extensions:         extensions,
	}

	var content Handshake

	if cfg.clientHelloMessageHook != nil {
		content = Handshake{Message: cfg.clientHelloMessageHook(*clientHello)}
	} else {
		content = Handshake{Message: clientHello}
	}

	return []*packet{
		{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &content,
			},
		},
	}, nil, nil
}

func flight2Parse(
	ctx context.Context,
	c flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
	)
	if !ok {

		return flight0Parse(ctx, c, state, cache, cfg)
	}
	state.handshakeRecvSequence = seq

	var clientHello *MessageClientHello

	if clientHello, ok = msgs[TypeClientHello].(*MessageClientHello); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}

	if !clientHello.Version.Equal(Version1_2) {
		return 0, &Alert{Level: Fatal, Description: ProtocolVersion}, errUnsupportedProtocolVersion
	}

	if len(clientHello.Cookie) == 0 {
		return 0, nil, nil
	}
	if !bytes.Equal(state.cookie, clientHello.Cookie) {
		return 0, &Alert{Level: Fatal, Description: AccessDenied}, errCookieMismatch
	}

	return flight4, nil, nil
}

func flight2Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	_ *handshakeConfig,
) ([]*packet, *Alert, error) {
	state.handshakeSendSequence = 0

	return []*packet{
		{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &Handshake{
					Message: &MessageHelloVerifyRequest{
						Version: Version1_2,
						Cookie:  state.cookie,
					},
				},
			},
		},
	}, nil, nil
}

func flight3Parse(
	ctx context.Context,
	conn flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {

	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{TypeHelloVerifyRequest, cfg.initialEpoch, false, true},
	)
	if ok {
		if h, msgOk := msgs[TypeHelloVerifyRequest].(*MessageHelloVerifyRequest); msgOk {

			if !h.Version.Equal(Version1_0) && !h.Version.Equal(Version1_2) {
				return 0, &Alert{Level: Fatal, Description: ProtocolVersion}, errUnsupportedProtocolVersion
			}
			state.cookie = append([]byte{}, h.Cookie...)
			state.handshakeRecvSequence = seq

			return flight3, nil, nil
		}
	}

	_, msgs, ok = cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
	)
	if !ok {

		return 0, nil, nil
	}

	if serverHelloMsg, msgOk := msgs[TypeServerHello].(*MessageServerHello); msgOk {
		if !serverHelloMsg.Version.Equal(Version1_2) {
			return 0, &Alert{Level: Fatal, Description: ProtocolVersion}, errUnsupportedProtocolVersion
		}
		for _, v := range serverHelloMsg.Extensions {
			switch ext := v.(type) {
			case *UseSRTP:
				profile, found := findMatchingSRTPProfile(ext.ProtectionProfiles, cfg.localSRTPProtectionProfiles)
				if !found {
					return 0, &Alert{Level: Fatal, Description: IllegalParameter}, errClientNoMatchingSRTPProfile
				}
				state.setSRTPProtectionProfile(profile)
				state.remoteSRTPMasterKeyIdentifier = ext.MasterKeyIdentifier
			case *UseExtendedMasterSecret:
				if cfg.extendedMasterSecret != DisableExtendedMasterSecret {
					state.extendedMasterSecret = true
				}
			case *ALPN:
				if len(ext.ProtocolNameList) > 1 {
					return 0, &Alert{
						Level:       Fatal,
						Description: AlertInternalError,
					}, ErrALPNInvalidFormat
				}
				state.NegotiatedProtocol = ext.ProtocolNameList[0]
			case *ConnectionID:

				if cfg.connectionIDGenerator != nil {
					state.remoteConnectionID = ext.CID
				}
			}
		}

		if state.remoteConnectionID == nil {
			state.setLocalConnectionID(nil)
		}

		if cfg.extendedMasterSecret == RequireExtendedMasterSecret && !state.extendedMasterSecret {
			return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errClientRequiredButNoServerEMS
		}
		if len(cfg.localSRTPProtectionProfiles) > 0 && state.getSRTPProtectionProfile() == 0 {
			return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errRequestedButNoSRTPExtension
		}

		remoteCipherSuite := cipherSuiteForID(CipherSuiteID(*serverHelloMsg.CipherSuiteID), cfg.customCipherSuites)
		if remoteCipherSuite == nil {
			return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errCipherSuiteNoIntersection
		}

		selectedCipherSuite, found := findMatchingCipherSuite([]CipherSuite{remoteCipherSuite}, cfg.localCipherSuites)
		if !found {
			return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errInvalidCipherSuite
		}

		state.cipherSuite = selectedCipherSuite
		state.remoteRandom = serverHelloMsg.Random
		cfg.log.Tracef("[handshake] use cipher suite: %s", selectedCipherSuite.String())

		if len(serverHelloMsg.SessionID) > 0 && bytes.Equal(state.SessionID, serverHelloMsg.SessionID) {
			return handleResumption(ctx, conn, state, cache, cfg)
		}

		if len(state.SessionID) > 0 {
			cfg.log.Tracef("[handshake] clean old session : %s", state.SessionID)
			if err := cfg.sessionStore.Del(state.SessionID); err != nil {
				return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
			}
		}

		if cfg.sessionStore == nil {
			state.SessionID = []byte{}
		} else {
			state.SessionID = serverHelloMsg.SessionID
		}

		state.masterSecret = []byte{}
	}

	if cfg.localPSKCallback != nil {
		seq, msgs, ok = cache.fullPullMap(state.handshakeRecvSequence+1, state.cipherSuite,
			handshakeCachePullRule{TypeServerKeyExchange, cfg.initialEpoch, false, true},
			handshakeCachePullRule{TypeServerHelloDone, cfg.initialEpoch, false, false},
		)
	} else {
		seq, msgs, ok = cache.fullPullMap(state.handshakeRecvSequence+1, state.cipherSuite,
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, false, true},
			handshakeCachePullRule{TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificateRequest, cfg.initialEpoch, false, true},
			handshakeCachePullRule{TypeServerHelloDone, cfg.initialEpoch, false, false},
		)
	}
	if !ok {

		return 0, nil, nil
	}
	state.handshakeRecvSequence = seq

	if h, ok := msgs[TypeCertificate].(*MessageCertificate); ok {
		state.PeerCertificates = h.Certificate
	} else if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate {
		return 0, &Alert{Level: Fatal, Description: NoCertificate}, errInvalidCertificate
	}

	if h, ok := msgs[TypeServerKeyExchange].(*MessageServerKeyExchange); ok {
		alertPtr, err := handleServerKeyExchange(conn, state, cfg, h)
		if err != nil {
			return 0, alertPtr, err
		}
	}

	if creq, ok := msgs[TypeCertificateRequest].(*MessageCertificateRequest); ok {
		state.remoteCertRequestAlgs = creq.SignatureHashAlgorithms
		state.remoteRequestedCertificate = true
	}

	return flight5, nil, nil
}

func handleResumption(
	ctx context.Context,
	c flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {
	if err := state.initCipherSuite(); err != nil {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
	}

	if err := c.handleQueuedPackets(ctx); err != nil {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
	}

	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence+1, state.cipherSuite,
		handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, false, false},
	)
	if !ok {

		return 0, nil, nil
	}

	var finished *MessageFinished
	if finished, ok = msgs[TypeFinished].(*MessageFinished); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}
	plainText := cache.pullAndMerge(
		handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
		handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
	)

	expectedVerifyData, err := VerifyDataServer(state.masterSecret, plainText, state.cipherSuite.HashFunc())
	if err != nil {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &Alert{Level: Fatal, Description: HandshakeFailure}, errVerifyDataMismatch
	}

	clientRandom := state.localRandom.MarshalFixed()
	cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)

	return flight5b, nil, nil
}

func handleServerKeyExchange(
	_ flightConn,
	state *State,
	cfg *handshakeConfig,
	keyExchangeMessage *MessageServerKeyExchange,
) (*Alert, error) {
	var err error
	if state.cipherSuite == nil {
		return &Alert{Level: Fatal, Description: InsufficientSecurity}, errInvalidCipherSuite
	}
	if cfg.localPSKCallback != nil {
		var psk []byte
		if psk, err = cfg.localPSKCallback(keyExchangeMessage.IdentityHint); err != nil {
			return &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
		state.IdentityHint = keyExchangeMessage.IdentityHint
		switch state.cipherSuite.KeyExchangeAlgorithm() {
		case KeyExchangeAlgorithmPsk:
			state.preMasterSecret = PSKPreMasterSecret(psk)
		case (KeyExchangeAlgorithmEcdhe | KeyExchangeAlgorithmPsk):
			if state.localKeypair, err = GenerateKeypair(keyExchangeMessage.NamedCurve); err != nil {
				return &Alert{Level: Fatal, Description: AlertInternalError}, err
			}
			state.preMasterSecret, err = EcdhePSKPreMasterSecret(
				psk,
				keyExchangeMessage.PublicKey,
				state.localKeypair.PrivateKey,
				state.localKeypair.Curve,
			)
			if err != nil {
				return &Alert{Level: Fatal, Description: AlertInternalError}, err
			}
		default:
			return &Alert{Level: Fatal, Description: InsufficientSecurity}, errInvalidCipherSuite
		}
	} else {
		if state.localKeypair, err = GenerateKeypair(keyExchangeMessage.NamedCurve); err != nil {
			return &Alert{Level: Fatal, Description: AlertInternalError}, err
		}

		if state.preMasterSecret, err = PreMasterSecret(
			keyExchangeMessage.PublicKey,
			state.localKeypair.PrivateKey,
			state.localKeypair.Curve,
		); err != nil {
			return &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	return nil, nil
}

func flight3Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *Alert, error) {
	extensions := []Extension{
		&SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.localSignatureSchemes,
		},
		&RenegotiationInfo{
			RenegotiatedConnection: 0,
		},
	}

	if len(cfg.localCertSignatureSchemes) > 0 {
		extensions = append(extensions, &SignatureAlgorithmsCert{
			SignatureHashAlgorithms: cfg.localCertSignatureSchemes,
		})
	}

	if state.namedCurve != 0 {
		extensions = append(extensions, []Extension{
			&SupportedEllipticCurves{
				EllipticCurves: cfg.ellipticCurves,
			},
			&SupportedPointFormats{
				PointFormats: []CurvePointFormat{CurvePointFormatUncompressed},
			},
		}...)
	}

	if len(cfg.localSRTPProtectionProfiles) > 0 {
		extensions = append(extensions, &UseSRTP{
			ProtectionProfiles: cfg.localSRTPProtectionProfiles,
		})
	}

	if cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret {
		extensions = append(extensions, &UseExtendedMasterSecret{
			Supported: true,
		})
	}

	if len(cfg.serverName) > 0 {
		extensions = append(extensions, &ServerName{ServerName: cfg.serverName})
	}

	if len(cfg.supportedProtocols) > 0 {
		extensions = append(extensions, &ALPN{ProtocolNameList: cfg.supportedProtocols})
	}

	if state.getLocalConnectionID() != nil {
		extensions = append(extensions, &ConnectionID{CID: state.getLocalConnectionID()})
	}

	clientHello := &MessageClientHello{
		Version:            Version1_2,
		SessionID:          state.SessionID,
		Cookie:             state.cookie,
		Random:             state.localRandom,
		CipherSuiteIDs:     cipherSuiteIDs(cfg.localCipherSuites),
		CompressionMethods: defaultCompressionMethods(),
		Extensions:         extensions,
	}

	var content Handshake

	if cfg.clientHelloMessageHook != nil {
		content = Handshake{Message: cfg.clientHelloMessageHook(*clientHello)}
	} else {
		content = Handshake{Message: clientHello}
	}

	return []*packet{
		{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &content,
			},
		},
	}, nil, nil
}

func flight4Parse(
	ctx context.Context,
	conn flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {
	seq, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, true, true},
		handshakeCachePullRule{TypeClientKeyExchange, cfg.initialEpoch, true, false},
		handshakeCachePullRule{TypeCertificateVerify, cfg.initialEpoch, true, true},
	)
	if !ok {

		return 0, nil, nil
	}

	var clientKeyExchange *MessageClientKeyExchange
	if clientKeyExchange, ok = msgs[TypeClientKeyExchange].(*MessageClientKeyExchange); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}

	if h, hasCert := msgs[TypeCertificate].(*MessageCertificate); hasCert {
		state.PeerCertificates = h.Certificate

		state.SessionID = nil
	}

	if verify, hasVerify := msgs[TypeCertificateVerify].(*MessageCertificateVerify); hasVerify {
		if state.PeerCertificates == nil {
			return 0, &Alert{Level: Fatal, Description: NoCertificate}, errCertificateVerifyNoCertificate
		}

		plainText := cache.pullAndMerge(
			handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeClientKeyExchange, cfg.initialEpoch, true, false},
		)

		var validSignatureScheme bool
		for _, ss := range cfg.localSignatureSchemes {
			if ss.Hash == verify.HashAlgorithm && ss.Signature == verify.SignatureAlgorithm {
				validSignatureScheme = true

				break
			}
		}
		if !validSignatureScheme {
			return 0, &Alert{Level: Fatal, Description: InsufficientSecurity}, errNoAvailableSignatureSchemes
		}

		if err := verifyCertificateVerify(
			plainText,
			verify.HashAlgorithm,
			verify.SignatureAlgorithm,
			verify.Signature,
			state.PeerCertificates,
		); err != nil {
			return 0, &Alert{Level: Fatal, Description: BadCertificate}, err
		}
		var chains [][]*x509.Certificate
		var err error
		var verified bool
		if cfg.clientAuth >= VerifyClientCertIfGiven {

			certAlgs := cfg.localCertSignatureSchemes
			if len(certAlgs) == 0 {
				certAlgs = cfg.localSignatureSchemes
			}
			if chains, err = verifyClientCert(state.PeerCertificates, cfg.clientCAs, certAlgs); err != nil {
				return 0, &Alert{Level: Fatal, Description: BadCertificate}, err
			}
			verified = true
		}
		if cfg.verifyPeerCertificate != nil {
			if err := cfg.verifyPeerCertificate(state.PeerCertificates, chains); err != nil {
				return 0, &Alert{Level: Fatal, Description: BadCertificate}, err
			}
		}
		state.peerCertificatesVerified = verified
	} else if state.PeerCertificates != nil {

		return 0, nil, nil
	}

	if !state.cipherSuite.IsInitialized() {
		serverRandom := state.localRandom.MarshalFixed()
		clientRandom := state.remoteRandom.MarshalFixed()

		var err error
		var preMasterSecret []byte
		if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypePreSharedKey {
			var psk []byte
			if psk, err = cfg.localPSKCallback(clientKeyExchange.IdentityHint); err != nil {
				return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
			}
			state.IdentityHint = clientKeyExchange.IdentityHint
			switch state.cipherSuite.KeyExchangeAlgorithm() {
			case CipherSuiteKeyExchangeAlgorithmPsk:
				preMasterSecret = PSKPreMasterSecret(psk)
			case (CipherSuiteKeyExchangeAlgorithmPsk | CipherSuiteKeyExchangeAlgorithmEcdhe):
				if preMasterSecret, err = EcdhePSKPreMasterSecret(
					psk,
					clientKeyExchange.PublicKey,
					state.localKeypair.PrivateKey,
					state.localKeypair.Curve,
				); err != nil {
					return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
				}
			default:
				return 0, &Alert{Level: Fatal, Description: AlertInternalError}, errInvalidCipherSuite
			}
		} else {
			preMasterSecret, err = PreMasterSecret(
				clientKeyExchange.PublicKey,
				state.localKeypair.PrivateKey,
				state.localKeypair.Curve,
			)
			if err != nil {
				return 0, &Alert{Level: Fatal, Description: IllegalParameter}, err
			}
		}

		if state.extendedMasterSecret {
			var sessionHash []byte
			sessionHash, err = cache.sessionHash(state.cipherSuite.HashFunc(), cfg.initialEpoch)
			if err != nil {
				return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
			}

			state.masterSecret, err = ExtendedMasterSecret(preMasterSecret, sessionHash, state.cipherSuite.HashFunc())
			if err != nil {
				return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
			}
		} else {
			state.masterSecret, err = MasterSecret(
				preMasterSecret,
				clientRandom[:],
				serverRandom[:],
				state.cipherSuite.HashFunc(),
			)
			if err != nil {
				return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
			}
		}

		if err := state.cipherSuite.Init(state.masterSecret, clientRandom[:], serverRandom[:], false); err != nil {
			return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
		cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)
	}

	if len(state.SessionID) > 0 {
		s := Session{
			ID:     state.SessionID,
			Secret: state.masterSecret,
		}
		cfg.log.Tracef("[handshake] save new session: %x", s.ID)
		if err := cfg.sessionStore.Set(state.SessionID, s); err != nil {
			return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	if err := conn.handleQueuedPackets(ctx); err != nil {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
	}

	seq, msgs, ok = cache.fullPullMap(seq, state.cipherSuite,
		handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {

		return 0, nil, nil
	}
	state.handshakeRecvSequence = seq

	if _, ok = msgs[TypeFinished].(*MessageFinished); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}

	if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeAnonymous {
		if cfg.verifyConnection != nil {
			stateClone, err := state.clone()
			if err != nil {
				return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
			}
			if err := cfg.verifyConnection(stateClone); err != nil {
				return 0, &Alert{Level: Fatal, Description: BadCertificate}, err
			}
		}

		return flight6, nil, nil
	}

	switch cfg.clientAuth {
	case RequireAnyClientCert:
		if state.PeerCertificates == nil {
			return 0, &Alert{Level: Fatal, Description: NoCertificate}, errClientCertificateRequired
		}
	case VerifyClientCertIfGiven:
		if state.PeerCertificates != nil && !state.peerCertificatesVerified {
			return 0, &Alert{Level: Fatal, Description: BadCertificate}, errClientCertificateNotVerified
		}
	case RequireAndVerifyClientCert:
		if state.PeerCertificates == nil {
			return 0, &Alert{Level: Fatal, Description: NoCertificate}, errClientCertificateRequired
		}
		if !state.peerCertificatesVerified {
			return 0, &Alert{Level: Fatal, Description: BadCertificate}, errClientCertificateNotVerified
		}
	case NoClientCert, RequestClientCert:

	}
	if cfg.verifyConnection != nil {
		stateClone, err := state.clone()
		if err != nil {
			return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
		if err := cfg.verifyConnection(stateClone); err != nil {
			return 0, &Alert{Level: Fatal, Description: BadCertificate}, err
		}
	}

	return flight6, nil, nil
}

func flight4Generate(
	_ flightConn,
	state *State,
	_ *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *Alert, error) {
	extensions := []Extension{}

	if (cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret) && state.extendedMasterSecret {
		extensions = append(extensions, &UseExtendedMasterSecret{
			Supported: true,
		})
	}
	if state.getSRTPProtectionProfile() != 0 {
		extensions = append(extensions, &UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{state.getSRTPProtectionProfile()},
			MasterKeyIdentifier: cfg.localSRTPMasterKeyIdentifier,
		})
	}
	if state.remoteSupportsRenegotiation {
		extensions = append(extensions, &RenegotiationInfo{
			RenegotiatedConnection: 0,
		})
	}
	if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate {
		extensions = append(extensions, &SupportedPointFormats{
			PointFormats: []CurvePointFormat{CurvePointFormatUncompressed},
		})
	}

	selectedProto, err := ALPNProtocolSelection(cfg.supportedProtocols, state.peerSupportedProtocols)
	if err != nil {
		return nil, &Alert{Level: Fatal, Description: NoApplicationProtocol}, err
	}
	if selectedProto != "" {
		extensions = append(extensions, &ALPN{
			ProtocolNameList: []string{selectedProto},
		})
		state.NegotiatedProtocol = selectedProto
	}

	if cfg.connectionIDGenerator != nil && state.remoteConnectionID != nil {
		state.setLocalConnectionID(cfg.connectionIDGenerator())
		extensions = append(extensions, &ConnectionID{CID: state.getLocalConnectionID()})
	}

	var pkts []*packet
	cipherSuiteID := uint16(state.cipherSuite.ID())

	if cfg.sessionStore != nil {
		state.SessionID = make([]byte, sessionLength)
		if _, err := rand.Read(state.SessionID); err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	serverHello := &MessageServerHello{
		Version:           Version1_2,
		Random:            state.localRandom,
		SessionID:         state.SessionID,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions:        extensions,
	}

	var content Handshake

	if cfg.serverHelloMessageHook != nil {
		content = Handshake{Message: cfg.serverHelloMessageHook(*serverHello)}
	} else {
		content = Handshake{Message: serverHello}
	}

	pkts = append(pkts, &packet{
		record: &RecordLayer{
			Header: RecordLayerHeader{
				Version: Version1_2,
			},
			Content: &content,
		},
	})

	switch {
	case state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate:
		certificate, err := cfg.getCertificate(&ClientHelloInfo{
			ServerName:   state.serverName,
			CipherSuites: []ID{state.cipherSuite.ID()},
			RandomBytes:  state.remoteRandom.RandomBytes,
		})
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: HandshakeFailure}, err
		}

		pkts = append(pkts, &packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &Handshake{
					Message: &MessageCertificate{
						Certificate: certificate.Certificate,
					},
				},
			},
		})

		serverRandom := state.localRandom.MarshalFixed()
		clientRandom := state.remoteRandom.MarshalFixed()

		signer, ok := certificate.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, errInvalidPrivateKey
		}

		signatureHashAlgo, err := SelectSignatureScheme(cfg.localSignatureSchemes, signer)
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: InsufficientSecurity}, err
		}

		signature, err := generateKeySignature(
			clientRandom[:],
			serverRandom[:],
			state.localKeypair.PublicKey,
			state.namedCurve,
			signer,
			signatureHashAlgo.Hash,
			signatureHashAlgo.Signature,
		)
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
		state.localKeySignature = signature

		pkts = append(pkts, &packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &Handshake{
					Message: &MessageServerKeyExchange{
						EllipticCurveType:  CurveTypeNamedCurve,
						NamedCurve:         state.namedCurve,
						PublicKey:          state.localKeypair.PublicKey,
						HashAlgorithm:      signatureHashAlgo.Hash,
						SignatureAlgorithm: signatureHashAlgo.Signature,
						Signature:          state.localKeySignature,
					},
				},
			},
		})

		if cfg.clientAuth > NoClientCert {

			var certificateAuthorities [][]byte
			if cfg.clientCAs != nil {

				certificateAuthorities = cfg.clientCAs.Subjects()
			}

			certReq := &MessageCertificateRequest{
				CertificateTypes:            []ClientCertificateType{RSASign, ECDSASign},
				SignatureHashAlgorithms:     cfg.localSignatureSchemes,
				CertificateAuthoritiesNames: certificateAuthorities,
			}

			var content Handshake

			if cfg.certificateRequestMessageHook != nil {
				content = Handshake{Message: cfg.certificateRequestMessageHook(*certReq)}
			} else {
				content = Handshake{Message: certReq}
			}

			pkts = append(pkts, &packet{
				record: &RecordLayer{
					Header: RecordLayerHeader{
						Version: Version1_2,
					},
					Content: &content,
				},
			})
		}
	case cfg.localPSKIdentityHint != nil ||
		state.cipherSuite.KeyExchangeAlgorithm().Has(CipherSuiteKeyExchangeAlgorithmEcdhe):

		srvExchange := &MessageServerKeyExchange{
			IdentityHint: cfg.localPSKIdentityHint,
		}
		if state.cipherSuite.KeyExchangeAlgorithm().Has(CipherSuiteKeyExchangeAlgorithmEcdhe) {
			srvExchange.EllipticCurveType = CurveTypeNamedCurve
			srvExchange.NamedCurve = state.namedCurve
			srvExchange.PublicKey = state.localKeypair.PublicKey
		}
		pkts = append(pkts, &packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &Handshake{
					Message: srvExchange,
				},
			},
		})
	}

	pkts = append(pkts, &packet{
		record: &RecordLayer{
			Header: RecordLayerHeader{
				Version: Version1_2,
			},
			Content: &Handshake{
				Message: &MessageServerHelloDone{},
			},
		},
	})

	return pkts, nil, nil
}

func flight4bParse(
	_ context.Context,
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {

		return 0, nil, nil
	}

	var finished *MessageFinished
	if finished, ok = msgs[TypeFinished].(*MessageFinished); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}

	plainText := cache.pullAndMerge(
		handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
		handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
		handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, false, false},
	)

	expectedVerifyData, err := VerifyDataClient(state.masterSecret, plainText, state.cipherSuite.HashFunc())
	if err != nil {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &Alert{Level: Fatal, Description: HandshakeFailure}, errVerifyDataMismatch
	}

	return flight4b, nil, nil
}

func flight4bGenerate(
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *Alert, error) {
	var pkts []*packet

	extensions := []Extension{&RenegotiationInfo{
		RenegotiatedConnection: 0,
	}}
	if (cfg.extendedMasterSecret == RequestExtendedMasterSecret ||
		cfg.extendedMasterSecret == RequireExtendedMasterSecret) && state.extendedMasterSecret {
		extensions = append(extensions, &UseExtendedMasterSecret{
			Supported: true,
		})
	}
	if state.getSRTPProtectionProfile() != 0 {
		extensions = append(extensions, &UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{state.getSRTPProtectionProfile()},
			MasterKeyIdentifier: cfg.localSRTPMasterKeyIdentifier,
		})
	}

	selectedProto, err := ALPNProtocolSelection(cfg.supportedProtocols, state.peerSupportedProtocols)
	if err != nil {
		return nil, &Alert{Level: Fatal, Description: NoApplicationProtocol}, err
	}
	if selectedProto != "" {
		extensions = append(extensions, &ALPN{
			ProtocolNameList: []string{selectedProto},
		})
		state.NegotiatedProtocol = selectedProto
	}

	cipherSuiteID := uint16(state.cipherSuite.ID())
	var serverHello Handshake

	serverHelloMessage := &MessageServerHello{
		Version:           Version1_2,
		Random:            state.localRandom,
		SessionID:         state.SessionID,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
		Extensions:        extensions,
	}

	if cfg.serverHelloMessageHook != nil {
		serverHello = Handshake{Message: cfg.serverHelloMessageHook(*serverHelloMessage)}
	} else {
		serverHello = Handshake{Message: serverHelloMessage}
	}

	serverHello.Header.MessageSequence = uint16(state.handshakeSendSequence)

	if len(state.localVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
		)
		raw, err := serverHello.Marshal()
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
		plainText = append(plainText, raw...)

		state.localVerifyData, err = VerifyDataServer(state.masterSecret, plainText, state.cipherSuite.HashFunc())
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &serverHello,
			},
		},
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &ChangeCipherSpec{},
			},
		},
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
					Epoch:   1,
				},
				Content: &Handshake{
					Message: &MessageFinished{
						VerifyData: state.localVerifyData,
					},
				},
			},
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		},
	)

	return pkts, nil, nil
}

func flight5Parse(
	_ context.Context,
	conn flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence, state.cipherSuite,
		handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, false, false},
	)
	if !ok {

		return 0, nil, nil
	}

	var finished *MessageFinished
	if finished, ok = msgs[TypeFinished].(*MessageFinished); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}
	plainText := cache.pullAndMerge(
		handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
		handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
		handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, false, false},
		handshakeCachePullRule{TypeServerKeyExchange, cfg.initialEpoch, false, false},
		handshakeCachePullRule{TypeCertificateRequest, cfg.initialEpoch, false, false},
		handshakeCachePullRule{TypeServerHelloDone, cfg.initialEpoch, false, false},
		handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, true, false},
		handshakeCachePullRule{TypeClientKeyExchange, cfg.initialEpoch, true, false},
		handshakeCachePullRule{TypeCertificateVerify, cfg.initialEpoch, true, false},
		handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, true, false},
	)

	expectedVerifyData, err := VerifyDataServer(state.masterSecret, plainText, state.cipherSuite.HashFunc())
	if err != nil {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
	}
	if !bytes.Equal(expectedVerifyData, finished.VerifyData) {
		return 0, &Alert{Level: Fatal, Description: HandshakeFailure}, errVerifyDataMismatch
	}

	if len(state.SessionID) > 0 {
		s := Session{
			ID:     state.SessionID,
			Secret: state.masterSecret,
		}
		cfg.log.Tracef("[handshake] save new session: %x", s.ID)
		if err := cfg.sessionStore.Set(conn.sessionKey(), s); err != nil {
			return 0, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	return flight5, nil, nil
}

func flight5Generate(
	conn flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *Alert, error) {
	var signer crypto.Signer
	var pkts []*packet
	if state.remoteRequestedCertificate {
		_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence-2, state.cipherSuite,
			handshakeCachePullRule{TypeCertificateRequest, cfg.initialEpoch, false, false})
		if !ok {
			return nil, &Alert{Level: Fatal, Description: HandshakeFailure}, errClientCertificateRequired
		}
		reqInfo := CertificateRequestInfo{}
		if r, ok2 := msgs[TypeCertificateRequest].(*MessageCertificateRequest); ok2 {
			reqInfo.AcceptableCAs = r.CertificateAuthoritiesNames
		} else {
			return nil, &Alert{Level: Fatal, Description: HandshakeFailure}, errClientCertificateRequired
		}
		certificate, err := cfg.getClientCertificate(&reqInfo)
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: HandshakeFailure}, err
		}
		if certificate == nil {
			return nil, &Alert{Level: Fatal, Description: HandshakeFailure}, errNotAcceptableCertificateChain
		}
		if certificate.Certificate != nil {
			signer, ok = certificate.PrivateKey.(crypto.Signer)
			if !ok {
				return nil, &Alert{Level: Fatal, Description: HandshakeFailure}, errInvalidPrivateKey
			}
		}
		pkts = append(pkts,
			&packet{
				record: &RecordLayer{
					Header: RecordLayerHeader{
						Version: Version1_2,
					},
					Content: &Handshake{
						Message: &MessageCertificate{
							Certificate: certificate.Certificate,
						},
					},
				},
			})
	}

	clientKeyExchange := &MessageClientKeyExchange{}
	if cfg.localPSKCallback == nil {
		clientKeyExchange.PublicKey = state.localKeypair.PublicKey
	} else {
		clientKeyExchange.IdentityHint = cfg.localPSKIdentityHint
	}
	if state != nil && state.localKeypair != nil && len(state.localKeypair.PublicKey) > 0 {
		clientKeyExchange.PublicKey = state.localKeypair.PublicKey
	}

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &Handshake{
					Message: clientKeyExchange,
				},
			},
		})

	serverKeyExchangeData := cache.pullAndMerge(
		handshakeCachePullRule{TypeServerKeyExchange, cfg.initialEpoch, false, false},
	)

	serverKeyExchange := &MessageServerKeyExchange{}

	if len(serverKeyExchangeData) == 0 {
		alertPtr, err := handleServerKeyExchange(conn, state, cfg, &MessageServerKeyExchange{})
		if err != nil {
			return nil, alertPtr, err
		}
	} else {
		rawHandshake := &Handshake{
			KeyExchangeAlgorithm: state.cipherSuite.KeyExchangeAlgorithm(),
		}
		err := rawHandshake.Unmarshal(serverKeyExchangeData)
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: UnexpectedMessage}, err
		}

		switch h := rawHandshake.Message.(type) {
		case *MessageServerKeyExchange:
			serverKeyExchange = h
		default:
			return nil, &Alert{Level: Fatal, Description: UnexpectedMessage}, errInvalidContentType
		}
	}

	merged := []byte{}
	seqPred := uint16(state.handshakeSendSequence)
	for _, p := range pkts {
		h, ok := p.record.Content.(*Handshake)
		if !ok {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, errInvalidContentType
		}
		h.Header.MessageSequence = seqPred
		seqPred++
		raw, err := h.Marshal()
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
		merged = append(merged, raw...)
	}

	if alertPtr, err := initializeCipherSuite(state, cache, cfg, serverKeyExchange, merged); err != nil {
		return nil, alertPtr, err
	}

	if state.remoteRequestedCertificate && signer != nil {
		plainText := append(cache.pullAndMerge(
			handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeClientKeyExchange, cfg.initialEpoch, true, false},
		), merged...)

		signatureHashAlgo, err := SelectSignatureScheme(state.remoteCertRequestAlgs, signer)
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: InsufficientSecurity}, err
		}

		certVerify, err := generateCertificateVerify(plainText, signer, signatureHashAlgo.Hash, signatureHashAlgo.Signature)
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
		state.localCertificatesVerify = certVerify

		pkt := &packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &Handshake{
					Message: &MessageCertificateVerify{
						HashAlgorithm:      signatureHashAlgo.Hash,
						SignatureAlgorithm: signatureHashAlgo.Signature,
						Signature:          state.localCertificatesVerify,
					},
				},
			},
		}
		pkts = append(pkts, pkt)

		h, ok := pkt.record.Content.(*Handshake)
		if !ok {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, errInvalidContentType
		}
		h.Header.MessageSequence = seqPred

		raw, err := h.Marshal()
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
		merged = append(merged, raw...)
	}

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &ChangeCipherSpec{},
			},
		})

	if len(state.localVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeClientKeyExchange, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeCertificateVerify, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, true, false},
		)

		var err error
		state.localVerifyData, err = VerifyDataClient(
			state.masterSecret,
			append(plainText, merged...),
			state.cipherSuite.HashFunc(),
		)
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
					Epoch:   1,
				},
				Content: &Handshake{
					Message: &MessageFinished{
						VerifyData: state.localVerifyData,
					},
				},
			},
			shouldWrapCID:            len(state.remoteConnectionID) > 0,
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		})

	return pkts, nil, nil
}

func initializeCipherSuite(
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
	handshakeKeyExchange *MessageServerKeyExchange,
	sendingPlainText []byte,
) (*Alert, error) {
	if state.cipherSuite.IsInitialized() {
		return nil, nil
	}

	clientRandom := state.localRandom.MarshalFixed()
	serverRandom := state.remoteRandom.MarshalFixed()

	var err error

	if state.extendedMasterSecret {
		var sessionHash []byte
		sessionHash, err = cache.sessionHash(state.cipherSuite.HashFunc(), cfg.initialEpoch, sendingPlainText)
		if err != nil {
			return &Alert{Level: Fatal, Description: AlertInternalError}, err
		}

		state.masterSecret, err = ExtendedMasterSecret(state.preMasterSecret, sessionHash, state.cipherSuite.HashFunc())
		if err != nil {
			return &Alert{Level: Fatal, Description: IllegalParameter}, err
		}
	} else {
		state.masterSecret, err = MasterSecret(
			state.preMasterSecret,
			clientRandom[:],
			serverRandom[:],
			state.cipherSuite.HashFunc(),
		)
		if err != nil {
			return &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	if state.cipherSuite.AuthenticationType() == CipherSuiteAuthenticationTypeCertificate {

		var validSignatureScheme bool
		for _, ss := range cfg.localSignatureSchemes {
			if ss.Hash == handshakeKeyExchange.HashAlgorithm && ss.Signature == handshakeKeyExchange.SignatureAlgorithm {
				validSignatureScheme = true

				break
			}
		}
		if !validSignatureScheme {
			return &Alert{Level: Fatal, Description: InsufficientSecurity}, errNoAvailableSignatureSchemes
		}

		expectedMsg := valueKeyMessage(
			clientRandom[:],
			serverRandom[:],
			handshakeKeyExchange.PublicKey,
			handshakeKeyExchange.NamedCurve,
		)
		if err = verifyKeySignature(
			expectedMsg,
			handshakeKeyExchange.Signature,
			handshakeKeyExchange.HashAlgorithm,
			handshakeKeyExchange.SignatureAlgorithm,
			state.PeerCertificates,
		); err != nil {
			return &Alert{Level: Fatal, Description: BadCertificate}, err
		}
		var chains [][]*x509.Certificate
		if !cfg.insecureSkipVerify {
			certAlgs := cfg.localCertSignatureSchemes
			if len(certAlgs) == 0 {
				certAlgs = cfg.localSignatureSchemes
			}
			if chains, err = verifyServerCert(state.PeerCertificates, cfg.rootCAs, cfg.serverName, certAlgs); err != nil {
				return &Alert{Level: Fatal, Description: BadCertificate}, err
			}
		}
		if cfg.verifyPeerCertificate != nil {
			if err = cfg.verifyPeerCertificate(state.PeerCertificates, chains); err != nil {
				return &Alert{Level: Fatal, Description: BadCertificate}, err
			}
		}
	}
	if cfg.verifyConnection != nil {
		stateClone, errC := state.clone()
		if errC != nil {
			return &Alert{Level: Fatal, Description: AlertInternalError}, errC
		}
		if errC = cfg.verifyConnection(stateClone); errC != nil {
			return &Alert{Level: Fatal, Description: BadCertificate}, errC
		}
	}

	if err = state.cipherSuite.Init(state.masterSecret, clientRandom[:], serverRandom[:], true); err != nil {
		return &Alert{Level: Fatal, Description: AlertInternalError}, err
	}

	cfg.writeKeyLog(keyLogLabelTLS12, clientRandom[:], state.masterSecret)

	return nil, nil
}

func flight5bParse(
	_ context.Context,
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence-1, state.cipherSuite,
		handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, false, false},
	)
	if !ok {

		return 0, nil, nil
	}

	if _, ok = msgs[TypeFinished].(*MessageFinished); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}

	return flight5b, nil, nil
}

func flight5bGenerate(
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *Alert, error) {
	var pkts []*packet

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &ChangeCipherSpec{},
			},
		})

	if len(state.localVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, false, false},
		)

		var err error
		state.localVerifyData, err = VerifyDataClient(state.masterSecret, plainText, state.cipherSuite.HashFunc())
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
					Epoch:   1,
				},
				Content: &Handshake{
					Message: &MessageFinished{
						VerifyData: state.localVerifyData,
					},
				},
			},
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		})

	return pkts, nil, nil
}

func flight6Parse(
	_ context.Context,
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) (flightVal, *Alert, error) {
	_, msgs, ok := cache.fullPullMap(state.handshakeRecvSequence-1, state.cipherSuite,
		handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, true, false},
	)
	if !ok {

		return 0, nil, nil
	}

	if _, ok = msgs[TypeFinished].(*MessageFinished); !ok {
		return 0, &Alert{Level: Fatal, Description: AlertInternalError}, nil
	}

	return flight6, nil, nil
}

func flight6Generate(
	_ flightConn,
	state *State,
	cache *handshakeCache,
	cfg *handshakeConfig,
) ([]*packet, *Alert, error) {
	var pkts []*packet

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
				},
				Content: &ChangeCipherSpec{},
			},
		})

	if len(state.localVerifyData) == 0 {
		plainText := cache.pullAndMerge(
			handshakeCachePullRule{TypeClientHello, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeServerHello, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeServerKeyExchange, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificateRequest, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeServerHelloDone, cfg.initialEpoch, false, false},
			handshakeCachePullRule{TypeCertificate, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeClientKeyExchange, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeCertificateVerify, cfg.initialEpoch, true, false},
			handshakeCachePullRule{TypeFinished, cfg.initialEpoch + 1, true, false},
		)

		var err error
		state.localVerifyData, err = VerifyDataServer(state.masterSecret, plainText, state.cipherSuite.HashFunc())
		if err != nil {
			return nil, &Alert{Level: Fatal, Description: AlertInternalError}, err
		}
	}

	pkts = append(pkts,
		&packet{
			record: &RecordLayer{
				Header: RecordLayerHeader{
					Version: Version1_2,
					Epoch:   1,
				},
				Content: &Handshake{
					Message: &MessageFinished{
						VerifyData: state.localVerifyData,
					},
				},
			},
			shouldWrapCID:            len(state.remoteConnectionID) > 0,
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		},
	)

	return pkts, nil, nil
}

// ===================== merged from internal/ciphersuite/types/types.go =====================
type AuthenticationType int

const (
	AuthenticationTypeCertificate AuthenticationType = iota + 1
	AuthenticationTypePreSharedKey
	AuthenticationTypeAnonymous
)

type KeyExchangeAlgorithm int

const (
	KeyExchangeAlgorithmNone KeyExchangeAlgorithm = 0
	KeyExchangeAlgorithmPsk  KeyExchangeAlgorithm = iota << 1
	KeyExchangeAlgorithmEcdhe
)

func (a KeyExchangeAlgorithm) Has(v KeyExchangeAlgorithm) bool {
	return (a & v) == v
}

// ===================== merged from internal/closer/closer.go =====================
type Closer struct {
	ctx       context.Context
	closeFunc func()
}

func NewCloser() *Closer {
	ctx, closeFunc := context.WithCancel(context.Background())

	return &Closer{
		ctx:       ctx,
		closeFunc: closeFunc,
	}
}

func (c *Closer) Done() <-chan struct{} {
	return c.ctx.Done()
}

func (c *Closer) Close() {
	c.closeFunc()
}

// ===================== merged from pkg/crypto/ccm/ccm.go =====================
type ccm struct {
	b cipher.Block
	M uint8
	L uint8
}

const ccmBlockSize = 16

type CCM interface {
	cipher.AEAD
	MaxLength() int
}

var (
	errInvalidBlockSize = errors.New("ccm: NewCCM requires 128-bit block cipher")
	errInvalidTagSize   = errors.New("ccm: tagsize must be 4, 6, 8, 10, 12, 14, or 16")
	errInvalidNonceSize = errors.New("ccm: invalid nonce size")
)

func NewCCM(b cipher.Block, tagsize, noncesize int) (CCM, error) {
	if b.BlockSize() != ccmBlockSize {
		return nil, errInvalidBlockSize
	}
	if tagsize < 4 || tagsize > 16 || tagsize&1 != 0 {
		return nil, errInvalidTagSize
	}
	lensize := 15 - noncesize
	if lensize < 2 || lensize > 8 {
		return nil, errInvalidNonceSize
	}
	c := &ccm{b: b, M: uint8(tagsize), L: uint8(lensize)}

	return c, nil
}

func (c *ccm) NonceSize() int { return 15 - int(c.L) }
func (c *ccm) Overhead() int  { return int(c.M) }
func (c *ccm) MaxLength() int { return maxlen(c.L, c.Overhead()) }

func maxlen(l uint8, tagsize int) int {
	mLen := (uint64(1) << (8 * l)) - 1
	if m64 := uint64(math.MaxInt64) - uint64(tagsize); l > 8 || mLen > m64 {
		mLen = m64
	}
	if mLen != uint64(int(mLen)) {
		return math.MaxInt32 - tagsize
	}

	return int(mLen)
}

func (c *ccm) cbcRound(mac, data []byte) {
	for i := 0; i < ccmBlockSize; i++ {
		mac[i] ^= data[i]
	}
	c.b.Encrypt(mac, mac)
}

func (c *ccm) cbcData(mac, data []byte) {
	for len(data) >= ccmBlockSize {
		c.cbcRound(mac, data[:ccmBlockSize])
		data = data[ccmBlockSize:]
	}
	if len(data) > 0 {
		var block [ccmBlockSize]byte
		copy(block[:], data)
		c.cbcRound(mac, block[:])
	}
}

var errPlaintextTooLong = errors.New("ccm: plaintext too large")

func (c *ccm) tag(nonce, plaintext, adata []byte) ([]byte, error) {
	var mac [ccmBlockSize]byte

	if len(adata) > 0 {
		mac[0] |= 1 << 6
	}
	mac[0] |= (c.M - 2) << 2
	mac[0] |= c.L - 1
	if len(nonce) != c.NonceSize() {
		return nil, errInvalidNonceSize
	}
	if len(plaintext) > c.MaxLength() {
		return nil, errPlaintextTooLong
	}
	binary.BigEndian.PutUint64(mac[ccmBlockSize-8:], uint64(len(plaintext)))
	copy(mac[1:ccmBlockSize-c.L], nonce)
	c.b.Encrypt(mac[:], mac[:])

	var block [ccmBlockSize]byte
	if adataLength := uint64(len(adata)); adataLength > 0 {

		i := 2
		if adataLength <= 0xfeff {
			binary.BigEndian.PutUint16(block[:i], uint16(adataLength))
		} else {
			binary.BigEndian.PutUint16(block[0:2], 0xfeff)
			if adataLength < uint64(1<<32) {
				i = 2 + 4
				binary.BigEndian.PutUint32(block[2:i], uint32(adataLength))
			} else {
				i = 2 + 8
				binary.BigEndian.PutUint64(block[2:i], adataLength)
			}
		}
		i = copy(block[i:], adata)
		c.cbcRound(mac[:], block[:])
		c.cbcData(mac[:], adata[i:])
	}

	if len(plaintext) > 0 {
		c.cbcData(mac[:], plaintext)
	}

	return mac[:c.M], nil
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]

	return
}

func (c *ccm) Seal(dst, nonce, plaintext, adata []byte) []byte {
	tag, err := c.tag(nonce, plaintext, adata)
	if err != nil {

		panic(err)
	}

	var iv, s0 [ccmBlockSize]byte
	iv[0] = c.L - 1
	copy(iv[1:ccmBlockSize-c.L], nonce)
	c.b.Encrypt(s0[:], iv[:])
	for i := 0; i < int(c.M); i++ {
		tag[i] ^= s0[i]
	}
	iv[len(iv)-1] |= 1
	stream := cipher.NewCTR(c.b, iv[:])
	ret, out := sliceForAppend(dst, len(plaintext)+int(c.M))
	stream.XORKeyStream(out, plaintext)
	copy(out[len(plaintext):], tag)

	return ret
}

var (
	errOpen               = errors.New("ccm: message authentication failed")
	errCiphertextTooShort = errors.New("ccm: ciphertext too short")
	errCiphertextTooLong  = errors.New("ccm: ciphertext too long")
)

func (c *ccm) Open(dst, nonce, ciphertext, adata []byte) ([]byte, error) {
	if len(ciphertext) < int(c.M) {
		return nil, errCiphertextTooShort
	}
	if len(ciphertext) > c.MaxLength()+c.Overhead() {
		return nil, errCiphertextTooLong
	}

	tag := make([]byte, int(c.M))
	copy(tag, ciphertext[len(ciphertext)-int(c.M):])
	ciphertextWithoutTag := ciphertext[:len(ciphertext)-int(c.M)]

	var iv, s0 [ccmBlockSize]byte
	iv[0] = c.L - 1
	copy(iv[1:ccmBlockSize-c.L], nonce)
	c.b.Encrypt(s0[:], iv[:])
	for i := 0; i < int(c.M); i++ {
		tag[i] ^= s0[i]
	}
	iv[len(iv)-1] |= 1
	stream := cipher.NewCTR(c.b, iv[:])

	plaintext := make([]byte, len(ciphertextWithoutTag))
	stream.XORKeyStream(plaintext, ciphertextWithoutTag)
	expectedTag, err := c.tag(nonce, plaintext, adata)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		return nil, errOpen
	}

	return append(dst, plaintext...), nil
}

// ===================== merged from pkg/crypto/clientcertificate/client_certificate.go =====================
type ClientCertificateType byte

const (
	RSASign   ClientCertificateType = 1
	ECDSASign ClientCertificateType = 64
)

func ClientCertificateTypes() map[ClientCertificateType]bool {
	return map[ClientCertificateType]bool{
		RSASign:   true,
		ECDSASign: true,
	}
}

// ===================== merged from pkg/crypto/elliptic/elliptic.go =====================
var errInvalidNamedCurve = errors.New("invalid named curve")

type CurvePointFormat byte

const (
	CurvePointFormatUncompressed CurvePointFormat = 0
)

type Keypair struct {
	Curve      Curve
	PublicKey  []byte
	PrivateKey []byte
}

type CurveType byte

const (
	CurveTypeNamedCurve CurveType = 0x03
)

func CurveTypes() map[CurveType]struct{} {
	return map[CurveType]struct{}{
		CurveTypeNamedCurve: {},
	}
}

type Curve uint16

const (
	P256   Curve = 0x0017
	P384   Curve = 0x0018
	X25519 Curve = 0x001d
)

func (c Curve) String() string {
	switch c {
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	case X25519:
		return "X25519"
	}

	return fmt.Sprintf("%#x", uint16(c))
}

func Curves() map[Curve]bool {
	return map[Curve]bool{
		X25519: true,
		P256:   true,
		P384:   true,
	}
}

func GenerateKeypair(curve Curve) (*Keypair, error) {
	ec, err := curve.toECDH()
	if err != nil {
		return nil, err
	}

	sk, err := ec.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pk := sk.PublicKey()

	return &Keypair{
		Curve:      curve,
		PublicKey:  pk.Bytes(),
		PrivateKey: sk.Bytes(),
	}, nil
}

func (c Curve) toECDH() (ecdh.Curve, error) {
	switch c {
	case X25519:
		return ecdh.X25519(), nil
	case P256:
		return ecdh.P256(), nil
	case P384:
		return ecdh.P384(), nil
	default:
		return nil, errInvalidNamedCurve
	}
}

// ===================== merged from pkg/crypto/fingerprint/fingerprint.go =====================
var (
	errFpHashUnavailable          = errors.New("fingerprint: hash algorithm is not linked into the binary")
	errFpInvalidFingerprintLength = errors.New("fingerprint: invalid fingerprint length")
	errFpInvalidHashAlgorithm     = errors.New("fingerprint: invalid hash algorithm")
)

func Fingerprint(cert *x509.Certificate, algo crypto.Hash) (string, error) {
	if !algo.Available() {
		return "", errFpHashUnavailable
	}
	h := algo.New()
	for i := 0; i < len(cert.Raw); {
		n, _ := h.Write(cert.Raw[i:])
		i += n
	}
	digest := fmt.Appendf(nil, "%x", h.Sum(nil))

	digestlen := len(digest)
	if digestlen == 0 {
		return "", nil
	}
	if digestlen%2 != 0 {
		return "", errFpInvalidFingerprintLength
	}
	res := make([]byte, digestlen>>1+digestlen-1)

	pos := 0
	for i, c := range digest {
		res[pos] = c
		pos++
		if (i)%2 != 0 && i < digestlen-1 {
			res[pos] = byte(':')
			pos++
		}
	}

	return string(res), nil
}

func fpNameToHash() map[string]crypto.Hash {
	return map[string]crypto.Hash{
		"md5":     crypto.MD5,
		"sha-1":   crypto.SHA1,
		"sha-224": crypto.SHA224,
		"sha-256": crypto.SHA256,
		"sha-384": crypto.SHA384,
		"sha-512": crypto.SHA512,
	}
}

func HashFromString(s string) (crypto.Hash, error) {
	if h, ok := fpNameToHash()[strings.ToLower(s)]; ok {
		return h, nil
	}

	return 0, errFpInvalidHashAlgorithm
}

func StringFromHash(hash crypto.Hash) (string, error) {
	for s, h := range fpNameToHash() {
		if h == hash {
			return s, nil
		}
	}

	return "", errFpInvalidHashAlgorithm
}

// ===================== merged from pkg/crypto/hash/hash.go =====================
type HashAlgorithm uint16

const (
	HashNone    HashAlgorithm = 0
	HashMD5     HashAlgorithm = 1
	HashSHA1    HashAlgorithm = 2
	HashSHA224  HashAlgorithm = 3
	HashSHA256  HashAlgorithm = 4
	HashSHA384  HashAlgorithm = 5
	HashSHA512  HashAlgorithm = 6
	HashEd25519 HashAlgorithm = 8
)

func (a HashAlgorithm) String() string {
	switch a {
	case HashNone:
		return "none"
	case HashMD5:
		return "md5"
	case HashSHA1:
		return "sha-1"
	case HashSHA224:
		return "sha-224"
	case HashSHA256:
		return "sha-256"
	case HashSHA384:
		return "sha-384"
	case HashSHA512:
		return "sha-512"
	case HashEd25519:
		return "null"
	default:
		return "unknown or unsupported hash algorithm"
	}
}

func (a HashAlgorithm) Digest(b []byte) []byte {
	switch a {
	case HashNone:
		return nil
	case HashMD5:
		hash := md5.Sum(b)

		return hash[:]
	case HashSHA1:
		hash := sha1.Sum(b)

		return hash[:]
	case HashSHA224:
		hash := sha256.Sum224(b)

		return hash[:]
	case HashSHA256:
		hash := sha256.Sum256(b)

		return hash[:]
	case HashSHA384:
		hash := sha512.Sum384(b)

		return hash[:]
	case HashSHA512:
		hash := sha512.Sum512(b)

		return hash[:]
	default:
		return nil
	}
}

func (a HashAlgorithm) Insecure() bool {
	switch a {
	case HashNone, HashMD5, HashSHA1:
		return true
	default:
		return false
	}
}

func (a HashAlgorithm) CryptoHash() crypto.Hash {
	switch a {
	case HashNone:
		return crypto.Hash(0)
	case HashMD5:
		return crypto.MD5
	case HashSHA1:
		return crypto.SHA1
	case HashSHA224:
		return crypto.SHA224
	case HashSHA256:
		return crypto.SHA256
	case HashSHA384:
		return crypto.SHA384
	case HashSHA512:
		return crypto.SHA512
	case HashEd25519:
		return crypto.Hash(0)
	default:
		return crypto.Hash(0)
	}
}

func HashAlgorithms() map[HashAlgorithm]struct{} {
	return map[HashAlgorithm]struct{}{
		HashNone:    {},
		HashMD5:     {},
		HashSHA1:    {},
		HashSHA224:  {},
		HashSHA256:  {},
		HashSHA384:  {},
		HashSHA512:  {},
		HashEd25519: {},
	}
}

func ExtractHashFromPSS(pssScheme uint16) HashAlgorithm {

	switch pssScheme {
	case 0x0804, 0x0809:
		return HashSHA256
	case 0x0805, 0x080a:
		return HashSHA384
	case 0x0806, 0x080b:
		return HashSHA512
	default:
		return HashNone
	}
}

// ===================== merged from pkg/crypto/signature/signature.go =====================
type SignatureAlgorithm uint16

const (
	SignatureAnonymous SignatureAlgorithm = 0
	SignatureRSA       SignatureAlgorithm = 1
	SignatureECDSA     SignatureAlgorithm = 3
	SignatureEd25519   SignatureAlgorithm = 7

	SignatureRSA_PSS_RSAE_SHA256 SignatureAlgorithm = 0x0804
	SignatureRSA_PSS_RSAE_SHA384 SignatureAlgorithm = 0x0805
	SignatureRSA_PSS_RSAE_SHA512 SignatureAlgorithm = 0x0806
	SignatureRSA_PSS_PSS_SHA256  SignatureAlgorithm = 0x0809
	SignatureRSA_PSS_PSS_SHA384  SignatureAlgorithm = 0x080a
	SignatureRSA_PSS_PSS_SHA512  SignatureAlgorithm = 0x080b
)

func SignatureAlgorithms() map[SignatureAlgorithm]struct{} {
	return map[SignatureAlgorithm]struct{}{
		SignatureAnonymous:           {},
		SignatureRSA:                 {},
		SignatureECDSA:               {},
		SignatureEd25519:             {},
		SignatureRSA_PSS_RSAE_SHA256: {},
		SignatureRSA_PSS_RSAE_SHA384: {},
		SignatureRSA_PSS_RSAE_SHA512: {},
		SignatureRSA_PSS_PSS_SHA256:  {},
		SignatureRSA_PSS_PSS_SHA384:  {},
		SignatureRSA_PSS_PSS_SHA512:  {},
	}
}

func (a SignatureAlgorithm) IsPSS() bool {
	return a == SignatureRSA_PSS_RSAE_SHA256 ||
		a == SignatureRSA_PSS_RSAE_SHA384 ||
		a == SignatureRSA_PSS_RSAE_SHA512 ||
		a == SignatureRSA_PSS_PSS_SHA256 ||
		a == SignatureRSA_PSS_PSS_SHA384 ||
		a == SignatureRSA_PSS_PSS_SHA512
}

func (a SignatureAlgorithm) IsUnsupported() bool {

	return a == SignatureRSA_PSS_PSS_SHA256 ||
		a == SignatureRSA_PSS_PSS_SHA384 ||
		a == SignatureRSA_PSS_PSS_SHA512
}

// ===================== merged from pkg/crypto/prf/prf.go =====================
const (
	masterSecretLabel         = "master secret"
	extendedMasterSecretLabel = "extended master secret"
	keyExpansionLabel         = "key expansion"
	verifyDataClientLabel     = "client finished"
	verifyDataServerLabel     = "server finished"
)

type HashFunc func() hash.Hash

type EncryptionKeys struct {
	MasterSecret   []byte
	ClientMACKey   []byte
	ServerMACKey   []byte
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
}

var errPrfInvalidNamedCurve = &FatalError{Err: errors.New("invalid named curve")}

func PSKPreMasterSecret(psk []byte) []byte {
	pskLen := uint16(len(psk))

	out := append(make([]byte, 2+pskLen+2), psk...)
	binary.BigEndian.PutUint16(out, pskLen)
	binary.BigEndian.PutUint16(out[2+pskLen:], pskLen)

	return out
}

func EcdhePSKPreMasterSecret(psk, publicKey, privateKey []byte, curve Curve) ([]byte, error) {
	preMasterSecret, err := PreMasterSecret(publicKey, privateKey, curve)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2+len(preMasterSecret)+2+len(psk))

	offset := 0
	binary.BigEndian.PutUint16(out[offset:], uint16(len(preMasterSecret)))
	offset += 2

	copy(out[offset:], preMasterSecret)
	offset += len(preMasterSecret)

	binary.BigEndian.PutUint16(out[offset:], uint16(len(psk)))
	offset += 2

	copy(out[offset:], psk)

	return out, nil
}

func PreMasterSecret(publicKey, privateKey []byte, curve Curve) ([]byte, error) {
	var ec ecdh.Curve

	switch curve {
	case X25519:
		ec = ecdh.X25519()
	case P256:
		ec = ecdh.P256()
	case P384:
		ec = ecdh.P384()
	default:
		return nil, errPrfInvalidNamedCurve
	}

	sk, err := ec.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	pk, err := ec.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return sk.ECDH(pk)
}

func PHash(secret, seed []byte, requestedLength int, hashFunc HashFunc) ([]byte, error) {
	hmacSHA256 := func(key, data []byte) ([]byte, error) {
		mac := hmac.New(hashFunc, key)
		if _, err := mac.Write(data); err != nil {
			return nil, err
		}

		return mac.Sum(nil), nil
	}

	var err error
	lastRound := seed
	out := []byte{}

	iterations := int(math.Ceil(float64(requestedLength) / float64(hashFunc().Size())))
	for i := 0; i < iterations; i++ {
		lastRound, err = hmacSHA256(secret, lastRound)
		if err != nil {
			return nil, err
		}
		withSecret, err := hmacSHA256(secret, append(lastRound, seed...))
		if err != nil {
			return nil, err
		}
		out = append(out, withSecret...)
	}

	return out[:requestedLength], nil
}

func ExtendedMasterSecret(preMasterSecret, sessionHash []byte, h HashFunc) ([]byte, error) {
	seed := append([]byte(extendedMasterSecretLabel), sessionHash...)

	return PHash(preMasterSecret, seed, 48, h)
}

func MasterSecret(preMasterSecret, clientRandom, serverRandom []byte, h HashFunc) ([]byte, error) {
	seed := append(append([]byte(masterSecretLabel), clientRandom...), serverRandom...)

	return PHash(preMasterSecret, seed, 48, h)
}

func GenerateEncryptionKeys(
	masterSecret, clientRandom, serverRandom []byte,
	macLen, keyLen, ivLen int,
	h HashFunc,
) (*EncryptionKeys, error) {
	seed := append(append([]byte(keyExpansionLabel), serverRandom...), clientRandom...)
	keyMaterial, err := PHash(masterSecret, seed, (2*macLen)+(2*keyLen)+(2*ivLen), h)
	if err != nil {
		return nil, err
	}

	clientMACKey := keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]

	serverMACKey := keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]

	clientWriteKey := keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]

	serverWriteKey := keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]

	clientWriteIV := keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]

	serverWriteIV := keyMaterial[:ivLen]

	return &EncryptionKeys{
		MasterSecret:   masterSecret,
		ClientMACKey:   clientMACKey,
		ServerMACKey:   serverMACKey,
		ClientWriteKey: clientWriteKey,
		ServerWriteKey: serverWriteKey,
		ClientWriteIV:  clientWriteIV,
		ServerWriteIV:  serverWriteIV,
	}, nil
}

func prfVerifyData(masterSecret, handshakeBodies []byte, label string, hashFunc HashFunc) ([]byte, error) {
	h := hashFunc()
	if _, err := h.Write(handshakeBodies); err != nil {
		return nil, err
	}

	seed := append([]byte(label), h.Sum(nil)...)

	return PHash(masterSecret, seed, 12, hashFunc)
}

func VerifyDataClient(masterSecret, handshakeBodies []byte, h HashFunc) ([]byte, error) {
	return prfVerifyData(masterSecret, handshakeBodies, verifyDataClientLabel, h)
}

func VerifyDataServer(masterSecret, handshakeBodies []byte, h HashFunc) ([]byte, error) {
	return prfVerifyData(masterSecret, handshakeBodies, verifyDataServerLabel, h)
}

// ===================== merged from pkg/crypto/signaturehash/signaturehash.go =====================
var (
	errShNoAvailableSignatureSchemes = errors.New("connection can not be created, no SignatureScheme satisfy this Config")
	errShInvalidSignatureAlgorithm   = errors.New("invalid signature algorithm")
	errShInvalidHashAlgorithm        = errors.New("invalid hash algorithm")
	errShInvalidPrivateKey           = errors.New("invalid private key type")
)

type SignatureHashAlgorithm struct {
	Hash      HashAlgorithm
	Signature SignatureAlgorithm
}

func SignatureHashAlgorithms() []SignatureHashAlgorithm {
	return []SignatureHashAlgorithm{
		{HashSHA256, SignatureECDSA},
		{HashSHA384, SignatureECDSA},
		{HashSHA512, SignatureECDSA},

		{HashEd25519, SignatureEd25519},

		{HashSHA256, SignatureRSA},
		{HashSHA384, SignatureRSA},
		{HashSHA512, SignatureRSA},
	}
}

func SelectSignatureScheme(sigs []SignatureHashAlgorithm, privateKey crypto.PrivateKey) (SignatureHashAlgorithm, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return SignatureHashAlgorithm{}, errShInvalidPrivateKey
	}
	for _, ss := range sigs {
		if ss.Signature.IsPSS() {
			continue
		}
		if ss.Signature.IsUnsupported() {
			continue
		}
		if ss.isCompatible(signer) {
			return ss, nil
		}
	}
	return SignatureHashAlgorithm{}, errShNoAvailableSignatureSchemes
}

func (a *SignatureHashAlgorithm) isCompatible(signer crypto.Signer) bool {
	switch signer.Public().(type) {
	case ed25519.PublicKey:
		return a.Signature == SignatureEd25519
	case *ecdsa.PublicKey:
		return a.Signature == SignatureECDSA
	case *rsa.PublicKey:
		return a.Signature == SignatureRSA || a.Signature.IsPSS()
	default:
		return false
	}
}

func ParseSignatureSchemes(sigs []tls.SignatureScheme, insecureHashes bool) ([]SignatureHashAlgorithm, error) {
	if len(sigs) == 0 {
		return SignatureHashAlgorithms(), nil
	}
	out := []SignatureHashAlgorithm{}
	for _, ss := range sigs {
		hashAlg, sigAlg, err := parseSignatureSchemeSH(ss)
		if err != nil {
			return nil, err
		}

		if hashAlg.Insecure() && !insecureHashes {
			continue
		}

		out = append(out, SignatureHashAlgorithm{
			Hash:      hashAlg,
			Signature: sigAlg,
		})
	}

	if len(out) == 0 {
		return nil, errShNoAvailableSignatureSchemes
	}

	return out, nil
}

func FromCertificate(cert *x509.Certificate) (SignatureHashAlgorithm, error) {
	var hashAlg HashAlgorithm
	var sigAlg SignatureAlgorithm

	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		hashAlg = HashSHA256
		sigAlg = SignatureRSA
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		hashAlg = HashSHA384
		sigAlg = SignatureRSA
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		hashAlg = HashSHA512
		sigAlg = SignatureRSA
	case x509.ECDSAWithSHA256:
		hashAlg = HashSHA256
		sigAlg = SignatureECDSA
	case x509.ECDSAWithSHA384:
		hashAlg = HashSHA384
		sigAlg = SignatureECDSA
	case x509.ECDSAWithSHA512:
		hashAlg = HashSHA512
		sigAlg = SignatureECDSA
	case x509.PureEd25519:
		hashAlg = HashNone
		sigAlg = SignatureEd25519
	case x509.SHA1WithRSA:
		hashAlg = HashSHA1
		sigAlg = SignatureRSA
	case x509.ECDSAWithSHA1:
		hashAlg = HashSHA1
		sigAlg = SignatureECDSA
	default:
		return SignatureHashAlgorithm{}, errShInvalidSignatureAlgorithm
	}

	return SignatureHashAlgorithm{Hash: hashAlg, Signature: sigAlg}, nil
}

func parseSignatureSchemeSH(sigScheme tls.SignatureScheme) (HashAlgorithm, SignatureAlgorithm, error) {
	var sigAlg SignatureAlgorithm
	var hashAlg HashAlgorithm

	if SignatureAlgorithm(sigScheme).IsPSS() {
		sigAlg = SignatureAlgorithm(sigScheme)
		hashAlg = ExtractHashFromPSS(uint16(sigScheme))
		if hashAlg == HashNone {
			return 0, 0, fmt.Errorf("SignatureScheme %04x: %w", sigScheme, errShInvalidHashAlgorithm)
		}
	} else {
		sigAlg = SignatureAlgorithm(sigScheme & 0xFF)
		hashAlg = HashAlgorithm(sigScheme >> 8)
	}

	if _, ok := SignatureAlgorithms()[sigAlg]; !ok {
		return 0, 0, fmt.Errorf("SignatureScheme %04x: %w", sigScheme, errShInvalidSignatureAlgorithm)
	}

	if _, ok := HashAlgorithms()[hashAlg]; !ok || (ok && hashAlg == HashNone) {
		return 0, 0, fmt.Errorf("SignatureScheme %04x: %w", sigScheme, errShInvalidHashAlgorithm)
	}

	return hashAlg, sigAlg, nil
}

// ===================== merged from pkg/protocol/protocol.go =====================
type ApplicationData struct {
	Data []byte
}

func (a ApplicationData) ContentType() ContentType {
	return ContentTypeApplicationData
}

func (a *ApplicationData) Marshal() ([]byte, error) {
	return append([]byte{}, a.Data...), nil
}

func (a *ApplicationData) Unmarshal(data []byte) error {
	a.Data = append([]byte{}, data...)

	return nil
}

type ChangeCipherSpec struct{}

func (c ChangeCipherSpec) ContentType() ContentType {
	return ContentTypeChangeCipherSpec
}

func (c *ChangeCipherSpec) Marshal() ([]byte, error) {
	return []byte{0x01}, nil
}

func (c *ChangeCipherSpec) Unmarshal(data []byte) error {
	if len(data) == 1 && data[0] == 0x01 {
		return nil
	}

	return errProtoInvalidCipherSpec
}

type CompressionMethodID byte

const (
	compressionMethodNull CompressionMethodID = 0
)

type CompressionMethod struct {
	ID CompressionMethodID
}

func CompressionMethods() map[CompressionMethodID]*CompressionMethod {
	return map[CompressionMethodID]*CompressionMethod{
		compressionMethodNull: {ID: compressionMethodNull},
	}
}

func DecodeCompressionMethods(buf []byte) ([]*CompressionMethod, error) {
	if len(buf) < 1 {
		return nil, errProtoBufferTooSmall
	}
	compressionMethodsCount := int(buf[0])
	c := []*CompressionMethod{}
	for i := 0; i < compressionMethodsCount; i++ {
		if len(buf) <= i+1 {
			return nil, errProtoBufferTooSmall
		}
		id := CompressionMethodID(buf[i+1])
		if compressionMethod, ok := CompressionMethods()[id]; ok {
			c = append(c, compressionMethod)
		}
	}

	return c, nil
}

func EncodeCompressionMethods(c []*CompressionMethod) []byte {
	out := []byte{byte(len(c))}
	for i := len(c); i > 0; i-- {
		out = append(out, byte(c[i-1].ID))
	}

	return out
}

type ContentType uint8

const (
	ContentTypeChangeCipherSpec ContentType = 20
	ContentTypeAlert            ContentType = 21
	ContentTypeHandshake        ContentType = 22
	ContentTypeApplicationData  ContentType = 23
	ContentTypeConnectionID     ContentType = 25
)

type Content interface {
	ContentType() ContentType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}

var (
	errProtoBufferTooSmall    = &TemporaryError{Err: errors.New("buffer is too small")}
	errProtoInvalidCipherSpec = &FatalError{Err: errors.New("cipher spec invalid")}
)

type FatalError struct {
	Err error
}

type InternalError struct {
	Err error
}

type TemporaryError struct {
	Err error
}

type TimeoutError struct {
	Err error
}

type HandshakeError struct {
	Err error
}

func (*FatalError) Timeout() bool { return false }

func (*FatalError) Temporary() bool { return false }

func (e *FatalError) Unwrap() error { return e.Err }

func (e *FatalError) Error() string { return fmt.Sprintf("dtls fatal: %v", e.Err) }

func (*InternalError) Timeout() bool { return false }

func (*InternalError) Temporary() bool { return false }

func (e *InternalError) Unwrap() error { return e.Err }

func (e *InternalError) Error() string { return fmt.Sprintf("dtls internal: %v", e.Err) }

func (*TemporaryError) Timeout() bool { return false }

func (*TemporaryError) Temporary() bool { return true }

func (e *TemporaryError) Unwrap() error { return e.Err }

func (e *TemporaryError) Error() string { return fmt.Sprintf("dtls temporary: %v", e.Err) }

func (*TimeoutError) Timeout() bool { return true }

func (*TimeoutError) Temporary() bool { return true }

func (e *TimeoutError) Unwrap() error { return e.Err }

func (e *TimeoutError) Error() string { return fmt.Sprintf("dtls timeout: %v", e.Err) }

func (e *HandshakeError) Timeout() bool {
	var netErr net.Error
	if errors.As(e.Err, &netErr) {
		return netErr.Timeout()
	}

	return false
}

func (e *HandshakeError) Temporary() bool {
	var netErr net.Error
	if errors.As(e.Err, &netErr) {
		return netErr.Temporary()
	}

	return false
}

func (e *HandshakeError) Unwrap() error { return e.Err }

func (e *HandshakeError) Error() string { return fmt.Sprintf("handshake error: %v", e.Err) }

var (
	Version1_0 = Version{Major: 0xfe, Minor: 0xff}
	Version1_2 = Version{Major: 0xfe, Minor: 0xfd}
	Version1_3 = Version{Major: 0xfe, Minor: 0xfc}
)

type Version struct {
	Major, Minor uint8
}

func (v Version) Equal(x Version) bool {
	return v.Major == x.Major && v.Minor == x.Minor
}

func IsValidBytes(major uint8, minor uint8) bool {
	return major == 0xfe && (minor == 0xff || minor == 0xfd || minor == 0xfc)
}

func IsValidVersion(v Version) bool {
	return v.Equal(Version1_0) || v.Equal(Version1_2) || v.Equal(Version1_3)
}

// ===================== merged from pkg/protocol/alert/alert.go =====================
var errAlertBufferTooSmall = &TemporaryError{Err: errors.New("buffer is too small")}

type Level byte

const (
	Warning Level = 1
	Fatal   Level = 2
)

func (l Level) String() string {
	switch l {
	case Warning:
		return "Warning"
	case Fatal:
		return "Fatal"
	default:
		return "Invalid alert level"
	}
}

type Description byte

const (
	CloseNotify            Description = 0
	UnexpectedMessage      Description = 10
	BadRecordMac           Description = 20
	DecryptionFailed       Description = 21
	RecordOverflow         Description = 22
	DecompressionFailure   Description = 30
	HandshakeFailure       Description = 40
	NoCertificate          Description = 41
	BadCertificate         Description = 42
	UnsupportedCertificate Description = 43
	CertificateRevoked     Description = 44
	CertificateExpired     Description = 45
	CertificateUnknown     Description = 46
	IllegalParameter       Description = 47
	UnknownCA              Description = 48
	AccessDenied           Description = 49
	DecodeError            Description = 50
	DecryptError           Description = 51
	ExportRestriction      Description = 60
	ProtocolVersion        Description = 70
	InsufficientSecurity   Description = 71
	AlertInternalError     Description = 80
	UserCanceled           Description = 90
	NoRenegotiation        Description = 100
	UnsupportedExtension   Description = 110
	NoApplicationProtocol  Description = 120
)

func (d Description) String() string {
	switch d {
	case CloseNotify:
		return "CloseNotify"
	case UnexpectedMessage:
		return "UnexpectedMessage"
	case BadRecordMac:
		return "BadRecordMac"
	case DecryptionFailed:
		return "DecryptionFailed"
	case RecordOverflow:
		return "RecordOverflow"
	case DecompressionFailure:
		return "DecompressionFailure"
	case HandshakeFailure:
		return "HandshakeFailure"
	case NoCertificate:
		return "NoCertificate"
	case BadCertificate:
		return "BadCertificate"
	case UnsupportedCertificate:
		return "UnsupportedCertificate"
	case CertificateRevoked:
		return "CertificateRevoked"
	case CertificateExpired:
		return "CertificateExpired"
	case CertificateUnknown:
		return "CertificateUnknown"
	case IllegalParameter:
		return "IllegalParameter"
	case UnknownCA:
		return "UnknownCA"
	case AccessDenied:
		return "AccessDenied"
	case DecodeError:
		return "DecodeError"
	case DecryptError:
		return "DecryptError"
	case ExportRestriction:
		return "ExportRestriction"
	case ProtocolVersion:
		return "ProtocolVersion"
	case InsufficientSecurity:
		return "InsufficientSecurity"
	case AlertInternalError:
		return "AlertInternalError"
	case UserCanceled:
		return "UserCanceled"
	case NoRenegotiation:
		return "NoRenegotiation"
	case UnsupportedExtension:
		return "UnsupportedExtension"
	case NoApplicationProtocol:
		return "NoApplicationProtocol"
	default:
		return "Invalid alert description"
	}
}

type Alert struct {
	Level       Level
	Description Description
}

func (a Alert) ContentType() ContentType {
	return ContentTypeAlert
}

func (a *Alert) Marshal() ([]byte, error) {
	return []byte{byte(a.Level), byte(a.Description)}, nil
}

func (a *Alert) Unmarshal(data []byte) error {
	if len(data) != 2 {
		return errAlertBufferTooSmall
	}

	a.Level = Level(data[0])
	a.Description = Description(data[1])

	return nil
}

func (a *Alert) String() string {
	return fmt.Sprintf("Alert %s: %s", a.Level, a.Description)
}

// ===================== merged from pkg/protocol/extension/extension.go =====================
type ALPN struct {
	ProtocolNameList []string
}

func (a ALPN) TypeValue() TypeValue {
	return ALPNTypeValue
}

func (a *ALPN) Marshal() ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16(uint16(a.TypeValue()))
	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, proto := range a.ProtocolNameList {
				p := proto
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(p))
				})
			}
		})
	})

	return builder.Bytes()
}

func (a *ALPN) Unmarshal(data []byte) error {
	val := cryptobyte.String(data)

	var extension uint16
	val.ReadUint16(&extension)
	if TypeValue(extension) != a.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	val.ReadUint16LengthPrefixed(&extData)

	var protoList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
		return ErrALPNInvalidFormat
	}
	for !protoList.Empty() {
		var proto cryptobyte.String
		if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
			return ErrALPNInvalidFormat
		}
		a.ProtocolNameList = append(a.ProtocolNameList, string(proto))
	}

	return nil
}

func ALPNProtocolSelection(supportedProtocols, peerSupportedProtocols []string) (string, error) {
	if len(supportedProtocols) == 0 || len(peerSupportedProtocols) == 0 {
		return "", nil
	}
	for _, s := range supportedProtocols {
		if slices.Contains(peerSupportedProtocols, s) {
			return s, nil
		}
	}

	return "", errALPNNoAppProto
}

type ConnectionID struct {
	CID []byte
}

func (c ConnectionID) TypeValue() TypeValue {
	return ConnectionIDTypeValue
}

func (c *ConnectionID) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(c.TypeValue()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(c.CID)
		})
	})

	return b.Bytes()
}

func (c *ConnectionID) Unmarshal(data []byte) error {
	val := cryptobyte.String(data)
	var extension uint16
	val.ReadUint16(&extension)
	if TypeValue(extension) != c.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	val.ReadUint16LengthPrefixed(&extData)

	var cid cryptobyte.String
	if !extData.ReadUint8LengthPrefixed(&cid) {
		return errInvalidCIDFormat
	}
	c.CID = make([]byte, len(cid))
	if !cid.CopyBytes(c.CID) {
		return errInvalidCIDFormat
	}

	return nil
}

const maxCookieSize = 0xffff - 2

type CookieExt struct {
	Cookie []byte
}

func (c CookieExt) TypeValue() TypeValue {
	return CookieTypeValue
}

func (c *CookieExt) Marshal() ([]byte, error) {
	cookieLength := len(c.Cookie)
	if cookieLength == 0 || cookieLength > maxCookieSize {
		return nil, errCookieExtFormat
	}
	var b cryptobyte.Builder
	b.AddUint16(uint16(c.TypeValue()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(c.Cookie)
		})
	})

	return b.Bytes()
}

func (c *CookieExt) Unmarshal(data []byte) error {
	val := cryptobyte.String(data)
	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != c.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errExtBufferTooSmall
	}

	var cookie cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&cookie) || cookie.Empty() || len(cookie) > maxCookieSize {
		return errCookieExtFormat
	}

	c.Cookie = append([]byte(nil), cookie...)

	return nil
}

var (
	ErrALPNInvalidFormat = &FatalError{
		Err: errors.New("invalid alpn format"),
	}
	errALPNNoAppProto = &FatalError{
		Err: errors.New("no application protocol"),
	}
	errExtBufferTooSmall = &TemporaryError{
		Err: errors.New("buffer is too small"),
	}
	errInvalidExtensionType = &FatalError{
		Err: errors.New("invalid extension type"),
	}
	errInvalidSNIFormat = &FatalError{
		Err: errors.New("invalid server name format"),
	}
	errInvalidCIDFormat = &FatalError{
		Err: errors.New("invalid connection ID format"),
	}
	errExtLengthMismatch = &InternalError{
		Err: errors.New("data length and declared length do not match"),
	}
	errMasterKeyIdentifierTooLarge = &FatalError{
		Err: errors.New("master key identifier is over 255 bytes"),
	}
	errCookieExtFormat = &FatalError{
		Err: errors.New("invalid cookie format"),
	}
	errInvalidKeyShareFormat = &FatalError{
		Err: errors.New("invalid key_share format"),
	}
	errDuplicateKeyShare = &FatalError{
		Err: errors.New("duplicate key_share group"),
	}
	errInvalidSupportedVersionsFormat = &FatalError{
		Err: errors.New("invalid supported_versions format"),
	}
	errInvalidDTLSVersion = &InternalError{
		Err: errors.New("invalid dtls version was provided"),
	}
)

type TypeValue uint16

const (
	ServerNameTypeValue TypeValue = 0

	SupportedEllipticCurvesTypeValue      TypeValue = 10
	SupportedPointFormatsTypeValue        TypeValue = 11
	SupportedSignatureAlgorithmsTypeValue TypeValue = 13
	UseSRTPTypeValue                      TypeValue = 14
	ALPNTypeValue                         TypeValue = 16
	UseExtendedMasterSecretTypeValue      TypeValue = 23
	SupportedVersionsTypeValue            TypeValue = 43
	CookieTypeValue                       TypeValue = 44
	SignatureAlgorithmsCertTypeValue      TypeValue = 50
	KeyShareTypeValue                     TypeValue = 51
	ConnectionIDTypeValue                 TypeValue = 54
	RenegotiationInfoTypeValue            TypeValue = 65281
)

type Extension interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	TypeValue() TypeValue
}

func Unmarshal(buf []byte) ([]Extension, error) {
	switch {
	case len(buf) == 0:
		return []Extension{}, nil
	case len(buf) < 2:
		return nil, errExtBufferTooSmall
	}

	declaredLen := binary.BigEndian.Uint16(buf)
	if len(buf)-2 != int(declaredLen) {
		return nil, errExtLengthMismatch
	}

	extensions := []Extension{}
	unmarshalAndAppend := func(data []byte, e Extension) error {
		err := e.Unmarshal(data)
		if err != nil {
			return err
		}
		extensions = append(extensions, e)

		return nil
	}

	for offset := 2; offset < len(buf); {
		bufView := buf[offset:]
		if len(bufView) < 2 {
			return nil, errExtBufferTooSmall
		}

		var err error
		switch TypeValue(binary.BigEndian.Uint16(bufView)) {
		case ServerNameTypeValue:
			err = unmarshalAndAppend(bufView, &ServerName{})
		case SupportedEllipticCurvesTypeValue:
			err = unmarshalAndAppend(bufView, &SupportedEllipticCurves{})
		case SupportedPointFormatsTypeValue:
			err = unmarshalAndAppend(bufView, &SupportedPointFormats{})
		case SupportedSignatureAlgorithmsTypeValue:
			err = unmarshalAndAppend(bufView, &SupportedSignatureAlgorithms{})
		case SignatureAlgorithmsCertTypeValue:
			err = unmarshalAndAppend(bufView, &SignatureAlgorithmsCert{})
		case UseSRTPTypeValue:
			err = unmarshalAndAppend(bufView, &UseSRTP{})
		case ALPNTypeValue:
			err = unmarshalAndAppend(bufView, &ALPN{})
		case UseExtendedMasterSecretTypeValue:
			err = unmarshalAndAppend(bufView, &UseExtendedMasterSecret{})
		case RenegotiationInfoTypeValue:
			err = unmarshalAndAppend(bufView, &RenegotiationInfo{})
		case ConnectionIDTypeValue:
			err = unmarshalAndAppend(bufView, &ConnectionID{})
		case SupportedVersionsTypeValue:
			err = unmarshalAndAppend(bufView, &SupportedVersions{})
		case KeyShareTypeValue:
			err = unmarshalAndAppend(bufView, &KeyShare{})
		case CookieTypeValue:
			err = unmarshalAndAppend(bufView, &CookieExt{})
		default:
		}

		if err != nil {
			return nil, err
		}
		if len(bufView) < 4 {
			return nil, errExtBufferTooSmall
		}
		extensionLength := binary.BigEndian.Uint16(bufView[2:])
		offset += (4 + int(extensionLength))
	}

	return extensions, nil
}

func Marshal(e []Extension) ([]byte, error) {
	extensions := []byte{}
	for _, e := range e {
		raw, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, raw...)
	}
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(extensions)))

	return append(out, extensions...), nil
}

func parseSignatureSchemeU16(scheme uint16) (HashAlgorithm, SignatureAlgorithm) {
	if SignatureAlgorithm(scheme).IsPSS() {

		return ExtractHashFromPSS(scheme), SignatureAlgorithm(scheme)
	}

	return HashAlgorithm(scheme >> 8), SignatureAlgorithm(scheme & 0xFF)
}

func marshalGenericSignatureHashAlgorithm(typeValue TypeValue, sigHashAlgs []SignatureHashAlgorithm) ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16(uint16(typeValue))
	builder.AddUint16LengthPrefixed(func(extBuilder *cryptobyte.Builder) {
		extBuilder.AddUint16LengthPrefixed(func(algBuilder *cryptobyte.Builder) {
			for _, v := range sigHashAlgs {

				if v.Signature.IsPSS() {

					algBuilder.AddUint16(uint16(v.Signature))
				} else {

					algBuilder.AddUint8(byte(v.Hash))
					algBuilder.AddUint8(byte(v.Signature))
				}
			}
		})
	})

	return builder.Bytes()
}

func unmarshalGenericSignatureHashAlgorithm(typeValue TypeValue, data []byte, dst *[]SignatureHashAlgorithm) error {
	val := cryptobyte.String(data)
	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != typeValue {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errExtBufferTooSmall
	}

	var algData cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&algData) {
		return errExtLengthMismatch
	}

	for !algData.Empty() {
		var scheme uint16
		if !algData.ReadUint16(&scheme) {
			return errExtLengthMismatch
		}

		supportedHashAlgorithm, supportedSignatureAlgorithm := parseSignatureSchemeU16(scheme)

		if _, ok := HashAlgorithms()[supportedHashAlgorithm]; ok {
			if _, ok := SignatureAlgorithms()[supportedSignatureAlgorithm]; ok {
				*dst = append(*dst, SignatureHashAlgorithm{
					Hash:      supportedHashAlgorithm,
					Signature: supportedSignatureAlgorithm,
				})
			}
		}
	}

	return nil
}

type KeyShareEntry struct {
	Group       Curve
	KeyExchange []byte
}

type KeyShare struct {
	ClientShares  []KeyShareEntry
	ServerShare   *KeyShareEntry
	SelectedGroup *Curve
}

func (k KeyShare) TypeValue() TypeValue { return KeyShareTypeValue }

func (k *KeyShare) Marshal() ([]byte, error) {
	hasClientShares := k.ClientShares != nil
	hasServerShare := k.ServerShare != nil
	hasHelloRetryRequest := k.SelectedGroup != nil

	if hasTooManyContexts(hasClientShares, hasServerShare, hasHelloRetryRequest) {
		return nil, errInvalidKeyShareFormat
	}

	var builder cryptobyte.Builder

	builder.AddUint16(uint16(k.TypeValue()))

	if hasClientShares {
		seenGroups := map[Curve]struct{}{}
		for _, e := range k.ClientShares {
			if _, ok := seenGroups[e.Group]; ok {
				return nil, errDuplicateKeyShare
			}

			seenGroups[e.Group] = struct{}{}

			if l := len(e.KeyExchange); l == 0 || l > 0xffff {
				return nil, errInvalidKeyShareFormat
			}
		}
	}

	if hasServerShare {
		if l := len(k.ServerShare.KeyExchange); l == 0 || l > 0xffff {
			return nil, errInvalidKeyShareFormat
		}
	}

	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		switch {
		case hasHelloRetryRequest:

			b.AddUint16(uint16(*k.SelectedGroup))

		case hasServerShare:

			addKeyShareEntry(b, *k.ServerShare)

		default:

			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, e := range k.ClientShares {
					addKeyShareEntry(b, e)
				}
			})
		}
	})

	return builder.Bytes()
}

func (k *KeyShare) Unmarshal(data []byte) error {
	val := cryptobyte.String(data)
	var extData cryptobyte.String

	var ext uint16
	if !val.ReadUint16(&ext) || TypeValue(ext) != k.TypeValue() {
		return errInvalidExtensionType
	}
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errExtBufferTooSmall
	}
	if extData.Empty() {
		return errInvalidKeyShareFormat
	}

	k.ClientShares, k.ServerShare, k.SelectedGroup = nil, nil, nil

	peek := extData
	var vecLen uint16

	if peek.ReadUint16(&vecLen) && int(vecLen) == len(peek) {
		seenGroups := map[Curve]struct{}{}
		for !peek.Empty() {
			var entry KeyShareEntry
			var groupU16 uint16
			var raw cryptobyte.String

			if !peek.ReadUint16(&groupU16) || !peek.ReadUint16LengthPrefixed(&raw) || len(raw) == 0 {
				return errInvalidKeyShareFormat
			}

			group := Curve(groupU16)

			if _, ok := seenGroups[group]; ok {
				return errDuplicateKeyShare
			}

			seenGroups[group] = struct{}{}

			entry.Group = group
			entry.KeyExchange = append([]byte(nil), raw...)
			k.ClientShares = append(k.ClientShares, entry)
		}

		if !extData.Skip(2 + int(vecLen)) {
			return errInvalidKeyShareFormat
		}

		return nil
	}

	if len(extData) == 2 {
		var groupU16 uint16
		if !extData.ReadUint16(&groupU16) {
			return errInvalidKeyShareFormat
		}

		group := Curve(groupU16)
		if Curves()[group] {
			k.SelectedGroup = &group
		}

		return nil
	}

	var groupU16 uint16
	var raw cryptobyte.String

	if !extData.ReadUint16(&groupU16) || !extData.ReadUint16LengthPrefixed(&raw) || !extData.Empty() || len(raw) == 0 {
		return errInvalidKeyShareFormat
	}

	group := Curve(groupU16)
	share := KeyShareEntry{Group: group, KeyExchange: append([]byte(nil), raw...)}
	k.ServerShare = &share

	return nil
}

func addKeyShareEntry(b *cryptobyte.Builder, e KeyShareEntry) {
	b.AddUint16(uint16(e.Group))

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.KeyExchange)
	})
}

func hasTooManyContexts(a bool, b bool, c bool) bool {
	return (a && b) || (a && c) || (b && c)
}

const (
	renegotiationInfoHeaderSize = 5
)

type RenegotiationInfo struct {
	RenegotiatedConnection uint8
}

func (r RenegotiationInfo) TypeValue() TypeValue {
	return RenegotiationInfoTypeValue
}

func (r *RenegotiationInfo) Marshal() ([]byte, error) {
	out := make([]byte, renegotiationInfoHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(r.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(1))
	out[4] = r.RenegotiatedConnection

	return out, nil
}

func (r *RenegotiationInfo) Unmarshal(data []byte) error {
	if len(data) < renegotiationInfoHeaderSize {
		return errExtBufferTooSmall
	} else if TypeValue(binary.BigEndian.Uint16(data)) != r.TypeValue() {
		return errInvalidExtensionType
	}

	r.RenegotiatedConnection = data[4]

	return nil
}

const serverNameTypeDNSHostName = 0

type ServerName struct {
	ServerName string
}

func (s ServerName) TypeValue() TypeValue {
	return ServerNameTypeValue
}

func (s *ServerName) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(uint16(s.TypeValue()))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(serverNameTypeDNSHostName)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(s.ServerName))
			})
		})
	})

	return b.Bytes()
}

func (s *ServerName) Unmarshal(data []byte) error {
	val := cryptobyte.String(data)
	var extension uint16
	val.ReadUint16(&extension)
	if TypeValue(extension) != s.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	val.ReadUint16LengthPrefixed(&extData)

	var nameList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
		return errInvalidSNIFormat
	}
	for !nameList.Empty() {
		var nameType uint8
		var serverName cryptobyte.String
		if !nameList.ReadUint8(&nameType) ||
			!nameList.ReadUint16LengthPrefixed(&serverName) ||
			serverName.Empty() {
			return errInvalidSNIFormat
		}
		if nameType != serverNameTypeDNSHostName {
			continue
		}
		if len(s.ServerName) != 0 {

			return errInvalidSNIFormat
		}
		s.ServerName = string(serverName)

		if strings.HasSuffix(s.ServerName, ".") {
			return errInvalidSNIFormat
		}
	}

	return nil
}

type SignatureAlgorithmsCert struct {
	SignatureHashAlgorithms []SignatureHashAlgorithm
}

func (s SignatureAlgorithmsCert) TypeValue() TypeValue {
	return SignatureAlgorithmsCertTypeValue
}

func (s *SignatureAlgorithmsCert) Marshal() ([]byte, error) {
	return marshalGenericSignatureHashAlgorithm(s.TypeValue(), s.SignatureHashAlgorithms)
}

func (s *SignatureAlgorithmsCert) Unmarshal(data []byte) error {
	s.SignatureHashAlgorithms = []SignatureHashAlgorithm{}

	return unmarshalGenericSignatureHashAlgorithm(s.TypeValue(), data, &s.SignatureHashAlgorithms)
}

type SRTPProtectionProfile uint16

const (
	SRTP_AES128_CM_HMAC_SHA1_80 SRTPProtectionProfile = 0x0001
	SRTP_AES128_CM_HMAC_SHA1_32 SRTPProtectionProfile = 0x0002
	SRTP_AES256_CM_SHA1_80      SRTPProtectionProfile = 0x0003
	SRTP_AES256_CM_SHA1_32      SRTPProtectionProfile = 0x0004
	SRTP_NULL_HMAC_SHA1_80      SRTPProtectionProfile = 0x0005
	SRTP_NULL_HMAC_SHA1_32      SRTPProtectionProfile = 0x0006
	SRTP_AEAD_AES_128_GCM       SRTPProtectionProfile = 0x0007
	SRTP_AEAD_AES_256_GCM       SRTPProtectionProfile = 0x0008
)

func srtpProtectionProfiles() map[SRTPProtectionProfile]bool {
	return map[SRTPProtectionProfile]bool{
		SRTP_AES128_CM_HMAC_SHA1_80: true,
		SRTP_AES128_CM_HMAC_SHA1_32: true,
		SRTP_AES256_CM_SHA1_80:      true,
		SRTP_AES256_CM_SHA1_32:      true,
		SRTP_NULL_HMAC_SHA1_80:      true,
		SRTP_NULL_HMAC_SHA1_32:      true,
		SRTP_AEAD_AES_128_GCM:       true,
		SRTP_AEAD_AES_256_GCM:       true,
	}
}

const (
	supportedGroupsHeaderSize = 6
)

type SupportedEllipticCurves struct {
	EllipticCurves []Curve
}

func (s SupportedEllipticCurves) TypeValue() TypeValue {
	return SupportedEllipticCurvesTypeValue
}

func (s *SupportedEllipticCurves) Marshal() ([]byte, error) {
	out := make([]byte, supportedGroupsHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(s.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(2+(len(s.EllipticCurves)*2)))
	binary.BigEndian.PutUint16(out[4:], uint16(len(s.EllipticCurves)*2))

	for _, v := range s.EllipticCurves {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(v))
	}

	return out, nil
}

func (s *SupportedEllipticCurves) Unmarshal(data []byte) error {
	if len(data) <= supportedGroupsHeaderSize {
		return errExtBufferTooSmall
	} else if TypeValue(binary.BigEndian.Uint16(data)) != s.TypeValue() {
		return errInvalidExtensionType
	}

	groupCount := int(binary.BigEndian.Uint16(data[4:]) / 2)
	if supportedGroupsHeaderSize+(groupCount*2) > len(data) {
		return errExtLengthMismatch
	}

	for i := 0; i < groupCount; i++ {
		supportedGroupID := Curve(binary.BigEndian.Uint16(data[(supportedGroupsHeaderSize + (i * 2)):]))
		if _, ok := Curves()[supportedGroupID]; ok {
			s.EllipticCurves = append(s.EllipticCurves, supportedGroupID)
		}
	}

	return nil
}

const (
	supportedPointFormatsSize = 5
)

type SupportedPointFormats struct {
	PointFormats []CurvePointFormat
}

func (s SupportedPointFormats) TypeValue() TypeValue {
	return SupportedPointFormatsTypeValue
}

func (s *SupportedPointFormats) Marshal() ([]byte, error) {
	out := make([]byte, supportedPointFormatsSize)

	binary.BigEndian.PutUint16(out, uint16(s.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(1+(len(s.PointFormats))))
	out[4] = byte(len(s.PointFormats))

	for _, v := range s.PointFormats {
		out = append(out, byte(v))
	}

	return out, nil
}

func (s *SupportedPointFormats) Unmarshal(data []byte) error {
	if len(data) <= supportedPointFormatsSize {
		return errExtBufferTooSmall
	}

	if TypeValue(binary.BigEndian.Uint16(data)) != s.TypeValue() {
		return errInvalidExtensionType
	}

	pointFormatCount := int(data[4])
	if supportedPointFormatsSize+pointFormatCount > len(data) {
		return errExtLengthMismatch
	}

	for i := 0; i < pointFormatCount; i++ {
		p := CurvePointFormat(data[supportedPointFormatsSize+i])
		switch p {
		case CurvePointFormatUncompressed:
			s.PointFormats = append(s.PointFormats, p)
		default:
		}
	}

	return nil
}

type SupportedSignatureAlgorithms struct {
	SignatureHashAlgorithms []SignatureHashAlgorithm
}

func (s SupportedSignatureAlgorithms) TypeValue() TypeValue {
	return SupportedSignatureAlgorithmsTypeValue
}

func (s *SupportedSignatureAlgorithms) Marshal() ([]byte, error) {
	return marshalGenericSignatureHashAlgorithm(s.TypeValue(), s.SignatureHashAlgorithms)
}

func (s *SupportedSignatureAlgorithms) Unmarshal(data []byte) error {
	s.SignatureHashAlgorithms = []SignatureHashAlgorithm{}

	return unmarshalGenericSignatureHashAlgorithm(s.TypeValue(), data, &s.SignatureHashAlgorithms)
}

type SupportedVersions struct {
	Versions []Version
}

func (s SupportedVersions) TypeValue() TypeValue { return SupportedVersionsTypeValue }

func (s *SupportedVersions) Marshal() ([]byte, error) {
	if len(s.Versions) == 0 {
		return nil, errInvalidSupportedVersionsFormat
	}

	totalBytes := len(s.Versions) * 2

	if totalBytes < 2 || totalBytes > 254 {
		return nil, errInvalidSupportedVersionsFormat
	}

	for _, v := range s.Versions {
		if !IsValidVersion(v) {
			return nil, errInvalidDTLSVersion
		}
	}

	var builder cryptobyte.Builder

	builder.AddUint16(uint16(s.TypeValue()))
	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		if len(s.Versions) == 1 {

			b.AddUint8(s.Versions[0].Major)
			b.AddUint8(s.Versions[0].Minor)

			return
		}

		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, v := range s.Versions {
				b.AddUint8(v.Major)
				b.AddUint8(v.Minor)
			}
		})
	})

	return builder.Bytes()
}

func (s *SupportedVersions) Unmarshal(data []byte) error {
	val := cryptobyte.String(data)
	var extData cryptobyte.String

	var extension uint16
	val.ReadUint16(&extension)
	if TypeValue(extension) != s.TypeValue() {
		return errInvalidExtensionType
	}

	if !val.ReadUint16LengthPrefixed(&extData) {
		return errExtBufferTooSmall
	}

	if extData.Empty() {
		return errInvalidSupportedVersionsFormat
	}

	peek := extData
	var listLen uint8
	if peek.ReadUint8(&listLen) && int(listLen) == len(peek) && listLen >= 2 && (listLen%2) == 0 {
		s.Versions = s.Versions[:0]

		for !peek.Empty() {
			var major, minor uint8
			if !peek.ReadUint8(&major) || !peek.ReadUint8(&minor) {
				return errInvalidSupportedVersionsFormat
			}

			if IsValidBytes(major, minor) {
				s.Versions = append(s.Versions, Version{Major: major, Minor: minor})
			}
		}

		if !extData.Skip(1 + int(listLen)) {
			return errInvalidSupportedVersionsFormat
		}

		return nil
	}

	if len(extData) != 2 {
		return errInvalidSupportedVersionsFormat
	}

	var major, minor uint8
	if !extData.ReadUint8(&major) || !extData.ReadUint8(&minor) {
		return errInvalidSupportedVersionsFormat
	}

	if IsValidBytes(major, minor) {
		s.Versions = append(s.Versions[:0], Version{Major: major, Minor: minor})
	}

	return nil
}

const (
	useExtendedMasterSecretHeaderSize = 4
)

type UseExtendedMasterSecret struct {
	Supported bool
}

func (u UseExtendedMasterSecret) TypeValue() TypeValue {
	return UseExtendedMasterSecretTypeValue
}

func (u *UseExtendedMasterSecret) Marshal() ([]byte, error) {
	if !u.Supported {
		return []byte{}, nil
	}

	out := make([]byte, useExtendedMasterSecretHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(u.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(0))

	return out, nil
}

func (u *UseExtendedMasterSecret) Unmarshal(data []byte) error {
	if len(data) < useExtendedMasterSecretHeaderSize {
		return errExtBufferTooSmall
	} else if TypeValue(binary.BigEndian.Uint16(data)) != u.TypeValue() {
		return errInvalidExtensionType
	}

	u.Supported = true

	return nil
}

const (
	useSRTPHeaderSize = 6
)

type UseSRTP struct {
	ProtectionProfiles  []SRTPProtectionProfile
	MasterKeyIdentifier []byte
}

func (u UseSRTP) TypeValue() TypeValue {
	return UseSRTPTypeValue
}

func (u *UseSRTP) Marshal() ([]byte, error) {
	out := make([]byte, useSRTPHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(u.TypeValue()))

	binary.BigEndian.PutUint16(
		out[2:],
		uint16(2+(len(u.ProtectionProfiles)*2)+1+len(u.MasterKeyIdentifier)),
	)
	binary.BigEndian.PutUint16(out[4:], uint16(len(u.ProtectionProfiles)*2))

	for _, v := range u.ProtectionProfiles {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(v))
	}
	if len(u.MasterKeyIdentifier) > 255 {
		return nil, errMasterKeyIdentifierTooLarge
	}

	out = append(out, byte(len(u.MasterKeyIdentifier)))
	out = append(out, u.MasterKeyIdentifier...)

	return out, nil
}

func (u *UseSRTP) Unmarshal(data []byte) error {
	if len(data) <= useSRTPHeaderSize {
		return errExtBufferTooSmall
	} else if TypeValue(binary.BigEndian.Uint16(data)) != u.TypeValue() {
		return errInvalidExtensionType
	}

	profileCount := int(binary.BigEndian.Uint16(data[4:]) / 2)
	masterKeyIdentifierIndex := supportedGroupsHeaderSize + (profileCount * 2)
	if masterKeyIdentifierIndex+1 > len(data) {
		return errExtLengthMismatch
	}

	for i := 0; i < profileCount; i++ {
		supportedProfile := SRTPProtectionProfile(binary.BigEndian.Uint16(data[(useSRTPHeaderSize + (i * 2)):]))
		if _, ok := srtpProtectionProfiles()[supportedProfile]; ok {
			u.ProtectionProfiles = append(u.ProtectionProfiles, supportedProfile)
		}
	}

	masterKeyIdentifierLen := int(data[masterKeyIdentifierIndex])
	if masterKeyIdentifierIndex+masterKeyIdentifierLen >= len(data) {
		return errExtLengthMismatch
	}

	u.MasterKeyIdentifier = append(
		[]byte{},
		data[masterKeyIdentifierIndex+1:masterKeyIdentifierIndex+1+masterKeyIdentifierLen]...,
	)

	return nil
}

// ===================== merged from pkg/protocol/handshake/handshake.go =====================
func decodeCipherSuiteIDs(buf []byte) ([]uint16, error) {
	if len(buf) < 2 {
		return nil, errHsBufferTooSmall
	}
	cipherSuitesCount := int(binary.BigEndian.Uint16(buf[0:])) / 2
	rtrn := make([]uint16, cipherSuitesCount)
	for i := 0; i < cipherSuitesCount; i++ {
		if len(buf) < (i*2 + 4) {
			return nil, errHsBufferTooSmall
		}

		rtrn[i] = binary.BigEndian.Uint16(buf[(i*2)+2:])
	}

	return rtrn, nil
}

func encodeCipherSuiteIDs(cipherSuiteIDs []uint16) []byte {
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(cipherSuiteIDs)*2))
	for _, id := range cipherSuiteIDs {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], id)
	}

	return out
}

var (
	errUnableToMarshalFragmented = &InternalError{
		Err: errors.New("unable to marshal fragmented handshakes"),
	}
	errHandshakeMessageUnset = &InternalError{
		Err: errors.New("handshake message unset, unable to marshal"),
	}
	errHsBufferTooSmall = &TemporaryError{
		Err: errors.New("buffer is too small"),
	}
	errHsLengthMismatch = &InternalError{
		Err: errors.New("data length and declared length do not match"),
	}
	errInvalidClientKeyExchange = &FatalError{
		Err: errors.New("unable to determine if ClientKeyExchange is a public key or PSK Identity"),
	}
	errHsInvalidHashAlgorithm = &FatalError{
		Err: errors.New("invalid hash algorithm"),
	}
	errHsInvalidSignatureAlgorithm = &FatalError{
		Err: errors.New("invalid signature algorithm"),
	}
	errCookieTooLong = &FatalError{
		Err: errors.New("cookie must not be longer then 255 bytes"),
	}
	errInvalidEllipticCurveType = &FatalError{
		Err: errors.New("invalid or unknown elliptic curve type"),
	}
	errHsInvalidNamedCurve = &FatalError{
		Err: errors.New("invalid named curve"),
	}
	errCipherSuiteUnset = &FatalError{
		Err: errors.New("server hello can not be created without a cipher suite"),
	}
	errCompressionMethodUnset = &FatalError{
		Err: errors.New("server hello can not be created without a compression method"),
	}
	errInvalidCompressionMethod = &FatalError{
		Err: errors.New("invalid or unknown compression method"),
	}
	errNotImplemented = &InternalError{
		Err: errors.New("feature has not been implemented yet"),
	}
)

type HandshakeType uint8

const (
	TypeHelloRequest       HandshakeType = 0
	TypeClientHello        HandshakeType = 1
	TypeServerHello        HandshakeType = 2
	TypeHelloVerifyRequest HandshakeType = 3
	TypeCertificate        HandshakeType = 11
	TypeServerKeyExchange  HandshakeType = 12
	TypeCertificateRequest HandshakeType = 13
	TypeServerHelloDone    HandshakeType = 14
	TypeCertificateVerify  HandshakeType = 15
	TypeClientKeyExchange  HandshakeType = 16
	TypeFinished           HandshakeType = 20
)

func (t HandshakeType) String() string {
	switch t {
	case TypeHelloRequest:
		return "HelloRequest"
	case TypeClientHello:
		return "ClientHello"
	case TypeServerHello:
		return "ServerHello"
	case TypeHelloVerifyRequest:
		return "HelloVerifyRequest"
	case TypeCertificate:
		return "TypeCertificate"
	case TypeServerKeyExchange:
		return "ServerKeyExchange"
	case TypeCertificateRequest:
		return "CertificateRequest"
	case TypeServerHelloDone:
		return "ServerHelloDone"
	case TypeCertificateVerify:
		return "CertificateVerify"
	case TypeClientKeyExchange:
		return "ClientKeyExchange"
	case TypeFinished:
		return "Finished"
	}

	return ""
}

type Message interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	HandshakeType() HandshakeType
}

type Handshake struct {
	Header               HandshakeHeader
	Message              Message
	KeyExchangeAlgorithm KeyExchangeAlgorithm
}

func (h Handshake) ContentType() ContentType {
	return ContentTypeHandshake
}

func (h *Handshake) Marshal() ([]byte, error) {
	if h.Message == nil {
		return nil, errHandshakeMessageUnset
	} else if h.Header.FragmentOffset != 0 {
		return nil, errUnableToMarshalFragmented
	}

	msg, err := h.Message.Marshal()
	if err != nil {
		return nil, err
	}

	h.Header.Length = uint32(len(msg))
	h.Header.FragmentLength = h.Header.Length
	h.Header.Type = h.Message.HandshakeType()
	header, err := h.Header.Marshal()
	if err != nil {
		return nil, err
	}

	return append(header, msg...), nil
}

func (h *Handshake) Unmarshal(data []byte) error {
	if err := h.Header.Unmarshal(data); err != nil {
		return err
	}

	reportedLen := webrtc.BEUint24(data[1:])
	if uint32(len(data)-HandshakeHeaderLength) != reportedLen {
		return errHsLengthMismatch
	} else if reportedLen != h.Header.FragmentLength {
		return errHsLengthMismatch
	}

	switch HandshakeType(data[0]) {
	case TypeHelloRequest:
		return errNotImplemented
	case TypeClientHello:
		h.Message = &MessageClientHello{}
	case TypeHelloVerifyRequest:
		h.Message = &MessageHelloVerifyRequest{}
	case TypeServerHello:
		h.Message = &MessageServerHello{}
	case TypeCertificate:
		h.Message = &MessageCertificate{}
	case TypeServerKeyExchange:
		h.Message = &MessageServerKeyExchange{KeyExchangeAlgorithm: h.KeyExchangeAlgorithm}
	case TypeCertificateRequest:
		h.Message = &MessageCertificateRequest{}
	case TypeServerHelloDone:
		h.Message = &MessageServerHelloDone{}
	case TypeClientKeyExchange:
		h.Message = &MessageClientKeyExchange{KeyExchangeAlgorithm: h.KeyExchangeAlgorithm}
	case TypeFinished:
		h.Message = &MessageFinished{}
	case TypeCertificateVerify:
		h.Message = &MessageCertificateVerify{}
	default:
		return errNotImplemented
	}

	return h.Message.Unmarshal(data[HandshakeHeaderLength:])
}

const HandshakeHeaderLength = 12

type HandshakeHeader struct {
	Type            HandshakeType
	Length          uint32
	MessageSequence uint16
	FragmentOffset  uint32
	FragmentLength  uint32
}

func (h *HandshakeHeader) Marshal() ([]byte, error) {
	out := make([]byte, HandshakeHeaderLength)

	out[0] = byte(h.Type)
	webrtc.PutBEUint24(out[1:], h.Length)
	binary.BigEndian.PutUint16(out[4:], h.MessageSequence)
	webrtc.PutBEUint24(out[6:], h.FragmentOffset)
	webrtc.PutBEUint24(out[9:], h.FragmentLength)

	return out, nil
}

func (h *HandshakeHeader) Unmarshal(data []byte) error {
	if len(data) < HandshakeHeaderLength {
		return errHsBufferTooSmall
	}

	h.Type = HandshakeType(data[0])
	h.Length = webrtc.BEUint24(data[1:])
	h.MessageSequence = binary.BigEndian.Uint16(data[4:])
	h.FragmentOffset = webrtc.BEUint24(data[6:])
	h.FragmentLength = webrtc.BEUint24(data[9:])

	return nil
}

type MessageCertificate struct {
	Certificate [][]byte
}

func (m MessageCertificate) HandshakeType() HandshakeType {
	return TypeCertificate
}

const (
	handshakeMessageCertificateLengthFieldSize = 3
)

func (m *MessageCertificate) Marshal() ([]byte, error) {
	out := make([]byte, handshakeMessageCertificateLengthFieldSize)

	for _, r := range m.Certificate {

		out = append(out, make([]byte, handshakeMessageCertificateLengthFieldSize)...)

		webrtc.PutBEUint24(out[len(out)-handshakeMessageCertificateLengthFieldSize:], uint32(len(r)))

		out = append(out, append([]byte{}, r...)...)
	}

	webrtc.PutBEUint24(out[0:], uint32(len(out[handshakeMessageCertificateLengthFieldSize:])))

	return out, nil
}

func (m *MessageCertificate) Unmarshal(data []byte) error {
	if len(data) < handshakeMessageCertificateLengthFieldSize {
		return errHsBufferTooSmall
	}

	if certificateBodyLen := int(webrtc.BEUint24(
		data,
	)); certificateBodyLen+handshakeMessageCertificateLengthFieldSize != len(data) {
		return errHsLengthMismatch
	}

	offset := handshakeMessageCertificateLengthFieldSize
	for offset < len(data) {
		certificateLen := int(webrtc.BEUint24(data[offset:]))
		offset += handshakeMessageCertificateLengthFieldSize

		if offset+certificateLen > len(data) {
			return errHsLengthMismatch
		}

		m.Certificate = append(m.Certificate, append([]byte{}, data[offset:offset+certificateLen]...))
		offset += certificateLen
	}

	return nil
}

type MessageCertificateRequest struct {
	CertificateTypes            []ClientCertificateType
	SignatureHashAlgorithms     []SignatureHashAlgorithm
	CertificateAuthoritiesNames [][]byte
}

const (
	messageCertificateRequestMinLength = 5
)

func (m MessageCertificateRequest) HandshakeType() HandshakeType {
	return TypeCertificateRequest
}

func (m *MessageCertificateRequest) Marshal() ([]byte, error) {
	out := []byte{byte(len(m.CertificateTypes))}
	for _, v := range m.CertificateTypes {
		out = append(out, byte(v))
	}

	out = append(out, []byte{0x00, 0x00}...)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(m.SignatureHashAlgorithms)*2))
	for _, v := range m.SignatureHashAlgorithms {
		out = append(out, byte(v.Hash))
		out = append(out, byte(v.Signature))
	}

	casLength := 0
	for _, ca := range m.CertificateAuthoritiesNames {
		casLength += len(ca) + 2
	}
	out = append(out, []byte{0x00, 0x00}...)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(casLength))
	if casLength > 0 {
		for _, ca := range m.CertificateAuthoritiesNames {
			out = append(out, []byte{0x00, 0x00}...)
			binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(ca)))
			out = append(out, ca...)
		}
	}

	return out, nil
}

func (m *MessageCertificateRequest) Unmarshal(data []byte) error {
	if len(data) < messageCertificateRequestMinLength {
		return errHsBufferTooSmall
	}

	offset := 0
	certificateTypesLength := int(data[0])
	offset++

	if (offset + certificateTypesLength) > len(data) {
		return errHsBufferTooSmall
	}

	for i := 0; i < certificateTypesLength; i++ {
		certType := ClientCertificateType(data[offset+i])
		if _, ok := ClientCertificateTypes()[certType]; ok {
			m.CertificateTypes = append(m.CertificateTypes, certType)
		}
	}
	offset += certificateTypesLength
	if len(data) < offset+2 {
		return errHsBufferTooSmall
	}
	signatureHashAlgorithmsLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if (offset + signatureHashAlgorithmsLength) > len(data) {
		return errHsBufferTooSmall
	}

	for i := 0; i < signatureHashAlgorithmsLength; i += 2 {
		if len(data) < (offset + i + 2) {
			return errHsBufferTooSmall
		}
		h := HashAlgorithm(data[offset+i])
		s := SignatureAlgorithm(data[offset+i+1])

		if _, ok := HashAlgorithms()[h]; !ok {
			continue
		} else if _, ok := SignatureAlgorithms()[s]; !ok {
			continue
		}
		m.SignatureHashAlgorithms = append(m.SignatureHashAlgorithms, SignatureHashAlgorithm{Signature: s, Hash: h})
	}

	offset += signatureHashAlgorithmsLength
	if len(data) < offset+2 {
		return errHsBufferTooSmall
	}
	casLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if (offset + casLength) > len(data) {
		return errHsBufferTooSmall
	}
	cas := make([]byte, casLength)
	copy(cas, data[offset:offset+casLength])
	m.CertificateAuthoritiesNames = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return errHsBufferTooSmall
		}
		caLen := binary.BigEndian.Uint16(cas)
		cas = cas[2:]

		if len(cas) < int(caLen) {
			return errHsBufferTooSmall
		}

		m.CertificateAuthoritiesNames = append(m.CertificateAuthoritiesNames, cas[:caLen])
		cas = cas[caLen:]
	}

	return nil
}

type MessageCertificateVerify struct {
	HashAlgorithm      HashAlgorithm
	SignatureAlgorithm SignatureAlgorithm
	Signature          []byte
}

const handshakeMessageCertificateVerifyMinLength = 4

func (m MessageCertificateVerify) HandshakeType() HandshakeType {
	return TypeCertificateVerify
}

func (m *MessageCertificateVerify) Marshal() ([]byte, error) {
	out := make([]byte, 1+1+2+len(m.Signature))

	out[0] = byte(m.HashAlgorithm)
	out[1] = byte(m.SignatureAlgorithm)
	binary.BigEndian.PutUint16(out[2:], uint16(len(m.Signature)))
	copy(out[4:], m.Signature)

	return out, nil
}

func (m *MessageCertificateVerify) Unmarshal(data []byte) error {
	if len(data) < handshakeMessageCertificateVerifyMinLength {
		return errHsBufferTooSmall
	}

	m.HashAlgorithm = HashAlgorithm(data[0])
	if _, ok := HashAlgorithms()[m.HashAlgorithm]; !ok {
		return errHsInvalidHashAlgorithm
	}

	m.SignatureAlgorithm = SignatureAlgorithm(data[1])
	if _, ok := SignatureAlgorithms()[m.SignatureAlgorithm]; !ok {
		return errHsInvalidSignatureAlgorithm
	}

	signatureLength := int(binary.BigEndian.Uint16(data[2:]))
	if (signatureLength + 4) != len(data) {
		return errHsBufferTooSmall
	}

	m.Signature = append([]byte{}, data[4:]...)

	return nil
}

type MessageClientHello struct {
	Version            Version
	Random             Random
	Cookie             []byte
	SessionID          []byte
	CipherSuiteIDs     []uint16
	CompressionMethods []*CompressionMethod
	Extensions         []Extension
}

const handshakeMessageClientHelloVariableWidthStart = 34

func (m MessageClientHello) HandshakeType() HandshakeType {
	return TypeClientHello
}

func (m *MessageClientHello) Marshal() ([]byte, error) {
	if len(m.Cookie) > 255 {
		return nil, errCookieTooLong
	}

	out := make([]byte, handshakeMessageClientHelloVariableWidthStart)
	out[0], out[1] = m.Version.Major, m.Version.Minor

	rand := m.Random.MarshalFixed()
	copy(out[2:], rand[:])

	out = append(out, byte(len(m.SessionID)))
	out = append(out, m.SessionID...)

	out = append(out, byte(len(m.Cookie)))
	out = append(out, m.Cookie...)
	out = append(out, encodeCipherSuiteIDs(m.CipherSuiteIDs)...)
	out = append(out, EncodeCompressionMethods(m.CompressionMethods)...)

	extensions, err := Marshal(m.Extensions)
	if err != nil {
		return nil, err
	}

	return append(out, extensions...), nil
}

func (m *MessageClientHello) Unmarshal(data []byte) error {
	if len(data) < 2+RandomLength {
		return errHsBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	currOffset := handshakeMessageClientHelloVariableWidthStart

	currOffset++
	if len(data) <= currOffset {
		return errHsBufferTooSmall
	}
	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errHsBufferTooSmall
	}
	m.SessionID = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.SessionID)

	currOffset++
	if len(data) <= currOffset {
		return errHsBufferTooSmall
	}
	n = int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errHsBufferTooSmall
	}
	m.Cookie = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.Cookie)

	if len(data) < currOffset {
		return errHsBufferTooSmall
	}
	cipherSuiteIDs, err := decodeCipherSuiteIDs(data[currOffset:])
	if err != nil {
		return err
	}
	m.CipherSuiteIDs = cipherSuiteIDs
	if len(data) < currOffset+2 {
		return errHsBufferTooSmall
	}
	currOffset += int(binary.BigEndian.Uint16(data[currOffset:])) + 2

	if len(data) < currOffset {
		return errHsBufferTooSmall
	}
	compressionMethods, err := DecodeCompressionMethods(data[currOffset:])
	if err != nil {
		return err
	}
	m.CompressionMethods = compressionMethods
	if len(data) < currOffset {
		return errHsBufferTooSmall
	}
	currOffset += int(data[currOffset]) + 1

	extensions, err := Unmarshal(data[currOffset:])
	if err != nil {
		return err
	}
	m.Extensions = extensions

	return nil
}

type MessageClientKeyExchange struct {
	IdentityHint         []byte
	PublicKey            []byte
	KeyExchangeAlgorithm KeyExchangeAlgorithm
}

func (m MessageClientKeyExchange) HandshakeType() HandshakeType {
	return TypeClientKeyExchange
}

func (m *MessageClientKeyExchange) Marshal() (out []byte, err error) {
	if m.IdentityHint == nil && m.PublicKey == nil {
		return nil, errInvalidClientKeyExchange
	}

	if m.IdentityHint != nil {
		out = append([]byte{0x00, 0x00}, m.IdentityHint...)
		binary.BigEndian.PutUint16(out, uint16(len(out)-2))
	}

	if m.PublicKey != nil {
		out = append(out, byte(len(m.PublicKey)))
		out = append(out, m.PublicKey...)
	}

	return out, nil
}

func (m *MessageClientKeyExchange) Unmarshal(data []byte) error {
	switch {
	case len(data) < 2:
		return errHsBufferTooSmall
	case m.KeyExchangeAlgorithm == KeyExchangeAlgorithmNone:
		return errCipherSuiteUnset
	}

	offset := 0
	if m.KeyExchangeAlgorithm.Has(KeyExchangeAlgorithmPsk) {
		pskLength := int(binary.BigEndian.Uint16(data))
		if pskLength > len(data)-2 {
			return errHsBufferTooSmall
		}

		m.IdentityHint = append([]byte{}, data[2:pskLength+2]...)
		offset += pskLength + 2
	}

	if m.KeyExchangeAlgorithm.Has(KeyExchangeAlgorithmEcdhe) {
		publicKeyLength := int(data[offset])
		if publicKeyLength > len(data)-1-offset {
			return errHsBufferTooSmall
		}

		m.PublicKey = append([]byte{}, data[offset+1:]...)
	}

	return nil
}

type MessageFinished struct {
	VerifyData []byte
}

func (m MessageFinished) HandshakeType() HandshakeType {
	return TypeFinished
}

func (m *MessageFinished) Marshal() ([]byte, error) {
	return append([]byte{}, m.VerifyData...), nil
}

func (m *MessageFinished) Unmarshal(data []byte) error {
	m.VerifyData = append([]byte{}, data...)

	return nil
}

type MessageHelloVerifyRequest struct {
	Version Version
	Cookie  []byte
}

func (m MessageHelloVerifyRequest) HandshakeType() HandshakeType {
	return TypeHelloVerifyRequest
}

func (m *MessageHelloVerifyRequest) Marshal() ([]byte, error) {
	if len(m.Cookie) > 255 {
		return nil, errCookieTooLong
	}

	out := make([]byte, 3+len(m.Cookie))
	out[0] = m.Version.Major
	out[1] = m.Version.Minor
	out[2] = byte(len(m.Cookie))
	copy(out[3:], m.Cookie)

	return out, nil
}

func (m *MessageHelloVerifyRequest) Unmarshal(data []byte) error {
	if len(data) < 3 {
		return errHsBufferTooSmall
	}
	m.Version.Major = data[0]
	m.Version.Minor = data[1]
	cookieLength := int(data[2])
	if len(data) < cookieLength+3 {
		return errHsBufferTooSmall
	}
	m.Cookie = make([]byte, cookieLength)

	copy(m.Cookie, data[3:3+cookieLength])

	return nil
}

type MessageServerHello struct {
	Version           Version
	Random            Random
	SessionID         []byte
	CipherSuiteID     *uint16
	CompressionMethod *CompressionMethod
	Extensions        []Extension
}

const messageServerHelloVariableWidthStart = 2 + RandomLength

func (m MessageServerHello) HandshakeType() HandshakeType {
	return TypeServerHello
}

func (m *MessageServerHello) Marshal() ([]byte, error) {
	if m.CipherSuiteID == nil {
		return nil, errCipherSuiteUnset
	} else if m.CompressionMethod == nil {
		return nil, errCompressionMethodUnset
	}

	out := make([]byte, messageServerHelloVariableWidthStart)
	out[0] = m.Version.Major
	out[1] = m.Version.Minor

	rand := m.Random.MarshalFixed()
	copy(out[2:], rand[:])

	out = append(out, byte(len(m.SessionID)))
	out = append(out, m.SessionID...)

	out = append(out, []byte{0x00, 0x00}...)
	binary.BigEndian.PutUint16(out[len(out)-2:], *m.CipherSuiteID)

	out = append(out, byte(m.CompressionMethod.ID))

	extensions, err := Marshal(m.Extensions)
	if err != nil {
		return nil, err
	}

	return append(out, extensions...), nil
}

func (m *MessageServerHello) Unmarshal(data []byte) error {
	if len(data) < 2+RandomLength {
		return errHsBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	currOffset := messageServerHelloVariableWidthStart
	currOffset++
	if len(data) <= currOffset {
		return errHsBufferTooSmall
	}

	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errHsBufferTooSmall
	}
	m.SessionID = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.SessionID)

	if len(data) < currOffset+2 {
		return errHsBufferTooSmall
	}
	m.CipherSuiteID = new(uint16)
	*m.CipherSuiteID = binary.BigEndian.Uint16(data[currOffset:])
	currOffset += 2

	if len(data) <= currOffset {
		return errHsBufferTooSmall
	}
	if compressionMethod, ok := CompressionMethods()[CompressionMethodID(data[currOffset])]; ok {
		m.CompressionMethod = compressionMethod
		currOffset++
	} else {
		return errInvalidCompressionMethod
	}

	if len(data) <= currOffset {
		m.Extensions = []Extension{}

		return nil
	}

	extensions, err := Unmarshal(data[currOffset:])
	if err != nil {
		return err
	}
	m.Extensions = extensions

	return nil
}

type MessageServerHelloDone struct{}

func (m MessageServerHelloDone) HandshakeType() HandshakeType {
	return TypeServerHelloDone
}

func (m *MessageServerHelloDone) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func (m *MessageServerHelloDone) Unmarshal([]byte) error {
	return nil
}

type MessageServerKeyExchange struct {
	IdentityHint         []byte
	EllipticCurveType    CurveType
	NamedCurve           Curve
	PublicKey            []byte
	HashAlgorithm        HashAlgorithm
	SignatureAlgorithm   SignatureAlgorithm
	Signature            []byte
	KeyExchangeAlgorithm KeyExchangeAlgorithm
}

func (m MessageServerKeyExchange) HandshakeType() HandshakeType {
	return TypeServerKeyExchange
}

func (m *MessageServerKeyExchange) Marshal() ([]byte, error) {
	var out []byte
	if m.IdentityHint != nil {
		out = append([]byte{0x00, 0x00}, m.IdentityHint...)
		binary.BigEndian.PutUint16(out, uint16(len(out)-2))
	}

	if m.EllipticCurveType == 0 || len(m.PublicKey) == 0 {
		return out, nil
	}
	out = append(out, byte(m.EllipticCurveType), 0x00, 0x00)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(m.NamedCurve))

	out = append(out, byte(len(m.PublicKey)))
	out = append(out, m.PublicKey...)
	switch {
	case m.HashAlgorithm != HashNone && len(m.Signature) == 0:
		return nil, errHsInvalidHashAlgorithm
	case m.HashAlgorithm == HashNone && len(m.Signature) > 0:
		return nil, errHsInvalidHashAlgorithm
	case m.SignatureAlgorithm == SignatureAnonymous && (m.HashAlgorithm != HashNone || len(m.Signature) > 0):
		return nil, errHsInvalidSignatureAlgorithm
	case m.SignatureAlgorithm == SignatureAnonymous:
		return out, nil
	}

	out = append(out, []byte{byte(m.HashAlgorithm), byte(m.SignatureAlgorithm), 0x00, 0x00}...)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(m.Signature)))
	out = append(out, m.Signature...)

	return out, nil
}

func (m *MessageServerKeyExchange) Unmarshal(data []byte) error {
	switch {
	case len(data) < 2:
		return errHsBufferTooSmall
	case m.KeyExchangeAlgorithm == KeyExchangeAlgorithmNone:
		return errCipherSuiteUnset
	}

	hintLength := binary.BigEndian.Uint16(data)
	if int(hintLength) <= len(data)-2 && m.KeyExchangeAlgorithm.Has(KeyExchangeAlgorithmPsk) {
		m.IdentityHint = append([]byte{}, data[2:2+hintLength]...)
		data = data[2+hintLength:]
	}
	if m.KeyExchangeAlgorithm == KeyExchangeAlgorithmPsk {
		if len(data) == 0 {
			return nil
		}

		return errHsLengthMismatch
	}

	if !m.KeyExchangeAlgorithm.Has(KeyExchangeAlgorithmEcdhe) {
		return errHsLengthMismatch
	}

	if _, ok := CurveTypes()[CurveType(data[0])]; ok {
		m.EllipticCurveType = CurveType(data[0])
	} else {
		return errInvalidEllipticCurveType
	}

	if len(data[1:]) < 2 {
		return errHsBufferTooSmall
	}
	m.NamedCurve = Curve(binary.BigEndian.Uint16(data[1:3]))
	if _, ok := Curves()[m.NamedCurve]; !ok {
		return errHsInvalidNamedCurve
	}
	if len(data) < 4 {
		return errHsBufferTooSmall
	}

	publicKeyLength := int(data[3])
	offset := 4 + publicKeyLength
	if len(data) < offset {
		return errHsBufferTooSmall
	}
	m.PublicKey = append([]byte{}, data[4:offset]...)

	if len(data) == offset {
		return nil
	} else if len(data) <= offset {
		return errHsBufferTooSmall
	}

	m.HashAlgorithm = HashAlgorithm(data[offset])
	if _, ok := HashAlgorithms()[m.HashAlgorithm]; !ok {
		return errHsInvalidHashAlgorithm
	}
	offset++
	if len(data) <= offset {
		return errHsBufferTooSmall
	}
	m.SignatureAlgorithm = SignatureAlgorithm(data[offset])
	if _, ok := SignatureAlgorithms()[m.SignatureAlgorithm]; !ok {
		return errHsInvalidSignatureAlgorithm
	}
	offset++
	if len(data) < offset+2 {
		return errHsBufferTooSmall
	}
	signatureLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+signatureLength {
		return errHsBufferTooSmall
	}
	m.Signature = append([]byte{}, data[offset:offset+signatureLength]...)

	return nil
}

const (
	RandomBytesLength = 28
	RandomLength      = RandomBytesLength + 4
)

type Random struct {
	GMTUnixTime time.Time
	RandomBytes [RandomBytesLength]byte
}

func (r *Random) MarshalFixed() [RandomLength]byte {
	var out [RandomLength]byte

	binary.BigEndian.PutUint32(out[0:], uint32(r.GMTUnixTime.Unix()))
	copy(out[4:], r.RandomBytes[:])

	return out
}

func (r *Random) UnmarshalFixed(data [RandomLength]byte) {
	r.GMTUnixTime = time.Unix(int64(binary.BigEndian.Uint32(data[0:])), 0)
	copy(r.RandomBytes[:], data[4:])
}

func (r *Random) Populate() error {
	r.GMTUnixTime = time.Now()

	tmp := make([]byte, RandomBytesLength)
	_, err := rand.Read(tmp)
	copy(r.RandomBytes[:], tmp)

	return err
}

// ===================== merged from pkg/protocol/recordlayer/recordlayer.go =====================
var (
	ErrInvalidPacketLength = &TemporaryError{
		Err: errors.New("packet length and declared length do not match"),
	}

	errRlBufferTooSmall             = &TemporaryError{Err: errors.New("buffer is too small")}
	errRlSequenceNumberOverflow     = &InternalError{Err: errors.New("sequence number overflow")}
	errRlUnsupportedProtocolVersion = &FatalError{Err: errors.New("unsupported protocol version")}
	errRlInvalidContentType         = &TemporaryError{Err: errors.New("invalid content type")}
)

const (
	FixedHeaderSize   = 13
	MaxSequenceNumber = 0x0000FFFFFFFFFFFF

	fixedHeaderLenIdx = 11
)

type RecordLayerHeader struct {
	ContentType    ContentType
	ContentLen     uint16
	Version        Version
	Epoch          uint16
	SequenceNumber uint64
	ConnectionID   []byte
}

func (h *RecordLayerHeader) Marshal() ([]byte, error) {
	if h.SequenceNumber > MaxSequenceNumber {
		return nil, errRlSequenceNumberOverflow
	}

	hs := FixedHeaderSize + len(h.ConnectionID)

	out := make([]byte, hs)
	out[0] = byte(h.ContentType)
	out[1] = h.Version.Major
	out[2] = h.Version.Minor
	binary.BigEndian.PutUint16(out[3:], h.Epoch)
	webrtc.PutBEUint48(out[5:], h.SequenceNumber)
	copy(out[11:11+len(h.ConnectionID)], h.ConnectionID)
	binary.BigEndian.PutUint16(out[hs-2:], h.ContentLen)

	return out, nil
}

func (h *RecordLayerHeader) Unmarshal(data []byte) error {
	if len(data) < FixedHeaderSize {
		return errRlBufferTooSmall
	}
	h.ContentType = ContentType(data[0])
	if h.ContentType == ContentTypeConnectionID {

		if len(data) < FixedHeaderSize+len(h.ConnectionID) {
			return errRlBufferTooSmall
		}
		h.ConnectionID = data[11 : 11+len(h.ConnectionID)]
	}

	h.Version.Major = data[1]
	h.Version.Minor = data[2]
	h.Epoch = binary.BigEndian.Uint16(data[3:])

	seqCopy := make([]byte, 8)
	copy(seqCopy[2:], data[5:11])
	h.SequenceNumber = binary.BigEndian.Uint64(seqCopy)

	if !h.Version.Equal(Version1_0) && !h.Version.Equal(Version1_2) {
		return errRlUnsupportedProtocolVersion
	}

	return nil
}

func (h *RecordLayerHeader) Size() int {
	return FixedHeaderSize + len(h.ConnectionID)
}

type InnerPlaintext struct {
	Content  []byte
	RealType ContentType
	Zeros    uint
}

func (p *InnerPlaintext) Marshal() ([]byte, error) {
	var out cryptobyte.Builder
	out.AddBytes(p.Content)
	out.AddUint8(uint8(p.RealType))
	out.AddBytes(make([]byte, p.Zeros))

	return out.Bytes()
}

func (p *InnerPlaintext) Unmarshal(data []byte) error {

	i := len(data) - 1
	for i >= 0 {
		if data[i] != 0 {
			p.Zeros = uint(len(data) - 1 - i)

			break
		}
		i--
	}
	if i == 0 {
		return errRlBufferTooSmall
	}
	p.RealType = ContentType(data[i])
	p.Content = append([]byte{}, data[:i]...)

	return nil
}

type RecordLayer struct {
	Header  RecordLayerHeader
	Content Content
}

func (r *RecordLayer) Marshal() ([]byte, error) {
	contentRaw, err := r.Content.Marshal()
	if err != nil {
		return nil, err
	}

	r.Header.ContentLen = uint16(len(contentRaw))
	r.Header.ContentType = r.Content.ContentType()

	headerRaw, err := r.Header.Marshal()
	if err != nil {
		return nil, err
	}

	return append(headerRaw, contentRaw...), nil
}

func (r *RecordLayer) Unmarshal(data []byte) error {
	if err := r.Header.Unmarshal(data); err != nil {
		return err
	}

	switch r.Header.ContentType {
	case ContentTypeChangeCipherSpec:
		r.Content = &ChangeCipherSpec{}
	case ContentTypeAlert:
		r.Content = &Alert{}
	case ContentTypeHandshake:
		r.Content = &Handshake{}
	case ContentTypeApplicationData:
		r.Content = &ApplicationData{}
	default:
		return errRlInvalidContentType
	}

	return r.Content.Unmarshal(data[r.Header.Size()+len(r.Header.ConnectionID):])
}

func ContentAwareUnpackDatagram(buf []byte, cidLength int) ([][]byte, error) {
	out := [][]byte{}

	for offset := 0; len(buf) != offset; {
		headerSize := FixedHeaderSize
		lenIdx := fixedHeaderLenIdx
		if ContentType(buf[offset]) == ContentTypeConnectionID {
			headerSize += cidLength
			lenIdx += cidLength
		}
		if len(buf)-offset <= headerSize {
			return nil, ErrInvalidPacketLength
		}

		pktLen := (headerSize + int(binary.BigEndian.Uint16(buf[offset+lenIdx:])))
		if offset+pktLen > len(buf) {
			return nil, ErrInvalidPacketLength
		}

		out = append(out, buf[offset:offset+pktLen])
		offset += pktLen
	}

	return out, nil
}

// ===================== merged from internal/ciphersuite/ciphersuite.go =====================
var errCipherSuiteNotInit = &TemporaryError{Err: errors.New("CipherSuite has not been initialized")}

type ID uint16

func (i ID) String() string {
	switch i {
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	default:
		return fmt.Sprintf("unknown(%v)", uint16(i))
	}
}

const (
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM   ID = 0xc0ac
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 ID = 0xc0ae

	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ID = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   ID = 0xc02f

	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ID = 0xc02c
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   ID = 0xc030

	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA ID = 0xc00a
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   ID = 0xc014
)

type AesCcm struct {
	ccm                   atomic.Value
	clientCertificateType ClientCertificateType
	id                    ID
	psk                   bool
	keyExchangeAlgorithm  KeyExchangeAlgorithm
	cryptoCCMTagLen       CCMTagLen
	ecc                   bool
}

func (c *AesCcm) CertificateType() ClientCertificateType {
	return c.clientCertificateType
}

func (c *AesCcm) ID() ID {
	return c.id
}

func (c *AesCcm) String() string {
	return c.id.String()
}

func (c *AesCcm) ECC() bool {
	return c.ecc
}

func (c *AesCcm) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return c.keyExchangeAlgorithm
}

func (c *AesCcm) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *AesCcm) AuthenticationType() AuthenticationType {
	if c.psk {
		return AuthenticationTypePreSharedKey
	}

	return AuthenticationTypeCertificate
}

func (c *AesCcm) IsInitialized() bool {
	return c.ccm.Load() != nil
}

func (c *AesCcm) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool, prfKeyLen int) error {
	const (
		prfMacLen = 0
		prfIvLen  = 4
	)

	keys, err := GenerateEncryptionKeys(
		masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc(),
	)
	if err != nil {
		return err
	}

	var ccm *cipherSuiteCCM
	if isClient {
		ccm, err = newCipherSuiteCCM(
			c.cryptoCCMTagLen, keys.ClientWriteKey, keys.ClientWriteIV, keys.ServerWriteKey, keys.ServerWriteIV,
		)
	} else {
		ccm, err = newCipherSuiteCCM(
			c.cryptoCCMTagLen, keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV,
		)
	}
	c.ccm.Store(ccm)

	return err
}

func (c *AesCcm) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.ccm.Load().(*cipherSuiteCCM)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Encrypt(pkt, raw)
}

func (c *AesCcm) Decrypt(h RecordLayerHeader, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.ccm.Load().(*cipherSuiteCCM)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Decrypt(h, raw)
}

type Aes128Ccm struct {
	AesCcm
}

func newAes128Ccm(
	clientCertificateType ClientCertificateType,
	id ID,
	psk bool,
	cryptoCCMTagLen CCMTagLen,
	keyExchangeAlgorithm KeyExchangeAlgorithm,
	ecc bool,
) *Aes128Ccm {
	return &Aes128Ccm{
		AesCcm: AesCcm{
			clientCertificateType: clientCertificateType,
			id:                    id,
			psk:                   psk,
			cryptoCCMTagLen:       cryptoCCMTagLen,
			keyExchangeAlgorithm:  keyExchangeAlgorithm,
			ecc:                   ecc,
		},
	}
}

func (c *Aes128Ccm) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const prfKeyLen = 16

	return c.AesCcm.Init(masterSecret, clientRandom, serverRandom, isClient, prfKeyLen)
}

func NewTLSEcdheEcdsaWithAes128Ccm() *Aes128Ccm {
	return newAes128Ccm(
		ECDSASign,
		TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		false,
		CCMTagLength,
		KeyExchangeAlgorithmEcdhe,
		true,
	)
}

func NewTLSEcdheEcdsaWithAes128Ccm8() *Aes128Ccm {
	return newAes128Ccm(
		ECDSASign,
		TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		false,
		CCMTagLength8,
		KeyExchangeAlgorithmEcdhe,
		true,
	)
}

type TLSEcdheEcdsaWithAes128GcmSha256 struct {
	gcm atomic.Value
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) CertificateType() ClientCertificateType {
	return ECDSASign
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmEcdhe
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) ECC() bool {
	return true
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) ID() ID {
	return TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) String() string {
	return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) AuthenticationType() AuthenticationType {
	return AuthenticationTypeCertificate
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) IsInitialized() bool {
	return c.gcm.Load() != nil
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) init(
	masterSecret, clientRandom, serverRandom []byte,
	isClient bool,
	prfMacLen, prfKeyLen, prfIvLen int,
	hashFunc func() hash.Hash,
) error {
	keys, err := GenerateEncryptionKeys(
		masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, hashFunc,
	)
	if err != nil {
		return err
	}

	var gcm *GCM
	if isClient {
		gcm, err = NewGCM(keys.ClientWriteKey, keys.ClientWriteIV, keys.ServerWriteKey, keys.ServerWriteIV)
	} else {
		gcm, err = NewGCM(keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV)
	}
	c.gcm.Store(gcm)

	return err
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 0
		prfKeyLen = 16
		prfIvLen  = 4
	)

	return c.init(masterSecret, clientRandom, serverRandom, isClient, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc())
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.gcm.Load().(*GCM)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Encrypt(pkt, raw)
}

func (c *TLSEcdheEcdsaWithAes128GcmSha256) Decrypt(h RecordLayerHeader, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.gcm.Load().(*GCM)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Decrypt(h, raw)
}

type TLSEcdheEcdsaWithAes256CbcSha struct {
	cbc atomic.Value
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) CertificateType() ClientCertificateType {
	return ECDSASign
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmEcdhe
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) ECC() bool {
	return true
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) ID() ID {
	return TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) String() string {
	return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) HashFunc() func() hash.Hash {
	return sha256.New
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) AuthenticationType() AuthenticationType {
	return AuthenticationTypeCertificate
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) IsInitialized() bool {
	return c.cbc.Load() != nil
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 20
		prfKeyLen = 32
		prfIvLen  = 16
	)

	keys, err := GenerateEncryptionKeys(
		masterSecret, clientRandom, serverRandom, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc(),
	)
	if err != nil {
		return err
	}

	var cbc *CBC
	if isClient {
		cbc, err = NewCBC(
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			sha1.New,
		)
	} else {
		cbc, err = NewCBC(
			keys.ServerWriteKey, keys.ServerWriteIV, keys.ServerMACKey,
			keys.ClientWriteKey, keys.ClientWriteIV, keys.ClientMACKey,
			sha1.New,
		)
	}
	c.cbc.Store(cbc)

	return err
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.cbc.Load().(*CBC)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Encrypt(pkt, raw)
}

func (c *TLSEcdheEcdsaWithAes256CbcSha) Decrypt(h RecordLayerHeader, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.cbc.Load().(*CBC)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Decrypt(h, raw)
}

type TLSEcdheEcdsaWithAes256GcmSha384 struct {
	TLSEcdheEcdsaWithAes128GcmSha256
}

func (c *TLSEcdheEcdsaWithAes256GcmSha384) ID() ID {
	return TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
}

func (c *TLSEcdheEcdsaWithAes256GcmSha384) String() string {
	return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
}

func (c *TLSEcdheEcdsaWithAes256GcmSha384) HashFunc() func() hash.Hash {
	return sha512.New384
}

func (c *TLSEcdheEcdsaWithAes256GcmSha384) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const (
		prfMacLen = 0
		prfKeyLen = 32
		prfIvLen  = 4
	)

	return c.init(masterSecret, clientRandom, serverRandom, isClient, prfMacLen, prfKeyLen, prfIvLen, c.HashFunc())
}

type TLSEcdheRsaWithAes128GcmSha256 struct {
	TLSEcdheEcdsaWithAes128GcmSha256
}

func (c *TLSEcdheRsaWithAes128GcmSha256) CertificateType() ClientCertificateType {
	return RSASign
}

func (c *TLSEcdheRsaWithAes128GcmSha256) ID() ID {
	return TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
}

func (c *TLSEcdheRsaWithAes128GcmSha256) String() string {
	return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
}

type TLSEcdheRsaWithAes256CbcSha struct {
	TLSEcdheEcdsaWithAes256CbcSha
}

func (c *TLSEcdheRsaWithAes256CbcSha) CertificateType() ClientCertificateType {
	return RSASign
}

func (c *TLSEcdheRsaWithAes256CbcSha) ID() ID {
	return TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
}

func (c *TLSEcdheRsaWithAes256CbcSha) String() string {
	return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
}

type TLSEcdheRsaWithAes256GcmSha384 struct {
	TLSEcdheEcdsaWithAes256GcmSha384
}

func (c *TLSEcdheRsaWithAes256GcmSha384) CertificateType() ClientCertificateType {
	return RSASign
}

func (c *TLSEcdheRsaWithAes256GcmSha384) ID() ID {
	return TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
}

func (c *TLSEcdheRsaWithAes256GcmSha384) String() string {
	return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
}

// ===================== merged from pkg/crypto/ciphersuite/ciphersuite.go =====================
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type CBC struct {
	writeCBC, readCBC cbcMode
	writeMac, readMac []byte
	h                 HashFunc
}

func NewCBC(
	localKey, localWriteIV, localMac, remoteKey, remoteWriteIV, remoteMac []byte,
	hashFunc HashFunc,
) (*CBC, error) {
	writeBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}

	readBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}

	writeCBC, ok := cipher.NewCBCEncrypter(writeBlock, localWriteIV).(cbcMode)
	if !ok {
		return nil, errFailedToCast
	}

	readCBC, ok := cipher.NewCBCDecrypter(readBlock, remoteWriteIV).(cbcMode)
	if !ok {
		return nil, errFailedToCast
	}

	return &CBC{
		writeCBC: writeCBC,
		writeMac: localMac,

		readCBC: readCBC,
		readMac: remoteMac,
		h:       hashFunc,
	}, nil
}

func (c *CBC) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	payload := raw[pkt.Header.Size():]
	raw = raw[:pkt.Header.Size()]
	blockSize := c.writeCBC.BlockSize()

	h := pkt.Header

	var err error
	var mac []byte
	if h.ContentType == ContentTypeConnectionID {
		mac, err = c.hmacCID(h.Epoch, h.SequenceNumber, h.Version, payload, c.writeMac, c.h, h.ConnectionID)
	} else {
		mac, err = c.hmac(h.Epoch, h.SequenceNumber, h.ContentType, h.Version, payload, c.writeMac, c.h)
	}
	if err != nil {
		return nil, err
	}
	payload = append(payload, mac...)

	padding := make([]byte, blockSize-len(payload)%blockSize)
	paddingLen := len(padding)
	for i := 0; i < paddingLen; i++ {
		padding[i] = byte(paddingLen - 1)
	}
	payload = append(payload, padding...)

	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	c.writeCBC.SetIV(iv)
	c.writeCBC.CryptBlocks(payload, payload)
	payload = append(iv, payload...)

	raw = append(raw, payload...)

	binary.BigEndian.PutUint16(raw[pkt.Header.Size()-2:], uint16(len(raw)-pkt.Header.Size()))

	return raw, nil
}

func (c *CBC) Decrypt(header RecordLayerHeader, in []byte) ([]byte, error) {
	blockSize := c.readCBC.BlockSize()
	mac := c.h()

	if err := header.Unmarshal(in); err != nil {
		return nil, err
	}
	body := in[header.Size():]

	switch {
	case header.ContentType == ContentTypeChangeCipherSpec:

		return in, nil
	case len(body)%blockSize != 0 || len(body) < blockSize+webrtc.MaxInt(mac.Size()+1, blockSize):
		return nil, errNotEnoughRoomForNonce
	}

	c.readCBC.SetIV(body[:blockSize])
	body = body[blockSize:]

	c.readCBC.CryptBlocks(body, body)

	paddingLen, paddingGood := examinePadding(body)
	if paddingGood != 255 {
		return nil, errInvalidMAC
	}

	macSize := mac.Size()
	if len(body) < macSize {
		return nil, errInvalidMAC
	}

	dataEnd := len(body) - macSize - paddingLen

	expectedMAC := body[dataEnd : dataEnd+macSize]
	var err error
	var actualMAC []byte
	if header.ContentType == ContentTypeConnectionID {
		actualMAC, err = c.hmacCID(
			header.Epoch, header.SequenceNumber, header.Version, body[:dataEnd], c.readMac, c.h, header.ConnectionID,
		)
	} else {
		actualMAC, err = c.hmac(
			header.Epoch, header.SequenceNumber, header.ContentType, header.Version, body[:dataEnd], c.readMac, c.h,
		)
	}

	if err != nil || !hmac.Equal(actualMAC, expectedMAC) {
		return nil, errInvalidMAC
	}

	return append(in[:header.Size()], body[:dataEnd]...), nil
}

func (c *CBC) hmac(
	epoch uint16,
	sequenceNumber uint64,
	contentType ContentType,
	protocolVersion Version,
	payload []byte,
	key []byte,
	hf func() hash.Hash,
) ([]byte, error) {
	hmacHash := hmac.New(hf, key)

	msg := make([]byte, 13)

	binary.BigEndian.PutUint16(msg, epoch)
	webrtc.PutBEUint48(msg[2:], sequenceNumber)
	msg[8] = byte(contentType)
	msg[9] = protocolVersion.Major
	msg[10] = protocolVersion.Minor
	binary.BigEndian.PutUint16(msg[11:], uint16(len(payload)))

	if _, err := hmacHash.Write(msg); err != nil {
		return nil, err
	}
	if _, err := hmacHash.Write(payload); err != nil {
		return nil, err
	}

	return hmacHash.Sum(nil), nil
}

func (c *CBC) hmacCID(
	epoch uint16,
	sequenceNumber uint64,
	protocolVersion Version,
	payload []byte,
	key []byte,
	hf func() hash.Hash,
	cid []byte,
) ([]byte, error) {

	ip := &InnerPlaintext{}
	if err := ip.Unmarshal(payload); err != nil {
		return nil, err
	}

	hmacHash := hmac.New(hf, key)

	var msg cryptobyte.Builder

	msg.AddUint64(seqNumPlaceholder)
	msg.AddUint8(uint8(ContentTypeConnectionID))
	msg.AddUint8(uint8(len(cid)))
	msg.AddUint8(uint8(ContentTypeConnectionID))
	msg.AddUint8(protocolVersion.Major)
	msg.AddUint8(protocolVersion.Minor)
	msg.AddUint16(epoch)
	webrtc.AddUint48(&msg, sequenceNumber)
	msg.AddBytes(cid)
	msg.AddUint16(uint16(len(payload)))
	msg.AddBytes(ip.Content)
	msg.AddUint8(uint8(ip.RealType))
	msg.AddBytes(make([]byte, ip.Zeros))

	if _, err := hmacHash.Write(msg.BytesOrPanic()); err != nil {
		return nil, err
	}
	if _, err := hmacHash.Write(payload); err != nil {
		return nil, err
	}

	return hmacHash.Sum(nil), nil
}

type CCMTagLen int

const (
	CCMTagLength8  CCMTagLen = 8
	CCMTagLength   CCMTagLen = 16
	ccmNonceLength           = 12
)

type cipherSuiteCCM struct {
	aead *aead
}

func newCipherSuiteCCM(tagLen CCMTagLen, localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*cipherSuiteCCM, error) {
	localBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}
	localCCM, err := NewCCM(localBlock, int(tagLen), ccmNonceLength)
	if err != nil {
		return nil, err
	}

	remoteBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}
	remoteCCM, err := NewCCM(remoteBlock, int(tagLen), ccmNonceLength)
	if err != nil {
		return nil, err
	}

	return &cipherSuiteCCM{
		aead: newAEAD(
			localCCM,
			localWriteIV,
			remoteCCM,
			remoteWriteIV,
			ccmNonceLength,
			int(tagLen),
		),
	}, nil
}

func (c *cipherSuiteCCM) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	return c.aead.encrypt(pkt, raw)
}

func (c *cipherSuiteCCM) Decrypt(header RecordLayerHeader, in []byte) ([]byte, error) {
	return c.aead.decrypt(header, in)
}

const (
	seqNumPlaceholder = 0xffffffffffffffff
)

var (
	errNotEnoughRoomForNonce = &InternalError{Err: errors.New("buffer not long enough to contain nonce")}

	errDecryptPacket = &TemporaryError{Err: errors.New("failed to decrypt packet")}

	errInvalidMAC = &TemporaryError{Err: errors.New("invalid mac")}

	errFailedToCast = &FatalError{Err: errors.New("failed to cast")}
)

type aead struct {
	localAEAD       cipher.AEAD
	remoteAEAD      cipher.AEAD
	localWriteIV    []byte
	remoteWriteIV   []byte
	nonceLength     int
	tagLength       int
	nonceBufferPool sync.Pool
}

func newAEAD(
	localAEAD cipher.AEAD,
	localWriteIV []byte,
	remoteAEAD cipher.AEAD,
	remoteWriteIV []byte,
	nonceLength int,
	tagLength int,
) *aead {
	return &aead{
		localAEAD:     localAEAD,
		localWriteIV:  localWriteIV,
		remoteAEAD:    remoteAEAD,
		remoteWriteIV: remoteWriteIV,
		nonceLength:   nonceLength,
		tagLength:     tagLength,
		nonceBufferPool: sync.Pool{
			New: func() any {
				b := make([]byte, nonceLength)
				return &b
			},
		},
	}
}

func (a *aead) encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	payload := raw[pkt.Header.Size():]
	raw = raw[:pkt.Header.Size()]

	noncePtr := a.nonceBufferPool.Get().(*[]byte)
	nonce := *noncePtr

	copy(nonce, a.localWriteIV[:4])

	seq64 := (uint64(pkt.Header.Epoch) << 48) | (pkt.Header.SequenceNumber & 0x0000ffffffffffff)
	binary.BigEndian.PutUint64(nonce[4:], seq64)

	var additionalData []byte
	if pkt.Header.ContentType == ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&pkt.Header, len(payload))
	} else {
		additionalData = generateAEADAdditionalData(&pkt.Header, len(payload))
	}
	finalSize := len(raw) + 8 + len(payload) + a.tagLength
	r := make([]byte, finalSize)
	copy(r, raw)
	copy(r[len(raw):], nonce[4:])

	a.localAEAD.Seal(r[len(raw)+8:len(raw)+8], nonce, payload, additionalData)

	binary.BigEndian.PutUint16(r[pkt.Header.Size()-2:], uint16(len(r)-pkt.Header.Size()))

	a.nonceBufferPool.Put(noncePtr)

	return r, nil
}

func (a *aead) decrypt(header RecordLayerHeader, in []byte) ([]byte, error) {
	err := header.Unmarshal(in)
	switch {
	case err != nil:
		return nil, err
	case header.ContentType == ContentTypeChangeCipherSpec:

		return in, nil
	case len(in) <= (8 + header.Size()):
		return nil, errNotEnoughRoomForNonce
	}

	noncePtr := a.nonceBufferPool.Get().(*[]byte)
	nonce := *noncePtr

	copy(nonce[:4], a.remoteWriteIV[:4])
	copy(nonce[4:], in[header.Size():header.Size()+8])
	out := in[header.Size()+8:]

	var additionalData []byte
	if header.ContentType == ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&header, len(out)-a.tagLength)
	} else {
		additionalData = generateAEADAdditionalData(&header, len(out)-a.tagLength)
	}
	out, err = a.remoteAEAD.Open(out[:0], nonce, out, additionalData)
	if err != nil {

		a.nonceBufferPool.Put(noncePtr)

		return nil, fmt.Errorf("%w: %v", errDecryptPacket, err)
	}

	a.nonceBufferPool.Put(noncePtr)

	return append(in[:header.Size()], out...), nil
}

func generateAEADAdditionalData(h *RecordLayerHeader, payloadLen int) []byte {
	var additionalData [13]byte

	binary.BigEndian.PutUint64(additionalData[:], h.SequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], h.Epoch)
	additionalData[8] = byte(h.ContentType)
	additionalData[9] = h.Version.Major
	additionalData[10] = h.Version.Minor

	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))

	return additionalData[:]
}

func generateAEADAdditionalDataCID(h *RecordLayerHeader, payloadLen int) []byte {
	var builder cryptobyte.Builder

	builder.AddUint64(seqNumPlaceholder)
	builder.AddUint8(uint8(ContentTypeConnectionID))
	builder.AddUint8(uint8(len(h.ConnectionID)))
	builder.AddUint8(uint8(ContentTypeConnectionID))
	builder.AddUint8(h.Version.Major)
	builder.AddUint8(h.Version.Minor)
	builder.AddUint16(h.Epoch)
	webrtc.AddUint48(&builder, h.SequenceNumber)
	builder.AddBytes(h.ConnectionID)
	builder.AddUint16(uint16(payloadLen))

	return builder.BytesOrPanic()
}

func examinePadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)

	good = byte(int32(^t) >> 31)

	toCheck := min(

		256, len(payload))

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)

		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	toRemove = int(paddingLen) + 1

	return toRemove, good
}

const (
	gcmTagLength   = 16
	gcmNonceLength = 12
)

type GCM struct {
	aead *aead
}

func NewGCM(localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*GCM, error) {
	localBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}
	localGCM, err := cipher.NewGCM(localBlock)
	if err != nil {
		return nil, err
	}

	remoteBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}
	remoteGCM, err := cipher.NewGCM(remoteBlock)
	if err != nil {
		return nil, err
	}

	return &GCM{
		aead: newAEAD(
			localGCM,
			localWriteIV,
			remoteGCM,
			remoteWriteIV,
			gcmNonceLength,
			gcmTagLength,
		),
	}, nil
}

func (g *GCM) Encrypt(pkt *RecordLayer, raw []byte) ([]byte, error) {
	return g.aead.encrypt(pkt, raw)
}

func (g *GCM) Decrypt(header RecordLayerHeader, in []byte) ([]byte, error) {
	return g.aead.decrypt(header, in)
}
