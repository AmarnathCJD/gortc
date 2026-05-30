package webrtc

import (
	"container/list"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	wutil "github.com/amarnathcjd/gortc/webrtc"
	"github.com/amarnathcjd/gortc/webrtc/dtls"
	"github.com/amarnathcjd/gortc/webrtc/ice"
	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/interceptor/pkg/nack"
	"github.com/amarnathcjd/gortc/webrtc/interceptor/pkg/report"
	"github.com/amarnathcjd/gortc/webrtc/interceptor/pkg/stats"
	"github.com/amarnathcjd/gortc/webrtc/interceptor/pkg/twcc"
	"github.com/amarnathcjd/gortc/webrtc/logging"
	"github.com/amarnathcjd/gortc/webrtc/rtcp"
	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"github.com/amarnathcjd/gortc/webrtc/rtp/codecs"
	"github.com/amarnathcjd/gortc/webrtc/sdp"
	"github.com/amarnathcjd/gortc/webrtc/srtp"
	"github.com/amarnathcjd/gortc/webrtc/stun"
	"github.com/amarnathcjd/gortc/webrtc/transport"
	"math"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

type API struct {
	settingEngine       *SettingEngine
	mediaEngine         *MediaEngine
	interceptorRegistry *interceptor.Registry
	interceptor         interceptor.Interceptor
}

func NewAPI(options ...func(*API)) *API {
	api := &API{
		interceptor:   &interceptor.NoOp{},
		settingEngine: &SettingEngine{},
	}

	for _, o := range options {
		o(api)
	}

	if api.settingEngine.LoggerFactory == nil {
		api.settingEngine.LoggerFactory = logging.NewDefaultLoggerFactory()
	}

	logger := api.settingEngine.LoggerFactory.NewLogger("api")

	if api.mediaEngine == nil {
		api.mediaEngine = &MediaEngine{}
		err := api.mediaEngine.RegisterDefaultCodecs()
		if err != nil {
			logger.Errorf("Failed to register default codecs %s", err)
		}
	}

	if api.interceptorRegistry == nil {
		api.interceptorRegistry = &interceptor.Registry{}
		err := RegisterDefaultInterceptorsWithOptions(api.mediaEngine, api.interceptorRegistry,
			WithInterceptorLoggerFactory(api.settingEngine.LoggerFactory))
		if err != nil {
			logger.Errorf("Failed to register default interceptors %s", err)
		}
	}

	return api
}

func WithMediaEngine(m *MediaEngine) func(a *API) {
	return func(a *API) {
		a.mediaEngine = m
		if a.mediaEngine == nil {
			a.mediaEngine = &MediaEngine{}
		}
	}
}

func WithSettingEngine(s SettingEngine) func(a *API) {
	return func(a *API) {
		a.settingEngine = &s
	}
}

func WithInterceptorRegistry(ir *interceptor.Registry) func(a *API) {
	return func(a *API) {
		a.interceptorRegistry = ir
		if a.interceptorRegistry == nil {
			a.interceptorRegistry = &interceptor.Registry{}
		}
	}
}

type Configuration struct {
	ICEServers                  []ICEServer        `json:"iceServers,omitempty"`
	ICETransportPolicy          ICETransportPolicy `json:"iceTransportPolicy,omitempty"`
	BundlePolicy                BundlePolicy       `json:"bundlePolicy,omitempty"`
	RTCPMuxPolicy               RTCPMuxPolicy      `json:"rtcpMuxPolicy,omitempty"`
	PeerIdentity                string             `json:"peerIdentity,omitempty"`
	Certificates                []Certificate      `json:"certificates,omitempty"`
	ICECandidatePoolSize        uint8              `json:"iceCandidatePoolSize,omitempty"`
	SDPSemantics                SDPSemantics       `json:"sdpSemantics,omitempty"`
	AlwaysNegotiateDataChannels bool               `json:"alwaysNegotiateDataChannels,omitempty"`
}

type DataChannel struct {
	mu                         sync.RWMutex
	statsID                    string
	label                      string
	ordered                    bool
	maxPacketLifeTime          *uint16
	maxRetransmits             *uint16
	protocol                   string
	negotiated                 bool
	id                         *uint16
	readyState                 atomic.Value
	bufferedAmountLowThreshold uint64
	onMessageHandler           func(DataChannelMessage)
	onOpenHandler              func()
	onDialHandler              func()
	onCloseHandler             func()
	onBufferedAmountLow        func()
	onErrorHandler             func(error)
	sctpTransport              *SCTPTransport
	api                        *API
	log                        logging.LeveledLogger
}

func (api *API) NewDataChannel(_ *SCTPTransport, _ *DataChannelParameters) (*DataChannel, error) {
	return nil, errSCTPDisabled
}

func (api *API) newDataChannel(
	params *DataChannelParameters,
	sctpTransport *SCTPTransport,
	log logging.LeveledLogger,
) (*DataChannel, error) {
	if len(params.Label) > 65535 {
		return nil, &TypeError{Err: ErrStringSizeLimit}
	}
	d := &DataChannel{
		sctpTransport:     sctpTransport,
		statsID:           fmt.Sprintf("DataChannel-%d", time.Now().UnixNano()),
		label:             params.Label,
		protocol:          params.Protocol,
		negotiated:        params.Negotiated,
		id:                params.ID,
		ordered:           params.Ordered,
		maxPacketLifeTime: params.MaxPacketLifeTime,
		maxRetransmits:    params.MaxRetransmits,
		api:               api,
		log:               log,
	}
	d.setReadyState(DataChannelStateConnecting)
	return d, nil
}

func (d *DataChannel) open(_ *SCTPTransport) error { return errSCTPDisabled }

func (d *DataChannel) Transport() *SCTPTransport { return d.sctpTransport }

func (d *DataChannel) OnOpen(f func()) {
	d.mu.Lock()
	d.onOpenHandler = f
	d.mu.Unlock()
}

func (d *DataChannel) OnDial(f func()) {
	d.mu.Lock()
	d.onDialHandler = f
	d.mu.Unlock()
}

func (d *DataChannel) OnClose(f func()) {
	d.mu.Lock()
	d.onCloseHandler = f
	d.mu.Unlock()
}

func (d *DataChannel) OnMessage(f func(msg DataChannelMessage)) {
	d.mu.Lock()
	d.onMessageHandler = f
	d.mu.Unlock()
}

func (d *DataChannel) OnError(f func(err error)) {
	d.mu.Lock()
	d.onErrorHandler = f
	d.mu.Unlock()
}

func (d *DataChannel) Send(_ []byte) error { return errSCTPDisabled }

func (d *DataChannel) SendText(_ string) error { return errSCTPDisabled }

func (d *DataChannel) Detach() (io.ReadWriteCloser, error) {
	return nil, errSCTPDisabled
}

func (d *DataChannel) DetachWithDeadline() (io.ReadWriteCloser, error) {
	return nil, errSCTPDisabled
}

func (d *DataChannel) Close() error { return nil }

func (d *DataChannel) GracefulClose() error { return nil }

func (d *DataChannel) Label() string { return d.label }

func (d *DataChannel) Ordered() bool { return d.ordered }

func (d *DataChannel) MaxPacketLifeTime() *uint16 { return d.maxPacketLifeTime }

func (d *DataChannel) MaxRetransmits() *uint16 { return d.maxRetransmits }

func (d *DataChannel) Protocol() string { return d.protocol }

func (d *DataChannel) Negotiated() bool { return d.negotiated }

func (d *DataChannel) ID() *uint16 { return d.id }

func (d *DataChannel) ReadyState() DataChannelState {
	if v := d.readyState.Load(); v != nil {
		return v.(DataChannelState)
	}
	return DataChannelStateConnecting
}

func (d *DataChannel) BufferedAmount() uint64 { return 0 }

func (d *DataChannel) BufferedAmountLowThreshold() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.bufferedAmountLowThreshold
}

func (d *DataChannel) SetBufferedAmountLowThreshold(th uint64) {
	d.mu.Lock()
	d.bufferedAmountLowThreshold = th
	d.mu.Unlock()
}

func (d *DataChannel) OnBufferedAmountLow(f func()) {
	d.mu.Lock()
	d.onBufferedAmountLow = f
	d.mu.Unlock()
}

func (d *DataChannel) getStatsID() string { return d.statsID }

func (d *DataChannel) collectStats(_ *statsReportCollector) {}

func (d *DataChannel) setReadyState(r DataChannelState) { d.readyState.Store(r) }

type DTLSTransport struct {
	lock                        sync.RWMutex
	iceTransport                *ICETransport
	certificates                []Certificate
	remoteParameters            DTLSParameters
	remoteCertificate           []byte
	state                       DTLSTransportState
	srtpProtectionProfile       srtp.ProtectionProfile
	onStateChangeHandler        func(DTLSTransportState)
	internalOnCloseHandler      func()
	conn                        *dtls.Conn
	srtpSession, srtcpSession   atomic.Value
	srtpEndpoint, srtcpEndpoint *Endpoint
	simulcastStreams            []simulcastStreamPair
	srtpReady                   chan struct{}
	dtlsMatcher                 MatchFunc
	api                         *API
	log                         logging.LeveledLogger
}

type simulcastStreamPair struct {
	srtp  *srtp.ReadStreamSRTP
	srtcp *srtp.ReadStreamSRTCP
}

type streamsForSSRCResult struct {
	rtpReadStream   *srtp.ReadStreamSRTP
	rtpInterceptor  interceptor.RTPReader
	rtcpReadStream  *srtp.ReadStreamSRTCP
	rtcpInterceptor interceptor.RTCPReader
}

func (api *API) NewDTLSTransport(transport *ICETransport, certificates []Certificate) (*DTLSTransport, error) {
	trans := &DTLSTransport{
		iceTransport: transport,
		api:          api,
		state:        DTLSTransportStateNew,
		dtlsMatcher:  MatchDTLS,
		srtpReady:    make(chan struct{}),
		log:          api.settingEngine.LoggerFactory.NewLogger("DTLSTransport"),
	}

	if len(certificates) > 0 {
		now := time.Now()
		for _, x509Cert := range certificates {
			if !x509Cert.Expires().IsZero() && now.After(x509Cert.Expires()) {
				return nil, &InvalidAccessError{Err: ErrCertificateExpired}
			}
			trans.certificates = append(trans.certificates, x509Cert)
		}
	} else {
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, &UnknownError{Err: err}
		}
		certificate, err := GenerateCertificate(sk)
		if err != nil {
			return nil, err
		}
		trans.certificates = []Certificate{*certificate}
	}

	return trans, nil
}

func (t *DTLSTransport) ICETransport() *ICETransport {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.iceTransport
}

func (t *DTLSTransport) onStateChange(state DTLSTransportState) {
	t.state = state
	handler := t.onStateChangeHandler
	if handler != nil {
		handler(state)
	}
}

func (t *DTLSTransport) OnStateChange(f func(DTLSTransportState)) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.onStateChangeHandler = f
}

func (t *DTLSTransport) State() DTLSTransportState {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.state
}

func (t *DTLSTransport) WriteRTCP(pkts []rtcp.Packet) (int, error) {
	raw, err := rtcp.Marshal(pkts)
	if err != nil {
		return 0, err
	}

	srtcpSession, err := t.getSRTCPSession()
	if err != nil {
		return 0, err
	}

	writeStream, err := srtcpSession.OpenWriteStream()
	if err != nil {

		return 0, fmt.Errorf("%w: %v", errPeerConnWriteRTCPOpenWriteStream, err)
	}

	return writeStream.Write(raw)
}

func (t *DTLSTransport) GetLocalParameters() (DTLSParameters, error) {
	fingerprints := []DTLSFingerprint{}

	for _, c := range t.certificates {
		prints, err := c.GetFingerprints()
		if err != nil {
			return DTLSParameters{}, err
		}

		fingerprints = append(fingerprints, prints...)
	}

	return DTLSParameters{
		Role:         DTLSRoleAuto,
		Fingerprints: fingerprints,
	}, nil
}

func (t *DTLSTransport) GetRemoteCertificate() []byte {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.remoteCertificate
}

func (t *DTLSTransport) startSRTP() error {
	srtpConfig := &srtp.Config{
		Profile:       t.srtpProtectionProfile,
		BufferFactory: t.api.settingEngine.BufferFactory,
		LoggerFactory: t.api.settingEngine.LoggerFactory,
	}
	if t.api.settingEngine.replayProtection.SRTP != nil {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTPReplayProtection(*t.api.settingEngine.replayProtection.SRTP),
		)
	}

	if t.api.settingEngine.disableSRTPReplayProtection {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTPNoReplayProtection(),
		)
	}

	if t.api.settingEngine.replayProtection.SRTCP != nil {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTCPReplayProtection(*t.api.settingEngine.replayProtection.SRTCP),
		)
	}

	if t.api.settingEngine.disableSRTCPReplayProtection {
		srtpConfig.RemoteOptions = append(
			srtpConfig.RemoteOptions,
			srtp.SRTCPNoReplayProtection(),
		)
	}

	connState, ok := t.conn.ConnectionState()
	if !ok {

		return fmt.Errorf("%w: Failed to get DTLS ConnectionState", errDtlsKeyExtractionFailed)
	}

	err := srtpConfig.ExtractSessionKeysFromDTLS(&connState, t.role() == DTLSRoleClient)
	if err != nil {

		return fmt.Errorf("%w: %v", errDtlsKeyExtractionFailed, err)
	}

	srtpSession, err := srtp.NewSessionSRTP(t.srtpEndpoint, srtpConfig)
	if err != nil {

		return fmt.Errorf("%w: %v", errFailedToStartSRTP, err)
	}

	srtcpSession, err := srtp.NewSessionSRTCP(t.srtcpEndpoint, srtpConfig)
	if err != nil {

		return fmt.Errorf("%w: %v", errFailedToStartSRTCP, err)
	}

	t.srtpSession.Store(srtpSession)
	t.srtcpSession.Store(srtcpSession)
	close(t.srtpReady)

	return nil
}

func (t *DTLSTransport) getSRTPSession() (*srtp.SessionSRTP, error) {
	if value, ok := t.srtpSession.Load().(*srtp.SessionSRTP); ok {
		return value, nil
	}

	return nil, errDtlsTransportNotStarted
}

func (t *DTLSTransport) getSRTCPSession() (*srtp.SessionSRTCP, error) {
	if value, ok := t.srtcpSession.Load().(*srtp.SessionSRTCP); ok {
		return value, nil
	}

	return nil, errDtlsTransportNotStarted
}

func (t *DTLSTransport) role() DTLSRole {

	switch t.remoteParameters.Role {
	case DTLSRoleClient:
		return DTLSRoleServer
	case DTLSRoleServer:
		return DTLSRoleClient
	default:
	}

	switch t.api.settingEngine.answeringDTLSRole {
	case DTLSRoleServer:
		return DTLSRoleServer
	case DTLSRoleClient:
		return DTLSRoleClient
	default:
	}

	if t.iceTransport.Role() == ICERoleControlling {
		return DTLSRoleServer
	}

	return defaultDtlsRoleAnswer
}

func (t *DTLSTransport) Start(remoteParameters DTLSParameters) error {
	role, certificate, err := t.prepareStart(remoteParameters)
	if err != nil {
		return err
	}

	dtlsEndpoint := t.iceTransport.newEndpoint(MatchDTLS)
	dtlsEndpoint.SetOnClose(t.internalOnCloseHandler)

	sharedOpts := t.dtlsSharedOptions(certificate)

	dtlsConn, err := t.connectDTLS(dtlsEndpoint, role, sharedOpts)
	if err != nil {
		dtlsEndpoint.SetOnClose(nil)
		_ = dtlsEndpoint.Close()

		return t.failStart(err)
	}

	if err = t.handshakeDTLS(dtlsConn); err != nil {
		dtlsEndpoint.SetOnClose(nil)
		_ = dtlsConn.Close()

		return t.failStart(err)
	}

	if err = t.completeStart(dtlsConn); err != nil {
		dtlsEndpoint.SetOnClose(nil)
		_ = dtlsConn.Close()

		return err
	}

	return nil
}

func (t *DTLSTransport) prepareStart(remoteParameters DTLSParameters) (DTLSRole, tls.Certificate, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if err := t.ensureICEConn(); err != nil {
		return DTLSRole(0), tls.Certificate{}, err
	}

	if t.state != DTLSTransportStateNew {
		return DTLSRole(0), tls.Certificate{}, &InvalidStateError{
			Err: fmt.Errorf("%w: %s", errInvalidDTLSStart, t.state),
		}
	}

	t.srtpEndpoint = t.iceTransport.newEndpoint(MatchSRTP)
	t.srtcpEndpoint = t.iceTransport.newEndpoint(MatchSRTCP)
	t.remoteParameters = remoteParameters

	cert := t.certificates[0]
	t.onStateChange(DTLSTransportStateConnecting)

	return t.role(), tls.Certificate{
		Certificate: [][]byte{cert.x509Cert.Raw},
		PrivateKey:  cert.privateKey,
	}, nil
}

func (t *DTLSTransport) dtlsSharedOptions(certificate tls.Certificate) []dtls.Option {
	sharedOpts := []dtls.Option{
		dtls.WithCertificates(certificate),
		dtls.WithSRTPProtectionProfiles(t.srtpProtectionProfiles()...),
		dtls.WithExtendedMasterSecret(t.api.settingEngine.dtls.extendedMasterSecret),
		dtls.WithInsecureSkipVerify(!t.api.settingEngine.dtls.disableInsecureSkipVerify),
		dtls.WithLoggerFactory(t.api.settingEngine.LoggerFactory),
		dtls.WithVerifyPeerCertificate(t.verifyPeerCertificateFunc()),
	}

	if t.api.settingEngine.dtls.customCipherSuites != nil {
		sharedOpts = append(
			sharedOpts,
			dtls.WithCustomCipherSuites(t.api.settingEngine.dtls.customCipherSuites),
		)
	}

	if t.api.settingEngine.dtls.retransmissionInterval > 0 {
		sharedOpts = append(
			sharedOpts,
			dtls.WithFlightInterval(t.api.settingEngine.dtls.retransmissionInterval),
		)
	}

	if t.api.settingEngine.replayProtection.DTLS != nil {
		sharedOpts = append(
			sharedOpts,
			dtls.WithReplayProtectionWindow(int(*t.api.settingEngine.replayProtection.DTLS)),
		)
	}

	if t.api.settingEngine.dtls.cipherSuites != nil {
		sharedOpts = append(
			sharedOpts,
			dtls.WithCipherSuites(t.api.settingEngine.dtls.cipherSuites...),
		)
	}

	if len(t.api.settingEngine.dtls.ellipticCurves) > 0 {
		sharedOpts = append(
			sharedOpts,
			dtls.WithEllipticCurves(t.api.settingEngine.dtls.ellipticCurves...),
		)
	}

	if t.api.settingEngine.dtls.rootCAs != nil {
		sharedOpts = append(sharedOpts, dtls.WithRootCAs(t.api.settingEngine.dtls.rootCAs))
	}

	if t.api.settingEngine.dtls.keyLogWriter != nil {
		sharedOpts = append(sharedOpts, dtls.WithKeyLogWriter(t.api.settingEngine.dtls.keyLogWriter))
	}

	if len(t.api.settingEngine.dtls.supportedProtocols) > 0 {
		sharedOpts = append(
			sharedOpts,
			dtls.WithSupportedProtocols(t.api.settingEngine.dtls.supportedProtocols...),
		)
	}

	return sharedOpts
}

func (t *DTLSTransport) srtpProtectionProfiles() []dtls.SRTPProtectionProfile {
	if len(t.api.settingEngine.srtpProtectionProfiles) > 0 {
		return t.api.settingEngine.srtpProtectionProfiles
	}

	return defaultSrtpProtectionProfiles()
}

func (t *DTLSTransport) verifyPeerCertificateFunc() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errNoRemoteCertificate
		}

		t.lock.Lock()
		defer t.lock.Unlock()
		t.remoteCertificate = rawCerts[0]

		if t.api.settingEngine.disableCertificateFingerprintVerification {
			return nil
		}

		parsedRemoteCert, err := x509.ParseCertificate(t.remoteCertificate)
		if err != nil {
			return err
		}

		return t.validateFingerPrint(parsedRemoteCert)
	}
}

func (t *DTLSTransport) connectDTLS(
	dtlsEndpoint *Endpoint,
	role DTLSRole,
	sharedOpts []dtls.Option,
) (*dtls.Conn, error) {
	if role == DTLSRoleClient {
		clientOpts := t.toDTLSClientOptions(sharedOpts)

		return dtls.ClientWithOptions(
			dtlsEndpoint,
			dtlsEndpoint.RemoteAddr(),
			clientOpts...,
		)
	}

	serverOpts := t.toDTLSServerOptions(sharedOpts)

	return dtls.ServerWithOptions(
		dtlsEndpoint,
		dtlsEndpoint.RemoteAddr(),
		serverOpts...,
	)
}

func (t *DTLSTransport) toDTLSServerOptions(sharedOpts []dtls.Option) []dtls.ServerOption {
	serverOpts := make([]dtls.ServerOption, 0, len(sharedOpts)+5)
	for _, opt := range sharedOpts {
		serverOpts = append(serverOpts, opt)
	}

	clientAuth := dtls.RequireAnyClientCert
	if t.api.settingEngine.dtls.clientAuth != nil {
		clientAuth = *t.api.settingEngine.dtls.clientAuth
	}

	serverOpts = append(serverOpts,
		dtls.WithClientAuth(clientAuth),
		dtls.WithClientCAs(t.api.settingEngine.dtls.clientCAs),
		dtls.WithInsecureSkipVerifyHello(t.api.settingEngine.dtls.insecureSkipHelloVerify),
	)

	if t.api.settingEngine.dtls.serverHelloMessageHook != nil {
		serverOpts = append(
			serverOpts,
			dtls.WithServerHelloMessageHook(t.api.settingEngine.dtls.serverHelloMessageHook),
		)
	}

	if t.api.settingEngine.dtls.certificateRequestMessageHook != nil {
		serverOpts = append(
			serverOpts,
			dtls.WithCertificateRequestMessageHook(t.api.settingEngine.dtls.certificateRequestMessageHook),
		)
	}

	return serverOpts
}

func (t *DTLSTransport) toDTLSClientOptions(sharedOpts []dtls.Option) []dtls.ClientOption {
	clientOpts := make([]dtls.ClientOption, 0, len(sharedOpts)+1)
	for _, opt := range sharedOpts {
		clientOpts = append(clientOpts, opt)
	}

	if t.api.settingEngine.dtls.clientHelloMessageHook != nil {
		clientOpts = append(
			clientOpts,
			dtls.WithClientHelloMessageHook(t.api.settingEngine.dtls.clientHelloMessageHook),
		)
	}

	return clientOpts
}

func (t *DTLSTransport) handshakeDTLS(dtlsConn *dtls.Conn) error {
	if t.api.settingEngine.dtls.connectContextMaker == nil {
		return dtlsConn.Handshake()
	}

	handshakeCtx, cancel := t.api.settingEngine.dtls.connectContextMaker()
	if cancel != nil {
		defer cancel()
	}

	return dtlsConn.HandshakeContext(handshakeCtx)
}

func (t *DTLSTransport) completeStart(dtlsConn *dtls.Conn) error {
	srtpProtectionProfile, err := srtpProtectionProfileFromDTLSConn(dtlsConn)

	t.lock.Lock()
	defer t.lock.Unlock()

	if err != nil {
		t.onStateChange(DTLSTransportStateFailed)

		return err
	}

	t.srtpProtectionProfile = srtpProtectionProfile
	t.conn = dtlsConn
	t.onStateChange(DTLSTransportStateConnected)

	return t.startSRTP()
}

func (t *DTLSTransport) failStart(err error) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.onStateChange(DTLSTransportStateFailed)

	return err
}

func srtpProtectionProfileFromDTLSConn(dtlsConn *dtls.Conn) (srtp.ProtectionProfile, error) {
	srtpProfile, ok := dtlsConn.SelectedSRTPProtectionProfile()
	if !ok {
		return 0, ErrNoSRTPProtectionProfile
	}

	return srtpProtectionProfileFromDTLS(srtpProfile)
}

func srtpProtectionProfileFromDTLS(srtpProfile dtls.SRTPProtectionProfile) (srtp.ProtectionProfile, error) {
	switch srtpProfile {
	case dtls.SRTP_AEAD_AES_128_GCM:
		return srtp.ProtectionProfileAeadAes128Gcm, nil
	case dtls.SRTP_AEAD_AES_256_GCM:
		return srtp.ProtectionProfileAeadAes256Gcm, nil
	case dtls.SRTP_AES128_CM_HMAC_SHA1_80:
		return srtp.ProtectionProfileAes128CmHmacSha1_80, nil
	case dtls.SRTP_NULL_HMAC_SHA1_80:
		return srtp.ProtectionProfileNullHmacSha1_80, nil
	default:
		return 0, ErrNoSRTPProtectionProfile
	}
}

func (t *DTLSTransport) Stop() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	var closeErrs []error

	if srtpSession, err := t.getSRTPSession(); err == nil && srtpSession != nil {
		closeErrs = append(closeErrs, srtpSession.Close())
	}

	if srtcpSession, err := t.getSRTCPSession(); err == nil && srtcpSession != nil {
		closeErrs = append(closeErrs, srtcpSession.Close())
	}

	for i := range t.simulcastStreams {
		closeErrs = append(closeErrs, t.simulcastStreams[i].srtp.Close())
		closeErrs = append(closeErrs, t.simulcastStreams[i].srtcp.Close())
	}

	if t.conn != nil {

		if err := t.conn.Close(); err != nil && !errors.Is(err, dtls.ErrConnClosed) {
			closeErrs = append(closeErrs, err)
		}
	}
	t.onStateChange(DTLSTransportStateClosed)

	return wutil.JoinErrors(closeErrs)
}

func (t *DTLSTransport) validateFingerPrint(remoteCert *x509.Certificate) error {
	for _, fp := range t.remoteParameters.Fingerprints {
		hashAlgo, err := dtls.HashFromString(fp.Algorithm)
		if err != nil {
			return err
		}

		remoteValue, err := dtls.Fingerprint(remoteCert, hashAlgo)
		if err != nil {
			return err
		}

		if strings.EqualFold(remoteValue, fp.Value) {
			return nil
		}
	}

	return errNoMatchingCertificateFingerprint
}

func (t *DTLSTransport) ensureICEConn() error {
	if t.iceTransport == nil {
		return errICEConnectionNotStarted
	}

	return nil
}

func (t *DTLSTransport) storeSimulcastStream(
	srtpReadStream *srtp.ReadStreamSRTP,
	srtcpReadStream *srtp.ReadStreamSRTCP,
) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.simulcastStreams = append(t.simulcastStreams, simulcastStreamPair{srtpReadStream, srtcpReadStream})
}

func (t *DTLSTransport) streamsForSSRC(
	ssrc SSRC,
	streamInfo interceptor.StreamInfo,
) (*streamsForSSRCResult, error) {
	srtpSession, err := t.getSRTPSession()
	if err != nil {
		return nil, err
	}

	rtpReadStream, err := srtpSession.OpenReadStream(uint32(ssrc))
	if err != nil {
		return nil, err
	}

	rtpInterceptor := t.api.interceptor.BindRemoteStream(
		&streamInfo,
		interceptor.RTPReaderFunc(
			func(in []byte, a interceptor.Attributes) (n int, attributes interceptor.Attributes, err error) {
				n, err = rtpReadStream.Read(in)

				return n, a, err
			},
		),
	)

	srtcpSession, err := t.getSRTCPSession()
	if err != nil {
		return nil, err
	}

	rtcpReadStream, err := srtcpSession.OpenReadStream(uint32(ssrc))
	if err != nil {
		return nil, err
	}

	rtcpInterceptor := t.api.interceptor.BindRTCPReader(interceptor.RTCPReaderFunc(
		func(in []byte, a interceptor.Attributes) (n int, attributes interceptor.Attributes, err error) {
			n, err = rtcpReadStream.Read(in)

			return n, a, err
		}),
	)

	return &streamsForSSRCResult{
		rtpReadStream:   rtpReadStream,
		rtpInterceptor:  rtpInterceptor,
		rtcpReadStream:  rtcpReadStream,
		rtcpInterceptor: rtcpInterceptor,
	}, nil
}

func (api *API) NewICETransport(gatherer *ICEGatherer) *ICETransport {
	return NewICETransport(gatherer, api.settingEngine.LoggerFactory)
}

type ICEGatherer struct {
	lock                       sync.RWMutex
	log                        logging.LeveledLogger
	state                      ICEGathererState
	validatedServers           []*stun.URI
	gatherPolicy               ICETransportPolicy
	agent                      *ice.Agent
	onLocalCandidateHandler    atomic.Value
	onStateChangeHandler       atomic.Value
	onGatheringCompleteHandler atomic.Value
	api                        *API
	sdpMid                     atomic.Value
	sdpMLineIndex              atomic.Uint32
	candidatePoolLock          sync.Mutex
	candidatePool              []ice.Candidate
	iceCandidatePoolSize       uint8
}

type ICEAddressRewriteMode byte

const (
	ICEAddressRewriteModeUnspecified ICEAddressRewriteMode = iota
	ICEAddressRewriteReplace
	ICEAddressRewriteAppend
)

func (r ICEAddressRewriteMode) toICE() ice.AddressRewriteMode {
	return ice.AddressRewriteMode(r)
}

type ICEAddressRewriteRule struct {
	External        []string
	Local           string
	Iface           string
	CIDR            string
	AsCandidateType ICECandidateType
	Mode            ICEAddressRewriteMode
	Networks        []NetworkType
}

func (r ICEAddressRewriteRule) toICE() ice.AddressRewriteRule {
	candidateType := r.AsCandidateType.toICE()
	mode := r.Mode.toICE()
	networks := toICENetworkTypes(r.Networks)

	rule := ice.AddressRewriteRule{
		External:        append([]string(nil), r.External...),
		Local:           r.Local,
		Iface:           r.Iface,
		CIDR:            r.CIDR,
		AsCandidateType: candidateType,
		Mode:            mode,
		Networks:        networks,
	}

	return rule
}

func (api *API) NewICEGatherer(opts ICEGatherOptions) (*ICEGatherer, error) {
	var validatedServers []*stun.URI
	if len(opts.ICEServers) > 0 {
		for _, server := range opts.ICEServers {
			url, err := server.urls()
			if err != nil {
				return nil, err
			}
			validatedServers = append(validatedServers, url...)
		}
	}

	return &ICEGatherer{
		state:                ICEGathererStateNew,
		gatherPolicy:         opts.ICEGatherPolicy,
		validatedServers:     validatedServers,
		api:                  api,
		log:                  api.settingEngine.LoggerFactory.NewLogger("ice"),
		sdpMid:               atomic.Value{},
		sdpMLineIndex:        atomic.Uint32{},
		candidatePool:        make([]ice.Candidate, 0, opts.ICECandidatePoolSize),
		iceCandidatePoolSize: opts.ICECandidatePoolSize,
	}, nil
}

func (g *ICEGatherer) updateServers(servers []ICEServer, policy ICETransportPolicy) error {
	g.lock.Lock()
	defer g.lock.Unlock()

	var validatedServers []*stun.URI
	for _, server := range servers {
		urls, err := server.urls()
		if err != nil {
			return err
		}
		validatedServers = append(validatedServers, urls...)
	}

	g.validatedServers = validatedServers
	g.gatherPolicy = policy

	if g.agent != nil && (g.State() != ICEGathererStateGathering ||
		g.iceCandidatePoolSize == 0) {
		return g.agent.UpdateOptions(ice.WithUrls(validatedServers))
	}

	return nil
}

func (g *ICEGatherer) createAgent() error {
	g.lock.Lock()
	defer g.lock.Unlock()

	if g.agent != nil || g.State() != ICEGathererStateNew {
		return nil
	}

	options, err := g.buildAgentOptions()
	if err != nil {
		return err
	}

	agent, err := ice.NewAgentWithOptions(options...)
	if err != nil {
		return err
	}

	g.agent = agent

	return nil
}

func (g *ICEGatherer) buildAgentOptions() ([]ice.AgentOption, error) {
	candidateTypes := g.resolveCandidateTypes()
	nat1To1CandiTyp := g.resolveNAT1To1CandidateType()
	mDNSMode := g.sanitizedMDNSMode()

	options := g.baseAgentOptions(mDNSMode)
	if len(candidateTypes) > 0 {
		options = append(options, ice.WithCandidateTypes(candidateTypes))
	}

	options = append(options, g.credentialOptions()...)

	rewriteOptions, err := g.addressRewriteOptions(nat1To1CandiTyp)
	if err != nil {
		return nil, err
	}
	options = append(options, rewriteOptions...)
	options = append(options, g.timeoutOptions()...)
	options = append(options, g.miscOptions()...)
	options = append(options, g.renominationOptions()...)

	requestedNetworkTypes := g.api.settingEngine.candidates.ICENetworkTypes
	if len(requestedNetworkTypes) == 0 {
		requestedNetworkTypes = supportedNetworkTypes()
	}

	return append(options, ice.WithNetworkTypes(toICENetworkTypes(requestedNetworkTypes))), nil
}

func (g *ICEGatherer) resolveCandidateTypes() []ice.CandidateType {
	if g.api.settingEngine.candidates.ICELite {
		return []ice.CandidateType{ice.CandidateTypeHost}
	}

	switch g.gatherPolicy {
	case ICETransportPolicyRelay:
		return []ice.CandidateType{ice.CandidateTypeRelay}
	case ICETransportPolicyNoHost:
		return []ice.CandidateType{ice.CandidateTypeServerReflexive, ice.CandidateTypeRelay}
	default:
	}

	return nil
}

func (g *ICEGatherer) resolveNAT1To1CandidateType() ice.CandidateType {
	switch g.api.settingEngine.candidates.NAT1To1IPCandidateType {
	case ICECandidateTypeHost:
		return ice.CandidateTypeHost
	case ICECandidateTypeSrflx:
		return ice.CandidateTypeServerReflexive
	default:
		return ice.CandidateTypeUnspecified
	}
}

func (g *ICEGatherer) sanitizedMDNSMode() ice.MulticastDNSMode {
	mode := g.api.settingEngine.candidates.MulticastDNSMode
	if mode == ice.MulticastDNSModeDisabled || mode == ice.MulticastDNSModeQueryAndGather {
		return mode
	}

	return ice.MulticastDNSModeQueryOnly
}

func (g *ICEGatherer) baseAgentOptions(mDNSMode ice.MulticastDNSMode) []ice.AgentOption {
	return []ice.AgentOption{
		ice.WithICELite(g.api.settingEngine.candidates.ICELite),
		ice.WithUrls(g.validatedServers),
		ice.WithPortRange(g.api.settingEngine.ephemeralUDP.PortMin, g.api.settingEngine.ephemeralUDP.PortMax),
		ice.WithLoggerFactory(g.api.settingEngine.LoggerFactory),
		ice.WithInterfaceFilter(g.api.settingEngine.candidates.InterfaceFilter),
		ice.WithIPFilter(g.api.settingEngine.candidates.IPFilter),
		ice.WithRemoteIPFilter(g.api.settingEngine.candidates.RemoteIPFilter),
		ice.WithNet(g.api.settingEngine.net),
		ice.WithMulticastDNSMode(mDNSMode),
		ice.WithTCPMux(g.api.settingEngine.iceTCPMux),
		ice.WithUDPMux(g.api.settingEngine.iceUDPMux),
		ice.WithProxyDialer(g.api.settingEngine.iceProxyDialer),
		ice.WithBindingRequestHandler(g.api.settingEngine.iceBindingRequestHandler),
	}
}

func (g *ICEGatherer) credentialOptions() []ice.AgentOption {
	ufrag := g.api.settingEngine.candidates.UsernameFragment
	pass := g.api.settingEngine.candidates.Password
	if ufrag == "" && pass == "" {
		return nil
	}

	return []ice.AgentOption{
		ice.WithLocalCredentials(g.api.settingEngine.candidates.UsernameFragment, g.api.settingEngine.candidates.Password),
	}
}

func (g *ICEGatherer) addressRewriteOptions(candidateType ice.CandidateType) ([]ice.AgentOption, error) {
	rules := g.api.settingEngine.candidates.addressRewriteRules
	nat1To1IPs := g.api.settingEngine.candidates.NAT1To1IPs
	if len(rules) > 0 && len(nat1To1IPs) > 0 {
		return nil, errAddressRewriteWithNAT1To1
	}

	if len(rules) > 0 {
		return []ice.AgentOption{ice.WithAddressRewriteRules(rules...)}, nil
	}

	if len(nat1To1IPs) == 0 {
		return nil, nil
	}

	return []ice.AgentOption{
		ice.WithAddressRewriteRules(
			legacyNAT1To1AddressRewriteRules(
				nat1To1IPs,
				candidateType,
			)...,
		),
	}, nil
}

func (g *ICEGatherer) timeoutOptions() []ice.AgentOption {
	opts := make([]ice.AgentOption, 0, 8)

	if g.api.settingEngine.timeout.ICEDisconnectedTimeout != nil {
		opts = append(opts, ice.WithDisconnectedTimeout(*g.api.settingEngine.timeout.ICEDisconnectedTimeout))
	}
	if g.api.settingEngine.timeout.ICEFailedTimeout != nil {
		opts = append(opts, ice.WithFailedTimeout(*g.api.settingEngine.timeout.ICEFailedTimeout))
	}
	if g.api.settingEngine.timeout.ICEKeepaliveInterval != nil {
		opts = append(opts, ice.WithKeepaliveInterval(*g.api.settingEngine.timeout.ICEKeepaliveInterval))
	}
	if g.api.settingEngine.timeout.ICEHostAcceptanceMinWait != nil {
		opts = append(opts, ice.WithHostAcceptanceMinWait(*g.api.settingEngine.timeout.ICEHostAcceptanceMinWait))
	}
	if g.api.settingEngine.timeout.ICESrflxAcceptanceMinWait != nil {
		opts = append(opts, ice.WithSrflxAcceptanceMinWait(*g.api.settingEngine.timeout.ICESrflxAcceptanceMinWait))
	}
	if g.api.settingEngine.timeout.ICEPrflxAcceptanceMinWait != nil {
		opts = append(opts, ice.WithPrflxAcceptanceMinWait(*g.api.settingEngine.timeout.ICEPrflxAcceptanceMinWait))
	}
	if g.api.settingEngine.timeout.ICERelayAcceptanceMinWait != nil {
		opts = append(opts, ice.WithRelayAcceptanceMinWait(*g.api.settingEngine.timeout.ICERelayAcceptanceMinWait))
	}
	if g.api.settingEngine.timeout.ICESTUNGatherTimeout != nil {
		opts = append(opts, ice.WithSTUNGatherTimeout(*g.api.settingEngine.timeout.ICESTUNGatherTimeout))
	}

	return opts
}

func (g *ICEGatherer) miscOptions() []ice.AgentOption {
	opts := make([]ice.AgentOption, 0, 4)

	if g.api.settingEngine.candidates.MulticastDNSHostName != "" {
		opts = append(opts, ice.WithMulticastDNSHostName(g.api.settingEngine.candidates.MulticastDNSHostName))
	}

	if g.api.settingEngine.candidates.IncludeLoopbackCandidate {
		opts = append(opts, ice.WithIncludeLoopback())
	}

	if g.api.settingEngine.iceDisableActiveTCP {
		opts = append(opts, ice.WithDisableActiveTCP())
	}

	if g.api.settingEngine.iceMaxBindingRequests != nil {
		opts = append(opts, ice.WithMaxBindingRequests(*g.api.settingEngine.iceMaxBindingRequests))
	}

	return opts
}

func (g *ICEGatherer) renominationOptions() []ice.AgentOption {
	renom := g.api.settingEngine.renomination
	if !renom.enabled && !renom.automatic {
		return nil
	}

	generator := renom.generator
	opts := []ice.AgentOption{
		ice.WithRenomination(func() uint32 {
			return generator()
		}),
	}
	if renom.attributeType != nil {
		opts = append(opts, ice.WithNominationAttribute(*renom.attributeType))
	}

	if renom.automatic {
		interval := time.Duration(0)
		if renom.automaticInterval != nil {
			interval = *renom.automaticInterval
		}

		opts = append(opts, ice.WithAutomaticRenomination(interval))
	}

	return opts
}

func legacyNAT1To1AddressRewriteRules(ips []string, candidateType ice.CandidateType) []ice.AddressRewriteRule {
	catchAll := make([]string, 0, len(ips))
	rules := make([]ice.AddressRewriteRule, 0, len(ips)+1)

	for _, ip := range ips {
		splits := strings.SplitN(ip, "/", 2)

		if len(splits) == 2 {
			rules = append(rules, ice.AddressRewriteRule{
				External:        []string{splits[0]},
				Local:           splits[1],
				AsCandidateType: candidateType,
			})
			catchAll = append(catchAll, splits[0])
		} else {
			catchAll = append(catchAll, ip)
		}
	}

	if len(catchAll) > 0 {
		rules = append(rules, ice.AddressRewriteRule{
			External:        catchAll,
			AsCandidateType: candidateType,
		})
	}

	return rules
}

func (g *ICEGatherer) Gather() error {
	if err := g.createAgent(); err != nil {
		return err
	}

	agent := g.getAgent()

	if agent == nil {
		return fmt.Errorf("%w: unable to gather", errICEAgentNotExist)
	}

	g.setState(ICEGathererStateGathering)
	if err := agent.OnCandidate(func(candidate ice.Candidate) {
		onLocalCandidateHandler := func(*ICECandidate) {}
		if handler, ok := g.onLocalCandidateHandler.Load().(func(candidate *ICECandidate)); ok && handler != nil {
			onLocalCandidateHandler = handler
		}

		onGatheringCompleteHandler := func() {}
		if handler, ok := g.onGatheringCompleteHandler.Load().(func()); ok && handler != nil {
			onGatheringCompleteHandler = handler
		}

		sdpMid := ""

		if mid, ok := g.sdpMid.Load().(string); ok {
			sdpMid = mid
		}

		sdpMLineIndex := uint16(g.sdpMLineIndex.Load())

		if candidate != nil {
			g.candidatePoolLock.Lock()
			if g.iceCandidatePoolSize > 0 && g.candidatePool != nil {
				g.candidatePool = append(g.candidatePool, candidate)
				g.candidatePoolLock.Unlock()

				return
			}
			g.candidatePoolLock.Unlock()

			c, err := newICECandidateFromICE(candidate, sdpMid, sdpMLineIndex)
			if err != nil {
				g.log.Warnf("Failed to convert ice.Candidate: %s", err)

				return
			}
			onLocalCandidateHandler(&c)
		} else {
			g.setState(ICEGathererStateComplete)
			onGatheringCompleteHandler()

			g.candidatePoolLock.Lock()
			if g.iceCandidatePoolSize > 0 && g.candidatePool != nil {
				g.candidatePoolLock.Unlock()

				return
			}
			g.candidatePoolLock.Unlock()

			onLocalCandidateHandler(nil)
		}
	}); err != nil {
		return err
	}

	return agent.GatherCandidates()
}

func (g *ICEGatherer) setMediaStreamIdentification(mid string, mLineIndex uint16) {
	g.sdpMid.Store(mid)
	g.sdpMLineIndex.Store(uint32(mLineIndex))
}

func (g *ICEGatherer) flushCandidates() {
	g.candidatePoolLock.Lock()

	candidates := g.candidatePool
	g.candidatePool = nil
	g.iceCandidatePoolSize = 0

	g.candidatePoolLock.Unlock()

	onLocalCandidateHandler := func(*ICECandidate) {}
	if handler, ok := g.onLocalCandidateHandler.Load().(func(candidate *ICECandidate)); ok && handler != nil {
		onLocalCandidateHandler = handler
	}

	sdpMid := ""
	if mid, ok := g.sdpMid.Load().(string); ok {
		sdpMid = mid
	}

	sdpMLineIndex := uint16(g.sdpMLineIndex.Load())

	currentState := g.State()

	for _, candidate := range candidates {
		c, err := newICECandidateFromICE(candidate, sdpMid, sdpMLineIndex)
		if err != nil {
			g.log.Warnf("Failed to convert pooled ice.Candidate: %s", err)

			continue
		}
		onLocalCandidateHandler(&c)
	}

	if currentState == ICEGathererStateComplete {
		onLocalCandidateHandler(nil)
	}
}

func (g *ICEGatherer) Close() error {
	return g.close(false)
}

func (g *ICEGatherer) GracefulClose() error {
	return g.close(true)
}

func (g *ICEGatherer) close(shouldGracefullyClose bool) error {
	g.lock.Lock()
	defer g.lock.Unlock()

	if g.agent == nil {
		return nil
	}
	if shouldGracefullyClose {
		if err := g.agent.GracefulClose(); err != nil {
			return err
		}
	} else {
		if err := g.agent.Close(); err != nil {
			return err
		}
	}

	if handler, ok := g.onGatheringCompleteHandler.Load().(func()); ok && handler != nil {
		handler()
	}

	g.agent = nil
	g.setState(ICEGathererStateClosed)

	return nil
}

func (g *ICEGatherer) GetLocalParameters() (ICEParameters, error) {
	if err := g.createAgent(); err != nil {
		return ICEParameters{}, err
	}

	agent := g.getAgent()

	if agent == nil {
		return ICEParameters{}, fmt.Errorf("%w: unable to get local parameters", errICEAgentNotExist)
	}

	frag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return ICEParameters{}, err
	}

	return ICEParameters{
		UsernameFragment: frag,
		Password:         pwd,
		ICELite:          false,
	}, nil
}

func (g *ICEGatherer) GetLocalCandidates() ([]ICECandidate, error) {
	if err := g.createAgent(); err != nil {
		return nil, err
	}

	agent := g.getAgent()

	if agent == nil {
		return nil, fmt.Errorf("%w: unable to get local candidates", errICEAgentNotExist)
	}

	iceCandidates, err := agent.GetLocalCandidates()
	if err != nil {
		return nil, err
	}

	sdpMid := ""
	if mid, ok := g.sdpMid.Load().(string); ok {
		sdpMid = mid
	}

	sdpMLineIndex := uint16(g.sdpMLineIndex.Load())

	return newICECandidatesFromICE(iceCandidates, sdpMid, sdpMLineIndex)
}

func (g *ICEGatherer) OnLocalCandidate(f func(*ICECandidate)) {
	g.onLocalCandidateHandler.Store(f)
}

func (g *ICEGatherer) OnStateChange(f func(ICEGathererState)) {
	g.onStateChangeHandler.Store(f)
}

func (g *ICEGatherer) State() ICEGathererState {
	return atomicLoadICEGathererState(&g.state)
}

func (g *ICEGatherer) setState(s ICEGathererState) {
	atomicStoreICEGathererState(&g.state, s)

	if handler, ok := g.onStateChangeHandler.Load().(func(state ICEGathererState)); ok && handler != nil {
		handler(s)
	}
}

func (g *ICEGatherer) getAgent() *ice.Agent {
	g.lock.RLock()
	defer g.lock.RUnlock()

	return g.agent
}

func (g *ICEGatherer) collectStats(collector *statsReportCollector) {
	agent := g.getAgent()
	if agent == nil {
		return
	}

	collector.Collecting()
	go func(collector *statsReportCollector, agent *ice.Agent) {
		for _, candidatePairStats := range agent.GetCandidatePairsStats() {
			collector.Collecting()

			stats, err := toICECandidatePairStats(candidatePairStats)
			if err != nil {
				g.log.Error(err.Error())
				collector.Done()

				continue
			}

			collector.Collect(stats.ID, stats)
		}

		for _, candidateStats := range agent.GetLocalCandidatesStats() {
			collector.Collecting()

			networkType, err := getNetworkType(candidateStats.NetworkType)
			if err != nil {
				g.log.Error(err.Error())
			}

			candidateType, err := getCandidateType(candidateStats.CandidateType)
			if err != nil {
				g.log.Error(err.Error())
			}

			stats := ICECandidateStats{
				Timestamp:     statsTimestampFrom(candidateStats.Timestamp),
				ID:            candidateStats.ID,
				Type:          StatsTypeLocalCandidate,
				IP:            candidateStats.IP,
				Port:          int32(candidateStats.Port),
				Protocol:      networkType.Protocol(),
				CandidateType: candidateType,
				Priority:      int32(candidateStats.Priority),
				URL:           candidateStats.URL,
				RelayProtocol: candidateStats.RelayProtocol,
				Deleted:       candidateStats.Deleted,
			}
			collector.Collect(stats.ID, stats)
		}

		for _, candidateStats := range agent.GetRemoteCandidatesStats() {
			collector.Collecting()
			networkType, err := getNetworkType(candidateStats.NetworkType)
			if err != nil {
				g.log.Error(err.Error())
			}

			candidateType, err := getCandidateType(candidateStats.CandidateType)
			if err != nil {
				g.log.Error(err.Error())
			}

			stats := ICECandidateStats{
				Timestamp:     statsTimestampFrom(candidateStats.Timestamp),
				ID:            candidateStats.ID,
				Type:          StatsTypeRemoteCandidate,
				IP:            candidateStats.IP,
				Port:          int32(candidateStats.Port),
				Protocol:      networkType.Protocol(),
				CandidateType: candidateType,
				Priority:      int32(candidateStats.Priority),
				URL:           candidateStats.URL,
				RelayProtocol: candidateStats.RelayProtocol,
			}
			collector.Collect(stats.ID, stats)
		}
		collector.Done()
	}(collector, agent)
}

func (g *ICEGatherer) getSelectedCandidatePairStats() (ICECandidatePairStats, bool) {
	agent := g.getAgent()
	if agent == nil {
		return ICECandidatePairStats{}, false
	}

	selectedCandidatePairStats, isAvailable := agent.GetSelectedCandidatePairStats()
	if !isAvailable {
		return ICECandidatePairStats{}, false
	}

	stats, err := toICECandidatePairStats(selectedCandidatePairStats)
	if err != nil {
		g.log.Error(err.Error())

		return ICECandidatePairStats{}, false
	}

	return stats, true
}

type ICEServer struct {
	URLs           []string          `json:"urls"`
	Username       string            `json:"username,omitempty"`
	Credential     any               `json:"credential,omitempty"`
	CredentialType ICECredentialType `json:"credentialType,omitempty"`
}

func (s ICEServer) parseURL(i int) (*stun.URI, error) {
	return stun.ParseURI(s.URLs[i])
}

func (s ICEServer) validate() error {
	_, err := s.urls()

	return err
}

func (s ICEServer) urls() ([]*stun.URI, error) {
	urls := []*stun.URI{}

	for i := range s.URLs {
		url, err := s.parseURL(i)
		if err != nil {
			return nil, &InvalidAccessError{Err: err}
		}

		if url.Scheme == stun.SchemeTypeTURN || url.Scheme == stun.SchemeTypeTURNS {

			if s.Username == "" || s.Credential == nil {
				return nil, &InvalidAccessError{Err: ErrNoTurnCredentials}
			}
			url.Username = s.Username

			switch s.CredentialType {
			case ICECredentialTypePassword:

				password, ok := s.Credential.(string)
				if !ok {
					return nil, &InvalidAccessError{Err: ErrTurnCredentials}
				}
				url.Password = password

			case ICECredentialTypeOauth:

				if _, ok := s.Credential.(OAuthCredential); !ok {
					return nil, &InvalidAccessError{Err: ErrTurnCredentials}
				}

			default:
				return nil, &InvalidAccessError{Err: ErrTurnCredentials}
			}
		}

		urls = append(urls, url)
	}

	return urls, nil
}

func iceserverUnmarshalUrls(val any) (*[]string, error) {
	s, ok := val.([]any)
	if !ok {
		return nil, errInvalidICEServer
	}
	out := make([]string, len(s))
	for idx, url := range s {
		out[idx], ok = url.(string)
		if !ok {
			return nil, errInvalidICEServer
		}
	}

	return &out, nil
}

func iceserverUnmarshalOauth(val any) (*OAuthCredential, error) {
	c, ok := val.(map[string]any)
	if !ok {
		return nil, errInvalidICEServer
	}
	MACKey, ok := c["MACKey"].(string)
	if !ok {
		return nil, errInvalidICEServer
	}
	AccessToken, ok := c["AccessToken"].(string)
	if !ok {
		return nil, errInvalidICEServer
	}

	return &OAuthCredential{
		MACKey:      MACKey,
		AccessToken: AccessToken,
	}, nil
}

func (s *ICEServer) iceserverUnmarshalFields(fields map[string]any) error {
	if val, ok := fields["urls"]; ok {
		u, err := iceserverUnmarshalUrls(val)
		if err != nil {
			return err
		}
		s.URLs = *u
	} else {
		s.URLs = []string{}
	}

	if val, ok := fields["username"]; ok {
		s.Username, ok = val.(string)
		if !ok {
			return errInvalidICEServer
		}
	}
	if val, ok := fields["credentialType"]; ok {
		ct, ok := val.(string)
		if !ok {
			return errInvalidICEServer
		}
		tpe, err := newICECredentialType(ct)
		if err != nil {
			return err
		}
		s.CredentialType = tpe
	} else {
		s.CredentialType = ICECredentialTypePassword
	}
	if val, ok := fields["credential"]; ok {
		switch s.CredentialType {
		case ICECredentialTypePassword:
			s.Credential = val
		case ICECredentialTypeOauth:
			c, err := iceserverUnmarshalOauth(val)
			if err != nil {
				return err
			}
			s.Credential = *c
		default:
			return errInvalidICECredentialTypeString
		}
	}

	return nil
}

func (s *ICEServer) UnmarshalJSON(b []byte) error {
	var tmp any
	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return err
	}
	if m, ok := tmp.(map[string]any); ok {
		return s.iceserverUnmarshalFields(m)
	}

	return errInvalidICEServer
}

func (s ICEServer) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	m["urls"] = s.URLs
	if s.Username != "" {
		m["username"] = s.Username
	}
	if s.Credential != nil {
		m["credential"] = s.Credential
	}
	m["credentialType"] = s.CredentialType

	return json.Marshal(m)
}

type ICETransport struct {
	lock                                   sync.RWMutex
	role                                   ICERole
	onConnectionStateChangeHandler         atomic.Value
	internalOnConnectionStateChangeHandler atomic.Value
	onSelectedCandidatePairChangeHandler   atomic.Value
	state                                  atomic.Value
	gatherer                               *ICEGatherer
	conn                                   *ice.Conn
	mux                                    *Mux
	ctxCancel                              func()
	loggerFactory                          logging.LoggerFactory
	log                                    logging.LeveledLogger
}

func (t *ICETransport) GetSelectedCandidatePair() (*ICECandidatePair, error) {
	agent := t.gatherer.getAgent()
	if agent == nil {
		return nil, nil
	}

	icePair, err := agent.GetSelectedCandidatePair()
	if icePair == nil || err != nil {
		return nil, err
	}

	local, err := newICECandidateFromICE(icePair.Local, "", 0)
	if err != nil {
		return nil, err
	}

	remote, err := newICECandidateFromICE(icePair.Remote, "", 0)
	if err != nil {
		return nil, err
	}

	return NewICECandidatePair(&local, &remote), nil
}

func (t *ICETransport) GetSelectedCandidatePairStats() (ICECandidatePairStats, bool) {
	return t.gatherer.getSelectedCandidatePairStats()
}

func NewICETransport(gatherer *ICEGatherer, loggerFactory logging.LoggerFactory) *ICETransport {
	iceTransport := &ICETransport{
		gatherer:      gatherer,
		loggerFactory: loggerFactory,
		log:           loggerFactory.NewLogger("ortc"),
	}
	iceTransport.setState(ICETransportStateNew)

	return iceTransport
}

func (t *ICETransport) Start(gatherer *ICEGatherer, params ICEParameters, role *ICERole) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.State() != ICETransportStateNew {
		return errICETransportNotInNew
	}

	if gatherer != nil {
		t.gatherer = gatherer
	}

	if err := t.ensureGatherer(); err != nil {
		return err
	}

	agent := t.gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to start ICETransport", errICEAgentNotExist)
	}

	if err := agent.OnConnectionStateChange(func(iceState ice.ConnectionState) {
		state := newICETransportStateFromICE(iceState)

		t.setState(state)
		t.onConnectionStateChange(state)
	}); err != nil {
		return err
	}
	if err := agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		candidates, err := newICECandidatesFromICE([]ice.Candidate{local, remote}, "", 0)
		if err != nil {
			t.log.Warnf("%w: %s", errICECandiatesCoversionFailed, err)

			return
		}
		t.onSelectedCandidatePairChange(NewICECandidatePair(&candidates[0], &candidates[1]))
	}); err != nil {
		return err
	}

	if role == nil {
		controlled := ICERoleControlled
		role = &controlled
	}
	t.role = *role

	ctx, ctxCancel := context.WithCancel(context.Background())
	t.ctxCancel = ctxCancel

	t.lock.Unlock()

	var iceConn *ice.Conn
	var err error
	switch *role {
	case ICERoleControlling:
		iceConn, err = agent.Dial(ctx,
			params.UsernameFragment,
			params.Password)

	case ICERoleControlled:
		iceConn, err = agent.Accept(ctx,
			params.UsernameFragment,
			params.Password)

	default:
		err = errICERoleUnknown
	}

	t.lock.Lock()
	if err != nil {
		return err
	}

	if t.State() == ICETransportStateClosed {
		return errICETransportClosed
	}

	t.conn = iceConn

	config := Config{
		Conn:          t.conn,
		BufferSize:    int(t.gatherer.api.settingEngine.getReceiveMTU()),
		LoggerFactory: t.loggerFactory,
	}
	t.mux = NewMux(config)

	return nil
}

func (t *ICETransport) restart() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	agent := t.gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to restart ICETransport", errICEAgentNotExist)
	}

	if err := agent.Restart(
		t.gatherer.api.settingEngine.candidates.UsernameFragment,
		t.gatherer.api.settingEngine.candidates.Password,
	); err != nil {
		return err
	}

	return t.gatherer.Gather()
}

func (t *ICETransport) Stop() error {
	return t.stop(false)
}

func (t *ICETransport) GracefulStop() error {
	return t.stop(true)
}

func (t *ICETransport) stop(shouldGracefullyClose bool) error {
	t.lock.Lock()
	t.setState(ICETransportStateClosed)

	if t.ctxCancel != nil {
		t.ctxCancel()
	}

	mux := t.mux
	gatherer := t.gatherer
	t.lock.Unlock()

	if mux != nil {
		var closeErrs []error
		if shouldGracefullyClose && gatherer != nil {

			closeErrs = append(closeErrs, gatherer.GracefulClose())
		}
		closeErrs = append(closeErrs, mux.Close())

		return wutil.JoinErrors(closeErrs)
	} else if gatherer != nil {
		if shouldGracefullyClose {
			return gatherer.GracefulClose()
		}

		return gatherer.Close()
	}

	return nil
}

func (t *ICETransport) OnSelectedCandidatePairChange(f func(*ICECandidatePair)) {
	t.onSelectedCandidatePairChangeHandler.Store(f)
}

func (t *ICETransport) onSelectedCandidatePairChange(pair *ICECandidatePair) {
	if handler, ok := t.onSelectedCandidatePairChangeHandler.Load().(func(*ICECandidatePair)); ok {
		handler(pair)
	}
}

func (t *ICETransport) OnConnectionStateChange(f func(ICETransportState)) {
	t.onConnectionStateChangeHandler.Store(f)
}

func (t *ICETransport) onConnectionStateChange(state ICETransportState) {
	if handler, ok := t.onConnectionStateChangeHandler.Load().(func(ICETransportState)); ok {
		handler(state)
	}
	if handler, ok := t.internalOnConnectionStateChangeHandler.Load().(func(ICETransportState)); ok {
		handler(state)
	}
}

func (t *ICETransport) Role() ICERole {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.role
}

func (t *ICETransport) SetRemoteCandidates(remoteCandidates []ICECandidate) error {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if err := t.ensureGatherer(); err != nil {
		return err
	}

	agent := t.gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to set remote candidates", errICEAgentNotExist)
	}

	for _, c := range remoteCandidates {
		i, err := c.ToICE()
		if err != nil {
			return err
		}

		if err = agent.AddRemoteCandidate(i); err != nil {
			return err
		}
	}

	return nil
}

func (t *ICETransport) AddRemoteCandidate(remoteCandidate *ICECandidate) error {
	t.lock.RLock()
	defer t.lock.RUnlock()

	var (
		candidate ice.Candidate
		err       error
	)

	if err = t.ensureGatherer(); err != nil {
		return err
	}

	if remoteCandidate != nil {
		if candidate, err = remoteCandidate.ToICE(); err != nil {
			return err
		}
	}

	agent := t.gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to add remote candidates", errICEAgentNotExist)
	}

	return agent.AddRemoteCandidate(candidate)
}

func (t *ICETransport) State() ICETransportState {
	if v, ok := t.state.Load().(ICETransportState); ok {
		return v
	}

	return ICETransportState(0)
}

func (t *ICETransport) GetLocalParameters() (ICEParameters, error) {
	if err := t.ensureGatherer(); err != nil {
		return ICEParameters{}, err
	}

	return t.gatherer.GetLocalParameters()
}

func (t *ICETransport) GetRemoteParameters() (ICEParameters, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	agent := t.gatherer.getAgent()
	if agent == nil {
		return ICEParameters{}, fmt.Errorf("%w: unable to get remote parameters", errICEAgentNotExist)
	}

	uFrag, uPwd, err := agent.GetRemoteUserCredentials()
	if err != nil {
		return ICEParameters{}, fmt.Errorf("%w: unable to get remote parameters", err)
	}

	return ICEParameters{
		UsernameFragment: uFrag,
		Password:         uPwd,
	}, nil
}

func (t *ICETransport) setState(i ICETransportState) {
	t.state.Store(i)
}

func (t *ICETransport) newEndpoint(f MatchFunc) *Endpoint {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.mux.NewEndpoint(f)
}

func (t *ICETransport) ensureGatherer() error {
	if t.gatherer == nil {
		return errICEGathererNotStarted
	} else if t.gatherer.getAgent() == nil {
		if err := t.gatherer.createAgent(); err != nil {
			return err
		}
	}

	return nil
}

func (t *ICETransport) Stats() TransportStats {
	t.lock.RLock()
	conn := t.conn
	t.lock.RUnlock()

	stats := TransportStats{
		Timestamp: statsTimestampFrom(time.Now()),
		Type:      StatsTypeTransport,
		ID:        "iceTransport",
	}
	if conn != nil {
		stats.BytesSent = conn.BytesSent()
		stats.BytesReceived = conn.BytesReceived()
	}

	return stats
}

func (t *ICETransport) collectStats(collector *statsReportCollector) {
	collector.Collecting()
	stats := t.Stats()
	collector.Collect(stats.ID, stats)
}

func (t *ICETransport) haveRemoteCredentialsChange(newUfrag, newPwd string) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	agent := t.gatherer.getAgent()
	if agent == nil {
		return false
	}

	uFrag, uPwd, err := agent.GetRemoteUserCredentials()
	if err != nil {
		return false
	}

	return uFrag != newUfrag || uPwd != newPwd
}

func (t *ICETransport) setRemoteCredentials(newUfrag, newPwd string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	agent := t.gatherer.getAgent()
	if agent == nil {
		return fmt.Errorf("%w: unable to SetRemoteCredentials", errICEAgentNotExist)
	}

	return agent.SetRemoteCredentials(newUfrag, newPwd)
}

func RegisterDefaultInterceptors(mediaEngine *MediaEngine, interceptorRegistry *interceptor.Registry) error {
	return RegisterDefaultInterceptorsWithOptions(mediaEngine, interceptorRegistry)
}

func RegisterDefaultInterceptorsWithOptions(mediaEngine *MediaEngine, interceptorRegistry *interceptor.Registry,
	opts ...InterceptorOption,
) error {
	var options interceptorOptions
	for _, opt := range opts {
		opt(&options)
	}

	if options.loggerFactory != nil {

		options.nackGeneratorOptions = append(options.nackGeneratorOptions,
			nack.WithGeneratorLoggerFactory(options.loggerFactory))
		options.nackResponderOptions = append(options.nackResponderOptions,
			nack.WithResponderLoggerFactory(options.loggerFactory))
		options.reportReceiverOptions = append(options.reportReceiverOptions,
			report.WithReceiverLoggerFactory(options.loggerFactory))
		options.reportSenderOptions = append(options.reportSenderOptions,
			report.WithSenderLoggerFactory(options.loggerFactory))
		options.statsOptions = append(options.statsOptions, stats.WithLoggerFactory(options.loggerFactory))
		options.twccOptions = append(options.twccOptions, twcc.WithLoggerFactory(options.loggerFactory))
	}

	if err := ConfigureNackWithOptions(mediaEngine, interceptorRegistry, options.nackGeneratorOptions,
		options.nackResponderOptions...); err != nil {
		return err
	}

	if err := ConfigureRTCPReportsWithOptions(interceptorRegistry, options.reportReceiverOptions,
		options.reportSenderOptions...); err != nil {
		return err
	}

	if err := ConfigureSimulcastExtensionHeaders(mediaEngine); err != nil {
		return err
	}

	if err := ConfigureStatsInterceptorWithOptions(interceptorRegistry, options.statsOptions...); err != nil {
		return err
	}

	return ConfigureTWCCSenderWithOptions(mediaEngine, interceptorRegistry, options.twccOptions...)
}

func ConfigureStatsInterceptorWithOptions(interceptorRegistry *interceptor.Registry, opts ...stats.Option) error {
	statsInterceptor, err := stats.NewInterceptor(opts...)
	if err != nil {
		return err
	}
	statsInterceptor.OnNewPeerConnection(func(id string, stats stats.Getter) {
		statsGetter.Store(id, stats)
	})
	interceptorRegistry.Add(statsInterceptor)

	return nil
}

func lookupStats(id string) (stats.Getter, bool) {
	if value, exists := statsGetter.Load(id); exists {
		if getter, ok := value.(stats.Getter); ok {
			return getter, true
		}
	}

	return nil, false
}

func cleanupStats(id string) {
	statsGetter.Delete(id)
}

var statsGetter sync.Map

func ConfigureRTCPReportsWithOptions(interceptorRegistry *interceptor.Registry, recvOpts []report.ReceiverOption,
	sendOpts ...report.SenderOption,
) error {
	receiver, err := report.NewReceiverInterceptor(recvOpts...)
	if err != nil {
		return err
	}

	sender, err := report.NewSenderInterceptor(sendOpts...)
	if err != nil {
		return err
	}

	interceptorRegistry.Add(receiver)
	interceptorRegistry.Add(sender)

	return nil
}

func ConfigureNackWithOptions(mediaEngine *MediaEngine, interceptorRegistry *interceptor.Registry,
	genOpts []nack.GeneratorOption, respOpts ...nack.ResponderOption,
) error {
	generator, err := nack.NewGeneratorInterceptor(genOpts...)
	if err != nil {
		return err
	}

	responder, err := nack.NewResponderInterceptor(respOpts...)
	if err != nil {
		return err
	}

	mediaEngine.RegisterFeedback(RTCPFeedback{Type: "nack"}, RTPCodecTypeVideo)
	mediaEngine.RegisterFeedback(RTCPFeedback{Type: "nack", Parameter: "pli"}, RTPCodecTypeVideo)
	interceptorRegistry.Add(responder)
	interceptorRegistry.Add(generator)

	return nil
}

func ConfigureTWCCSenderWithOptions(mediaEngine *MediaEngine, interceptorRegistry *interceptor.Registry,
	opts ...twcc.Option,
) error {
	mediaEngine.RegisterFeedback(RTCPFeedback{Type: TypeRTCPFBTransportCC}, RTPCodecTypeVideo)
	if err := mediaEngine.RegisterHeaderExtension(
		RTPHeaderExtensionCapability{URI: sdp.TransportCCURI}, RTPCodecTypeVideo,
	); err != nil {
		return err
	}

	mediaEngine.RegisterFeedback(RTCPFeedback{Type: TypeRTCPFBTransportCC}, RTPCodecTypeAudio)
	if err := mediaEngine.RegisterHeaderExtension(
		RTPHeaderExtensionCapability{URI: sdp.TransportCCURI}, RTPCodecTypeAudio,
	); err != nil {
		return err
	}

	generator, err := twcc.NewSenderInterceptor(opts...)
	if err != nil {
		return err
	}

	interceptorRegistry.Add(generator)

	return nil
}

func ConfigureSimulcastExtensionHeaders(mediaEngine *MediaEngine) error {
	if err := mediaEngine.RegisterHeaderExtension(
		RTPHeaderExtensionCapability{URI: sdp.SDESMidURI}, RTPCodecTypeVideo,
	); err != nil {
		return err
	}

	if err := mediaEngine.RegisterHeaderExtension(
		RTPHeaderExtensionCapability{URI: sdp.SDESRTPStreamIDURI}, RTPCodecTypeVideo,
	); err != nil {
		return err
	}

	return mediaEngine.RegisterHeaderExtension(
		RTPHeaderExtensionCapability{URI: sdp.SDESRepairRTPStreamIDURI}, RTPCodecTypeVideo,
	)
}

type interceptorToTrackLocalWriter struct{ interceptor atomic.Value }

func (i *interceptorToTrackLocalWriter) WriteRTP(header *rtp.Header, payload []byte) (int, error) {
	if writer, ok := i.interceptor.Load().(interceptor.RTPWriter); ok && writer != nil {
		return writer.Write(header, payload, interceptor.Attributes{})
	}

	return 0, nil
}

func (i *interceptorToTrackLocalWriter) Write(b []byte) (int, error) {
	packet := &rtp.Packet{}
	if err := packet.Unmarshal(b); err != nil {
		return 0, err
	}

	return i.WriteRTP(&packet.Header, packet.Payload)
}

func createStreamInfo(
	id string,
	ssrc, ssrcRTX, ssrcFEC SSRC,
	payloadType, payloadTypeRTX, payloadTypeFEC PayloadType,
	codec RTPCodecCapability,
	webrtcHeaderExtensions []RTPHeaderExtensionParameter,
) *interceptor.StreamInfo {
	headerExtensions := make([]interceptor.RTPHeaderExtension, 0, len(webrtcHeaderExtensions))
	for _, h := range webrtcHeaderExtensions {
		headerExtensions = append(headerExtensions, interceptor.RTPHeaderExtension{ID: h.ID, URI: h.URI})
	}

	feedbacks := make([]interceptor.RTCPFeedback, 0, len(codec.RTCPFeedback))
	for _, f := range codec.RTCPFeedback {
		feedbacks = append(feedbacks, interceptor.RTCPFeedback{Type: f.Type, Parameter: f.Parameter})
	}

	return &interceptor.StreamInfo{
		ID:                                id,
		Attributes:                        interceptor.Attributes{},
		SSRC:                              uint32(ssrc),
		SSRCRetransmission:                uint32(ssrcRTX),
		SSRCForwardErrorCorrection:        uint32(ssrcFEC),
		PayloadType:                       uint8(payloadType),
		PayloadTypeRetransmission:         uint8(payloadTypeRTX),
		PayloadTypeForwardErrorCorrection: uint8(payloadTypeFEC),
		RTPHeaderExtensions:               headerExtensions,
		MimeType:                          codec.MimeType,
		ClockRate:                         codec.ClockRate,
		Channels:                          codec.Channels,
		SDPFmtpLine:                       codec.SDPFmtpLine,
		RTCPFeedback:                      feedbacks,
	}
}

type interceptorOptions struct {
	loggerFactory         logging.LoggerFactory
	nackGeneratorOptions  []nack.GeneratorOption
	nackResponderOptions  []nack.ResponderOption
	reportReceiverOptions []report.ReceiverOption
	reportSenderOptions   []report.SenderOption
	statsOptions          []stats.Option
	twccOptions           []twcc.Option
}

type InterceptorOption func(*interceptorOptions)

func WithInterceptorLoggerFactory(loggerFactory logging.LoggerFactory) InterceptorOption {
	return func(o *interceptorOptions) {
		o.loggerFactory = loggerFactory
	}
}

type mediaEngineHeaderExtension struct {
	uri               string
	isAudio, isVideo  bool
	allowedDirections []RTPTransceiverDirection
}

type MediaEngine struct {
	negotiatedVideo, negotiatedAudio             bool
	negotiateMultiCodecs                         bool
	videoCodecs, audioCodecs                     []RTPCodecParameters
	negotiatedVideoCodecs, negotiatedAudioCodecs []RTPCodecParameters
	headerExtensions                             []mediaEngineHeaderExtension
	negotiatedHeaderExtensions                   map[int]mediaEngineHeaderExtension
	mu                                           sync.RWMutex
}

func (m *MediaEngine) setMultiCodecNegotiation(negotiateMultiCodecs bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.negotiateMultiCodecs = negotiateMultiCodecs
}

func (m *MediaEngine) RegisterDefaultCodecs() error {
	if err := m.RegisterCodec(RTPCodecParameters{
		RTPCodecCapability: RTPCodecCapability{MimeTypeOpus, 48000, 2, "minptime=10;useinbandfec=1", nil},
		PayloadType:        111,
	}, RTPCodecTypeAudio); err != nil {
		return err
	}

	videoRTCPFeedback := []RTCPFeedback{{"goog-remb", ""}, {"ccm", "fir"}, {"nack", ""}, {"nack", "pli"}}
	for _, codec := range []RTPCodecParameters{
		{
			RTPCodecCapability: RTPCodecCapability{MimeTypeVP8, 90000, 0, "", videoRTCPFeedback},
			PayloadType:        96,
		},
		{
			RTPCodecCapability: RTPCodecCapability{MimeTypeRTX, 90000, 0, "apt=96", nil},
			PayloadType:        97,
		},
	} {
		if err := m.RegisterCodec(codec, RTPCodecTypeVideo); err != nil {
			return err
		}
	}

	return nil
}

func (m *MediaEngine) addCodec(codecs []RTPCodecParameters, codec RTPCodecParameters) ([]RTPCodecParameters, error) {
	for _, c := range codecs {
		if c.PayloadType == codec.PayloadType {
			if strings.EqualFold(c.MimeType, codec.MimeType) &&
				wutil.ClockRateEqual(c.MimeType, c.ClockRate, codec.ClockRate) &&
				wutil.ChannelsEqual(c.MimeType, c.Channels, codec.Channels) {
				return codecs, nil
			}

			return codecs, ErrCodecAlreadyRegistered
		}
	}

	return append(codecs, codec), nil
}

func (m *MediaEngine) RegisterCodec(codec RTPCodecParameters, typ RTPCodecType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var err error
	codec.statsID = fmt.Sprintf("RTPCodec-%d", time.Now().UnixNano())
	switch typ {
	case RTPCodecTypeAudio:
		m.audioCodecs, err = m.addCodec(m.audioCodecs, codec)
	case RTPCodecTypeVideo:
		m.videoCodecs, err = m.addCodec(m.videoCodecs, codec)
	default:
		return ErrUnknownType
	}

	return err
}

func (m *MediaEngine) RegisterHeaderExtension(
	extension RTPHeaderExtensionCapability,
	typ RTPCodecType,
	allowedDirections ...RTPTransceiverDirection,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.negotiatedHeaderExtensions == nil {
		m.negotiatedHeaderExtensions = map[int]mediaEngineHeaderExtension{}
	}

	if len(allowedDirections) == 0 {
		allowedDirections = []RTPTransceiverDirection{RTPTransceiverDirectionRecvonly, RTPTransceiverDirectionSendonly}
	}

	for _, direction := range allowedDirections {
		if direction != RTPTransceiverDirectionRecvonly && direction != RTPTransceiverDirectionSendonly {
			return ErrRegisterHeaderExtensionInvalidDirection
		}
	}

	extensionIndex := -1
	for i := range m.headerExtensions {
		if extension.URI == m.headerExtensions[i].uri {
			extensionIndex = i
		}
	}

	if extensionIndex == -1 {
		m.headerExtensions = append(m.headerExtensions, mediaEngineHeaderExtension{})
		extensionIndex = len(m.headerExtensions) - 1
	}

	switch typ {
	case RTPCodecTypeAudio:
		m.headerExtensions[extensionIndex].isAudio = true
	case RTPCodecTypeVideo:
		m.headerExtensions[extensionIndex].isVideo = true
	}

	m.headerExtensions[extensionIndex].uri = extension.URI
	m.headerExtensions[extensionIndex].allowedDirections = allowedDirections

	return nil
}

func (m *MediaEngine) RegisterFeedback(feedback RTCPFeedback, typ RTPCodecType) {
	m.mu.Lock()
	defer m.mu.Unlock()

	addUniqueFeedback := func(existing []RTCPFeedback) []RTCPFeedback {
		for _, f := range existing {
			if strings.EqualFold(f.Type, feedback.Type) && strings.EqualFold(f.Parameter, feedback.Parameter) {
				return existing
			}
		}

		return append(existing, feedback)
	}

	switch typ {
	case RTPCodecTypeVideo:
		for i, v := range m.videoCodecs {
			v.RTCPFeedback = addUniqueFeedback(v.RTCPFeedback)
			m.videoCodecs[i] = v
		}
	case RTPCodecTypeAudio:
		for i, v := range m.audioCodecs {
			v.RTCPFeedback = addUniqueFeedback(v.RTCPFeedback)
			m.audioCodecs[i] = v
		}
	default:
	}
}

func (m *MediaEngine) getHeaderExtensionID(extension RTPHeaderExtensionCapability) (
	val int,
	audioNegotiated, videoNegotiated bool,
) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.negotiatedHeaderExtensions == nil {
		return 0, false, false
	}

	for id, h := range m.negotiatedHeaderExtensions {
		if extension.URI == h.uri {
			return id, h.isAudio, h.isVideo
		}
	}

	return
}

func (m *MediaEngine) copy() *MediaEngine {
	m.mu.Lock()
	defer m.mu.Unlock()
	cloned := &MediaEngine{
		videoCodecs:      append([]RTPCodecParameters{}, m.videoCodecs...),
		audioCodecs:      append([]RTPCodecParameters{}, m.audioCodecs...),
		headerExtensions: append([]mediaEngineHeaderExtension{}, m.headerExtensions...),
	}
	if len(m.headerExtensions) > 0 {
		cloned.negotiatedHeaderExtensions = map[int]mediaEngineHeaderExtension{}
	}

	return cloned
}

func findCodecByPayload(codecs []RTPCodecParameters, payloadType PayloadType) *RTPCodecParameters {
	for _, codec := range codecs {
		if codec.PayloadType == payloadType {
			return &codec
		}
	}

	return nil
}

func (m *MediaEngine) getCodecByPayload(payloadType PayloadType) (RTPCodecParameters, RTPCodecType, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.negotiatedVideo {
		if codec := findCodecByPayload(m.negotiatedVideoCodecs, payloadType); codec != nil {
			return *codec, RTPCodecTypeVideo, nil
		}
	}
	if m.negotiatedAudio {
		if codec := findCodecByPayload(m.negotiatedAudioCodecs, payloadType); codec != nil {
			return *codec, RTPCodecTypeAudio, nil
		}
	}
	if !m.negotiatedVideo {
		if codec := findCodecByPayload(m.videoCodecs, payloadType); codec != nil {
			return *codec, RTPCodecTypeVideo, nil
		}
	}
	if !m.negotiatedAudio {
		if codec := findCodecByPayload(m.audioCodecs, payloadType); codec != nil {
			return *codec, RTPCodecTypeAudio, nil
		}
	}

	return RTPCodecParameters{}, 0, ErrCodecNotFound
}

func (m *MediaEngine) collectStats(collector *statsReportCollector) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statsLoop := func(codecs []RTPCodecParameters) {
		for _, codec := range codecs {
			collector.Collecting()
			stats := CodecStats{
				Timestamp:   statsTimestampFrom(time.Now()),
				Type:        StatsTypeCodec,
				ID:          codec.statsID,
				PayloadType: codec.PayloadType,
				MimeType:    codec.MimeType,
				ClockRate:   codec.ClockRate,
				Channels:    uint8(codec.Channels),
				SDPFmtpLine: codec.SDPFmtpLine,
			}

			collector.Collect(stats.ID, stats)
		}
	}

	statsLoop(m.videoCodecs)
	statsLoop(m.audioCodecs)
}

func (m *MediaEngine) matchRemoteCodec(
	remoteCodec RTPCodecParameters,
	typ RTPCodecType,
	exactMatches, partialMatches []RTPCodecParameters,
) (RTPCodecParameters, codecMatchType, error) {
	codecs := m.videoCodecs
	if typ == RTPCodecTypeAudio {
		codecs = m.audioCodecs
	}

	remoteFmtp := wutil.ParseFMTP(
		remoteCodec.RTPCodecCapability.MimeType,
		remoteCodec.RTPCodecCapability.ClockRate,
		remoteCodec.RTPCodecCapability.Channels,
		remoteCodec.RTPCodecCapability.SDPFmtpLine)

	if apt, hasApt := remoteFmtp.Parameter("apt"); hasApt {
		payloadType, err := strconv.ParseUint(apt, 10, 8)
		if err != nil {
			return RTPCodecParameters{}, codecMatchNone, err
		}

		aptMatch := codecMatchNone
		var aptCodec RTPCodecParameters
		for _, codec := range exactMatches {
			if codec.PayloadType == PayloadType(payloadType) {
				aptMatch = codecMatchExact
				aptCodec = codec

				break
			}
		}

		if aptMatch == codecMatchNone {
			for _, codec := range partialMatches {
				if codec.PayloadType == PayloadType(payloadType) {
					aptMatch = codecMatchPartial
					aptCodec = codec

					break
				}
			}
		}

		if aptMatch == codecMatchNone {
			return RTPCodecParameters{}, codecMatchNone, nil
		}

		toMatchCodec := remoteCodec
		if aptMatched, mt := codecParametersFuzzySearch(aptCodec, codecs); mt == aptMatch {
			toMatchCodec.SDPFmtpLine = strings.Replace(
				toMatchCodec.SDPFmtpLine,
				fmt.Sprintf("apt=%d", payloadType),
				fmt.Sprintf("apt=%d", aptMatched.PayloadType),
				1,
			)
		}

		localCodec, matchType := codecParametersFuzzySearch(toMatchCodec, codecs)
		if matchType == codecMatchExact && aptMatch == codecMatchPartial {
			matchType = codecMatchPartial
		}

		return localCodec, matchType, nil
	}

	localCodec, matchType := codecParametersFuzzySearch(remoteCodec, codecs)

	return localCodec, matchType, nil
}

func (m *MediaEngine) updateHeaderExtensionFromMediaSection(media *sdp.MediaDescription) error {
	var typ RTPCodecType
	switch {
	case strings.EqualFold(media.MediaName.Media, "audio"):
		typ = RTPCodecTypeAudio
	case strings.EqualFold(media.MediaName.Media, "video"):
		typ = RTPCodecTypeVideo
	default:
		return nil
	}
	extensions, err := rtpExtensionsFromMediaDescription(media)
	if err != nil {
		return err
	}

	for extension, id := range extensions {
		if err = m.updateHeaderExtension(id, extension, typ); err != nil {
			return err
		}
	}

	return nil
}

func (m *MediaEngine) updateHeaderExtension(id int, extension string, typ RTPCodecType) error {
	if m.negotiatedHeaderExtensions == nil {
		return nil
	}

	for _, localExtension := range m.headerExtensions {
		if localExtension.uri == extension {
			h := mediaEngineHeaderExtension{uri: extension, allowedDirections: localExtension.allowedDirections}
			if existingValue, ok := m.negotiatedHeaderExtensions[id]; ok {
				h = existingValue
			}

			switch {
			case localExtension.isAudio && typ == RTPCodecTypeAudio:
				h.isAudio = true
			case localExtension.isVideo && typ == RTPCodecTypeVideo:
				h.isVideo = true
			}

			m.negotiatedHeaderExtensions[id] = h
		}
	}

	return nil
}

func (m *MediaEngine) pushCodecs(codecs []RTPCodecParameters, typ RTPCodecType) error {
	var joinedErr error
	for _, codec := range codecs {
		var err error
		switch typ {
		case RTPCodecTypeAudio:
			m.negotiatedAudioCodecs, err = m.addCodec(m.negotiatedAudioCodecs, codec)
		case RTPCodecTypeVideo:
			m.negotiatedVideoCodecs, err = m.addCodec(m.negotiatedVideoCodecs, codec)
		}
		if err != nil {
			joinedErr = errors.Join(joinedErr, err)
		}
	}

	return joinedErr
}

func (m *MediaEngine) updateFromRemoteDescription(desc sdp.SessionDescription) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, media := range desc.MediaDescriptions {
		var typ RTPCodecType

		switch {
		case strings.EqualFold(media.MediaName.Media, "audio"):
			typ = RTPCodecTypeAudio
		case strings.EqualFold(media.MediaName.Media, "video"):
			typ = RTPCodecTypeVideo
		}

		switch {
		case !m.negotiatedAudio && typ == RTPCodecTypeAudio:
			m.negotiatedAudio = true
		case !m.negotiatedVideo && typ == RTPCodecTypeVideo:
			m.negotiatedVideo = true
		default:

			if err := m.updateHeaderExtensionFromMediaSection(media); err != nil {
				return err
			}

			if !m.negotiateMultiCodecs || (typ != RTPCodecTypeAudio && typ != RTPCodecTypeVideo) {
				continue
			}
		}

		codecs, err := codecsFromMediaDescription(media)
		if err != nil {
			return err
		}

		addIfNew := func(existingCodecs []RTPCodecParameters, codec RTPCodecParameters) []RTPCodecParameters {
			found := false
			for _, existingCodec := range existingCodecs {
				if existingCodec.PayloadType == codec.PayloadType {
					found = true

					break
				}
			}

			if !found {
				existingCodecs = append(existingCodecs, codec)
			}

			return existingCodecs
		}

		exactMatches := make([]RTPCodecParameters, 0, len(codecs))
		partialMatches := make([]RTPCodecParameters, 0, len(codecs))

		for _, remoteCodec := range codecs {
			localCodec, matchType, mErr := m.matchRemoteCodec(remoteCodec, typ, exactMatches, partialMatches)
			if mErr != nil {
				return mErr
			}

			remoteCodec.RTCPFeedback = rtcpFeedbackIntersection(localCodec.RTCPFeedback, remoteCodec.RTCPFeedback)

			switch matchType {
			case codecMatchExact:
				exactMatches = addIfNew(exactMatches, remoteCodec)
			case codecMatchPartial:
				partialMatches = addIfNew(partialMatches, remoteCodec)
			}
		}

		for _, remoteCodec := range codecs {
			localCodec, matchType, mErr := m.matchRemoteCodec(remoteCodec, typ, exactMatches, partialMatches)
			if mErr != nil {
				return mErr
			}

			remoteCodec.RTCPFeedback = rtcpFeedbackIntersection(localCodec.RTCPFeedback, remoteCodec.RTCPFeedback)

			switch matchType {
			case codecMatchExact:
				exactMatches = addIfNew(exactMatches, remoteCodec)
			case codecMatchPartial:
				partialMatches = addIfNew(partialMatches, remoteCodec)
			}
		}

		switch {
		case len(exactMatches) > 0:
			err = m.pushCodecs(exactMatches, typ)
		case len(partialMatches) > 0:
			err = m.pushCodecs(partialMatches, typ)
		default:

			continue
		}
		if err != nil {
			return err
		}

		if err := m.updateHeaderExtensionFromMediaSection(media); err != nil {
			return err
		}
	}

	return nil
}

func (m *MediaEngine) getCodecsByKind(typ RTPCodecType) []RTPCodecParameters {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch typ {
	case RTPCodecTypeVideo:
		if m.negotiatedVideo {
			return m.negotiatedVideoCodecs
		}

		return m.videoCodecs
	case RTPCodecTypeAudio:
		if m.negotiatedAudio {
			return m.negotiatedAudioCodecs
		}

		return m.audioCodecs
	}

	return nil
}

func (m *MediaEngine) getRTPParametersByKind(typ RTPCodecType, directions []RTPTransceiverDirection) RTPParameters {
	headerExtensions := make([]RTPHeaderExtensionParameter, 0)

	foundCodecs := m.getCodecsByKind(typ)

	m.mu.RLock()
	defer m.mu.RUnlock()

	if (m.negotiatedVideo && typ == RTPCodecTypeVideo) || (m.negotiatedAudio && typ == RTPCodecTypeAudio) {
		for id, e := range m.negotiatedHeaderExtensions {
			if haveRTPTransceiverDirectionIntersection(e.allowedDirections, directions) &&
				(e.isAudio && typ == RTPCodecTypeAudio || e.isVideo && typ == RTPCodecTypeVideo) {
				headerExtensions = append(headerExtensions, RTPHeaderExtensionParameter{ID: id, URI: e.uri})
			}
		}
	} else {
		mediaHeaderExtensions := make(map[int]mediaEngineHeaderExtension)
		for _, ext := range m.headerExtensions {
			usingNegotiatedID := false
			for id := range m.negotiatedHeaderExtensions {
				if m.negotiatedHeaderExtensions[id].uri == ext.uri {
					usingNegotiatedID = true
					mediaHeaderExtensions[id] = ext

					break
				}
			}
			if !usingNegotiatedID {
				for id := 1; id < 15; id++ {
					idAvailable := true
					if _, ok := mediaHeaderExtensions[id]; ok {
						idAvailable = false
					}
					if _, taken := m.negotiatedHeaderExtensions[id]; idAvailable && !taken {
						mediaHeaderExtensions[id] = ext

						break
					}
				}
			}
		}

		for id, e := range mediaHeaderExtensions {
			if haveRTPTransceiverDirectionIntersection(e.allowedDirections, directions) &&
				(e.isAudio && typ == RTPCodecTypeAudio || e.isVideo && typ == RTPCodecTypeVideo) {
				headerExtensions = append(headerExtensions, RTPHeaderExtensionParameter{ID: id, URI: e.uri})
			}
		}
	}

	return RTPParameters{
		HeaderExtensions: headerExtensions,
		Codecs:           foundCodecs,
	}
}

func (m *MediaEngine) getRTPParametersByPayloadType(payloadType PayloadType) (RTPParameters, error) {
	codec, typ, err := m.getCodecByPayload(payloadType)
	if err != nil {
		return RTPParameters{}, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	headerExtensions := make([]RTPHeaderExtensionParameter, 0)
	for id, e := range m.negotiatedHeaderExtensions {
		if e.isAudio && typ == RTPCodecTypeAudio || e.isVideo && typ == RTPCodecTypeVideo {
			headerExtensions = append(headerExtensions, RTPHeaderExtensionParameter{ID: id, URI: e.uri})
		}
	}

	return RTPParameters{
		HeaderExtensions: headerExtensions,
		Codecs:           []RTPCodecParameters{codec},
	}, nil
}

func payloaderForCodec(codec RTPCodecCapability) (rtp.Payloader, error) {
	switch strings.ToLower(codec.MimeType) {
	case strings.ToLower(MimeTypeOpus):
		return &codecs.OpusPayloader{}, nil
	case strings.ToLower(MimeTypeVP8):
		return &codecs.VP8Payloader{
			EnablePictureID: true,
		}, nil
	default:
		return nil, ErrNoPayloaderForCodec
	}
}

func (m *MediaEngine) isRTXEnabled(typ RTPCodecType, directions []RTPTransceiverDirection) bool {
	for _, p := range m.getRTPParametersByKind(typ, directions).Codecs {
		if strings.EqualFold(p.MimeType, MimeTypeRTX) {
			return true
		}
	}

	return false
}

func (m *MediaEngine) isFECEnabled(typ RTPCodecType, directions []RTPTransceiverDirection) bool {
	for _, p := range m.getRTPParametersByKind(typ, directions).Codecs {
		if strings.Contains(strings.ToLower(p.MimeType), MimeTypeFlexFEC) {
			return true
		}
	}

	return false
}

type PeerConnection struct {
	id                                      string
	mu                                      sync.RWMutex
	sdpOrigin                               sdp.Origin
	ops                                     *operations
	configuration                           Configuration
	currentLocalDescription                 *SessionDescription
	pendingLocalDescription                 *SessionDescription
	currentRemoteDescription                *SessionDescription
	pendingRemoteDescription                *SessionDescription
	signalingState                          SignalingState
	iceConnectionState                      atomic.Value
	connectionState                         atomic.Value
	idpLoginURL                             *string
	isClosed                                *atomic.Bool
	isGracefullyClosingOrClosed             bool
	isCloseDone                             chan struct{}
	isGracefulCloseDone                     chan struct{}
	isNegotiationNeeded                     *atomic.Bool
	updateNegotiationNeededFlagOnEmptyChain *atomic.Bool
	lastOffer                               string
	lastAnswer                              string
	canTrickleICECandidates                 ICETrickleCapability
	greaterMid                              int
	rtpTransceivers                         []*RTPTransceiver
	nonMediaBandwidthProbe                  atomic.Value
	onSignalingStateChangeHandler           func(SignalingState)
	onICEConnectionStateChangeHandler       atomic.Value
	onConnectionStateChangeHandler          atomic.Value
	onTrackHandler                          func(*TrackRemote, *RTPReceiver)
	onDataChannelHandler                    func(*DataChannel)
	onNegotiationNeededHandler              atomic.Value
	iceGatherer                             *ICEGatherer
	iceTransport                            *ICETransport
	dtlsTransport                           *DTLSTransport
	sctpTransport                           *SCTPTransport
	api                                     *API
	log                                     logging.LeveledLogger
	interceptorRTCPWriter                   interceptor.RTCPWriter
	statsGetter                             stats.Getter
}

func (api *API) NewPeerConnection(configuration Configuration) (*PeerConnection, error) {

	pc := &PeerConnection{
		id: fmt.Sprintf("PeerConnection-%d", time.Now().UnixNano()),
		configuration: Configuration{
			ICEServers:           []ICEServer{},
			ICETransportPolicy:   ICETransportPolicyAll,
			BundlePolicy:         BundlePolicyBalanced,
			RTCPMuxPolicy:        RTCPMuxPolicyRequire,
			Certificates:         []Certificate{},
			ICECandidatePoolSize: 0,
		},
		isClosed:                                &atomic.Bool{},
		isCloseDone:                             make(chan struct{}),
		isGracefulCloseDone:                     make(chan struct{}),
		isNegotiationNeeded:                     &atomic.Bool{},
		updateNegotiationNeededFlagOnEmptyChain: &atomic.Bool{},
		lastOffer:                               "",
		lastAnswer:                              "",
		greaterMid:                              -1,
		signalingState:                          SignalingStateStable,

		api: api,
		log: api.settingEngine.LoggerFactory.NewLogger("pc"),
	}
	pc.onDataChannelHandler = pc.defaultOnDataChannelHandler
	pc.ops = newOperations(pc.updateNegotiationNeededFlagOnEmptyChain, pc.onNegotiationNeeded)

	pc.iceConnectionState.Store(ICEConnectionStateNew)
	pc.connectionState.Store(PeerConnectionStateNew)

	i, err := api.interceptorRegistry.Build(pc.id)
	if err != nil {
		return nil, err
	}

	if getter, ok := lookupStats(pc.id); ok {
		pc.statsGetter = getter
	}

	pc.api = &API{
		settingEngine: api.settingEngine,
		interceptor:   i,
	}

	if api.settingEngine.disableMediaEngineCopy {
		pc.api.mediaEngine = api.mediaEngine
	} else {
		pc.api.mediaEngine = api.mediaEngine.copy()
		pc.api.mediaEngine.setMultiCodecNegotiation(!api.settingEngine.disableMediaEngineMultipleCodecs)
	}

	if err = pc.initConfiguration(configuration); err != nil {
		return nil, err
	}

	pc.iceGatherer, err = pc.createICEGatherer()
	if err != nil {
		return nil, err
	}

	iceTransport := pc.createICETransport()
	pc.iceTransport = iceTransport

	dtlsTransport, err := pc.api.NewDTLSTransport(pc.iceTransport, pc.configuration.Certificates)
	if err != nil {
		return nil, err
	}
	pc.dtlsTransport = dtlsTransport

	pc.sctpTransport = pc.api.NewSCTPTransport(pc.dtlsTransport)

	pc.sctpTransport.OnDataChannel(func(d *DataChannel) {
		pc.mu.RLock()
		handler := pc.onDataChannelHandler
		pc.mu.RUnlock()
		if handler != nil {
			handler(d)
		}
	})

	if pc.configuration.ICECandidatePoolSize > 0 {
		if err := pc.iceGatherer.Gather(); err != nil {
			return nil, err
		}
	}

	pc.interceptorRTCPWriter = pc.api.interceptor.BindRTCPWriter(interceptor.RTCPWriterFunc(pc.writeRTCP))

	return pc, nil
}

func (pc *PeerConnection) initConfiguration(configuration Configuration) error {
	if configuration.PeerIdentity != "" {
		pc.configuration.PeerIdentity = configuration.PeerIdentity
	}

	if len(configuration.Certificates) > 0 {
		now := time.Now()
		for _, x509Cert := range configuration.Certificates {
			if !x509Cert.Expires().IsZero() && now.After(x509Cert.Expires()) {
				return &InvalidAccessError{Err: ErrCertificateExpired}
			}
			pc.configuration.Certificates = append(pc.configuration.Certificates, x509Cert)
		}
	} else {
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return &UnknownError{Err: err}
		}
		certificate, err := GenerateCertificate(sk)
		if err != nil {
			return err
		}
		pc.configuration.Certificates = []Certificate{*certificate}
	}

	if configuration.BundlePolicy != BundlePolicyUnknown {
		pc.configuration.BundlePolicy = configuration.BundlePolicy
	}

	if configuration.RTCPMuxPolicy != RTCPMuxPolicyUnknown {
		pc.configuration.RTCPMuxPolicy = configuration.RTCPMuxPolicy
	}

	if configuration.ICECandidatePoolSize != 0 {

		if configuration.ICECandidatePoolSize > 1 {
			return &NotSupportedError{Err: errICECandidatePoolSizeTooLarge}
		}

		pc.configuration.ICECandidatePoolSize = configuration.ICECandidatePoolSize
	}

	pc.configuration.ICETransportPolicy = configuration.ICETransportPolicy
	pc.configuration.SDPSemantics = configuration.SDPSemantics
	pc.configuration.AlwaysNegotiateDataChannels = configuration.AlwaysNegotiateDataChannels

	sanitizedICEServers := configuration.getICEServers()
	if len(sanitizedICEServers) > 0 {
		for _, server := range sanitizedICEServers {
			if err := server.validate(); err != nil {
				return err
			}
		}
		pc.configuration.ICEServers = sanitizedICEServers
	}

	return nil
}

func (pc *PeerConnection) OnSignalingStateChange(f func(SignalingState)) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.onSignalingStateChangeHandler = f
}

func (pc *PeerConnection) onSignalingStateChange(newState SignalingState) {
	pc.mu.RLock()
	handler := pc.onSignalingStateChangeHandler
	pc.mu.RUnlock()

	pc.log.Infof("signaling state changed to %s", newState)
	if handler != nil {
		go handler(newState)
	}
}

func (pc *PeerConnection) OnDataChannel(f func(*DataChannel)) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if f == nil {
		pc.onDataChannelHandler = pc.defaultOnDataChannelHandler

		return
	}
	pc.onDataChannelHandler = f
}

func (pc *PeerConnection) defaultOnDataChannelHandler(d *DataChannel) {
	if d == nil {
		return
	}

	if err := d.Close(); err != nil {
		pc.log.Warnf("Failed to close undeclared DataChannel: %v", err)
	}
}

func (pc *PeerConnection) OnNegotiationNeeded(f func()) {
	pc.onNegotiationNeededHandler.Store(f)
}

func (pc *PeerConnection) onNegotiationNeeded() {

	if !pc.ops.IsEmpty() {
		pc.updateNegotiationNeededFlagOnEmptyChain.Store(true)

		return
	}
	pc.ops.Enqueue(pc.negotiationNeededOp)
}

func (pc *PeerConnection) negotiationNeededOp() {

	if pc.isClosed.Load() {
		return
	}

	if !pc.ops.IsEmpty() {
		pc.updateNegotiationNeededFlagOnEmptyChain.Store(true)

		return
	}

	if pc.SignalingState() != SignalingStateStable {
		return
	}

	if !pc.checkNegotiationNeeded() {
		pc.isNegotiationNeeded.Store(false)

		return
	}

	if pc.isNegotiationNeeded.Load() {
		return
	}

	pc.isNegotiationNeeded.Store(true)

	if handler, ok := pc.onNegotiationNeededHandler.Load().(func()); ok && handler != nil {
		handler()
	}
}

func (pc *PeerConnection) checkNegotiationNeeded() bool {

	pc.mu.Lock()
	defer pc.mu.Unlock()

	localDesc := pc.currentLocalDescription
	remoteDesc := pc.currentRemoteDescription

	if localDesc == nil {
		return true
	}

	pc.sctpTransport.lock.Lock()
	lenDataChannel := len(pc.sctpTransport.dataChannels)
	pc.sctpTransport.lock.Unlock()

	if lenDataChannel != 0 && haveDataChannel(localDesc) == nil {
		return true
	}

	for _, transceiver := range pc.rtpTransceivers {

		mid := getByMid(transceiver.Mid(), localDesc)

		if mid == nil {
			return true
		}

		if transceiver.Direction() == RTPTransceiverDirectionSendrecv ||
			transceiver.Direction() == RTPTransceiverDirectionSendonly {
			descMsid, okMsid := mid.Attribute(sdp.AttrKeyMsid)
			sender := transceiver.Sender()
			if sender == nil {
				return true
			}
			track := sender.Track()
			if track == nil {

				continue
			}
			if !okMsid || descMsid != track.StreamID()+" "+track.ID() {
				return true
			}
		}
		switch localDesc.Type {
		case SDPTypeOffer:

			rm := getByMid(transceiver.Mid(), remoteDesc)
			if rm == nil {
				return true
			}

			if getPeerDirection(mid) != transceiver.Direction() && getPeerDirection(rm) != transceiver.Direction().Revers() {
				return true
			}
		case SDPTypeAnswer:

			if _, ok := mid.Attribute(transceiver.Direction().String()); !ok {
				return true
			}
		default:
		}

	}

	return false
}

func (pc *PeerConnection) OnICECandidate(f func(*ICECandidate)) {
	pc.iceGatherer.OnLocalCandidate(f)
}

func (pc *PeerConnection) OnICEGatheringStateChange(f func(ICEGatheringState)) {
	pc.iceGatherer.OnStateChange(
		func(gathererState ICEGathererState) {
			switch gathererState {
			case ICEGathererStateGathering:
				f(ICEGatheringStateGathering)
			case ICEGathererStateComplete:
				f(ICEGatheringStateComplete)
			default:

			}
		})
}

func (pc *PeerConnection) OnTrack(f func(*TrackRemote, *RTPReceiver)) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.onTrackHandler = f
}

func (pc *PeerConnection) onTrack(t *TrackRemote, r *RTPReceiver) {
	pc.mu.RLock()
	handler := pc.onTrackHandler
	pc.mu.RUnlock()

	pc.log.Debugf("got new track: %+v", t)
	if t != nil {
		if handler != nil {
			go handler(t, r)
		} else {
			pc.log.Warnf("OnTrack unset, unable to handle incoming media streams")
		}
	}
}

func (pc *PeerConnection) OnICEConnectionStateChange(f func(ICEConnectionState)) {
	pc.onICEConnectionStateChangeHandler.Store(f)
}

func (pc *PeerConnection) onICEConnectionStateChange(cs ICEConnectionState) {
	pc.iceConnectionState.Store(cs)
	pc.log.Infof("ICE connection state changed: %s", cs)
	if handler, ok := pc.onICEConnectionStateChangeHandler.Load().(func(ICEConnectionState)); ok && handler != nil {
		handler(cs)
	}
}

func (pc *PeerConnection) OnConnectionStateChange(f func(PeerConnectionState)) {
	pc.onConnectionStateChangeHandler.Store(f)
}

func (pc *PeerConnection) onConnectionStateChange(cs PeerConnectionState) {
	pc.connectionState.Store(cs)
	pc.log.Infof("peer connection state changed: %s", cs)
	if handler, ok := pc.onConnectionStateChangeHandler.Load().(func(PeerConnectionState)); ok && handler != nil {
		go handler(cs)
	}
}

func (pc *PeerConnection) SetConfiguration(configuration Configuration) error {

	if pc.isClosed.Load() {
		return &InvalidStateError{Err: ErrConnectionClosed}
	}

	if configuration.PeerIdentity != "" {
		if configuration.PeerIdentity != pc.configuration.PeerIdentity {
			return &InvalidModificationError{Err: ErrModifyingPeerIdentity}
		}
		pc.configuration.PeerIdentity = configuration.PeerIdentity
	}

	if len(configuration.Certificates) > 0 {
		if len(configuration.Certificates) != len(pc.configuration.Certificates) {
			return &InvalidModificationError{Err: ErrModifyingCertificates}
		}

		for i, certificate := range configuration.Certificates {
			if !pc.configuration.Certificates[i].Equals(certificate) {
				return &InvalidModificationError{Err: ErrModifyingCertificates}
			}
		}
		pc.configuration.Certificates = configuration.Certificates
	}

	if configuration.BundlePolicy != BundlePolicyUnknown {
		if configuration.BundlePolicy != pc.configuration.BundlePolicy {
			return &InvalidModificationError{Err: ErrModifyingBundlePolicy}
		}
		pc.configuration.BundlePolicy = configuration.BundlePolicy
	}

	if configuration.RTCPMuxPolicy != RTCPMuxPolicyUnknown {
		if configuration.RTCPMuxPolicy != pc.configuration.RTCPMuxPolicy {
			return &InvalidModificationError{Err: ErrModifyingRTCPMuxPolicy}
		}
		pc.configuration.RTCPMuxPolicy = configuration.RTCPMuxPolicy
	}

	if configuration.ICECandidatePoolSize != 0 {
		if pc.configuration.ICECandidatePoolSize != configuration.ICECandidatePoolSize &&
			pc.LocalDescription() != nil {
			return &InvalidModificationError{Err: ErrModifyingICECandidatePoolSize}
		}

		pc.log.Warn("Changing ICECandidatePoolSize is not yet supported. The new value will be ignored.")
	}

	for _, server := range configuration.ICEServers {
		if err := server.validate(); err != nil {
			return err
		}
	}

	pc.configuration.ICETransportPolicy = configuration.ICETransportPolicy

	if configuration.AlwaysNegotiateDataChannels {
		pc.configuration.AlwaysNegotiateDataChannels = configuration.AlwaysNegotiateDataChannels
	}

	if pc.configuration.ICECandidatePoolSize != configuration.ICECandidatePoolSize {
		pc.log.Warn("Dynamic ICE candidate pool adjustment is not yet supported")
	}

	if pc.iceGatherer != nil {
		if err := pc.iceGatherer.updateServers(configuration.ICEServers, pc.configuration.ICETransportPolicy); err != nil {
			pc.log.Debugf("Could not update ICE gatherer servers: %v", err)
		}
	}

	pc.configuration.ICEServers = configuration.ICEServers

	return nil
}

func (pc *PeerConnection) GetConfiguration() Configuration {
	return pc.configuration
}

func (pc *PeerConnection) ID() string {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	return pc.id
}

func (pc *PeerConnection) hasLocalDescriptionChanged(desc *SessionDescription) bool {
	for _, t := range pc.rtpTransceivers {
		m := getByMid(t.Mid(), desc)
		if m == nil {
			return true
		}

		if getPeerDirection(m) != t.Direction() {
			return true
		}
	}

	return false
}

func (pc *PeerConnection) CreateOffer(options *OfferOptions) (SessionDescription, error) {
	useIdentity := pc.idpLoginURL != nil
	switch {
	case useIdentity:
		return SessionDescription{}, errIdentityProviderNotImplemented
	case pc.isClosed.Load():
		return SessionDescription{}, &InvalidStateError{Err: ErrConnectionClosed}
	}

	if options != nil && options.ICERestart {
		if err := pc.iceTransport.restart(); err != nil {
			return SessionDescription{}, err
		}
	}

	var (
		descr *sdp.SessionDescription
		offer SessionDescription
		err   error
	)

	count := 0
	pc.mu.Lock()
	defer pc.mu.Unlock()
	for {

		currentTransceivers := pc.rtpTransceivers

		isPlanB := pc.configuration.SDPSemantics == SDPSemanticsPlanB
		if pc.currentRemoteDescription != nil && isPlanB {
			isPlanB = descriptionPossiblyPlanB(pc.currentRemoteDescription)
		}

		if !isPlanB {

			if pc.currentRemoteDescription != nil {
				var numericMid int
				for _, media := range pc.currentRemoteDescription.parsed.MediaDescriptions {
					mid := getMidValue(media)
					if mid == "" {
						continue
					}
					numericMid, err = strconv.Atoi(mid)
					if err != nil {
						continue
					}
					if numericMid > pc.greaterMid {
						pc.greaterMid = numericMid
					}
				}
			}
			for _, t := range currentTransceivers {
				if mid := t.Mid(); mid != "" {
					numericMid, errMid := strconv.Atoi(mid)
					if errMid == nil {
						if numericMid > pc.greaterMid {
							pc.greaterMid = numericMid
						}
					}

					continue
				}
				pc.greaterMid++
				err = t.SetMid(strconv.Itoa(pc.greaterMid))
				if err != nil {
					return SessionDescription{}, err
				}
			}
		}

		if pc.currentRemoteDescription == nil {
			descr, err = pc.generateUnmatchedSDP(currentTransceivers, useIdentity)
		} else {
			descr, err = pc.generateMatchedSDP(
				currentTransceivers,
				useIdentity,
				true,
				connectionRoleFromDtlsRole(defaultDtlsRoleOffer),
				false,
			)
		}

		if err != nil {
			return SessionDescription{}, err
		}

		if options != nil && options.ICETricklingSupported {
			descr.WithICETrickleAdvertised()
		}
		if pc.api.settingEngine.renomination.enabled {
			descr.WithICERenomination()
		}

		updateSDPOrigin(&pc.sdpOrigin, descr)
		sdpBytes, err := descr.Marshal()
		if err != nil {
			return SessionDescription{}, err
		}

		offer = SessionDescription{
			Type:   SDPTypeOffer,
			SDP:    string(sdpBytes),
			parsed: descr,
		}

		if isPlanB || !pc.hasLocalDescriptionChanged(&offer) {
			break
		}
		count++
		if count >= 128 {
			return SessionDescription{}, errExcessiveRetries
		}
	}

	pc.lastOffer = offer.SDP

	return offer, nil
}

func (pc *PeerConnection) createICEGatherer() (*ICEGatherer, error) {
	g, err := pc.api.NewICEGatherer(ICEGatherOptions{
		ICEServers:           pc.configuration.getICEServers(),
		ICEGatherPolicy:      pc.configuration.ICETransportPolicy,
		ICECandidatePoolSize: pc.configuration.ICECandidatePoolSize,
	})
	if err != nil {
		return nil, err
	}

	return g, nil
}

func (pc *PeerConnection) updateConnectionState(
	iceConnectionState ICEConnectionState,
	dtlsTransportState DTLSTransportState,
) {
	connectionState := PeerConnectionStateNew
	switch {

	case pc.isClosed.Load():
		connectionState = PeerConnectionStateClosed

	case iceConnectionState == ICEConnectionStateFailed || dtlsTransportState == DTLSTransportStateFailed:
		connectionState = PeerConnectionStateFailed

	case iceConnectionState == ICEConnectionStateDisconnected:
		connectionState = PeerConnectionStateDisconnected

	case (iceConnectionState == ICEConnectionStateNew || iceConnectionState == ICEConnectionStateClosed) &&
		(dtlsTransportState == DTLSTransportStateNew || dtlsTransportState == DTLSTransportStateClosed):
		connectionState = PeerConnectionStateNew

	case (iceConnectionState == ICEConnectionStateNew || iceConnectionState == ICEConnectionStateChecking) ||
		(dtlsTransportState == DTLSTransportStateNew || dtlsTransportState == DTLSTransportStateConnecting):
		connectionState = PeerConnectionStateConnecting

	case (iceConnectionState == ICEConnectionStateConnected ||
		iceConnectionState == ICEConnectionStateCompleted || iceConnectionState == ICEConnectionStateClosed) &&
		(dtlsTransportState == DTLSTransportStateConnected || dtlsTransportState == DTLSTransportStateClosed):
		connectionState = PeerConnectionStateConnected
	}

	if pc.connectionState.Load() == connectionState {
		return
	}

	pc.onConnectionStateChange(connectionState)
}

func (pc *PeerConnection) createICETransport() *ICETransport {
	transport := pc.api.NewICETransport(pc.iceGatherer)
	transport.internalOnConnectionStateChangeHandler.Store(func(state ICETransportState) {
		var cs ICEConnectionState
		switch state {
		case ICETransportStateNew:
			cs = ICEConnectionStateNew
		case ICETransportStateChecking:
			cs = ICEConnectionStateChecking
		case ICETransportStateConnected:
			cs = ICEConnectionStateConnected
		case ICETransportStateCompleted:
			cs = ICEConnectionStateCompleted
		case ICETransportStateFailed:
			cs = ICEConnectionStateFailed
		case ICETransportStateDisconnected:
			cs = ICEConnectionStateDisconnected
		case ICETransportStateClosed:
			cs = ICEConnectionStateClosed
		default:
			pc.log.Warnf("OnConnectionStateChange: unhandled ICE state: %s", state)

			return
		}
		pc.onICEConnectionStateChange(cs)
		pc.updateConnectionState(cs, pc.dtlsTransport.State())
	})

	return transport
}

func (pc *PeerConnection) CreateAnswer(options *AnswerOptions) (SessionDescription, error) {
	useIdentity := pc.idpLoginURL != nil
	remoteDesc := pc.RemoteDescription()
	switch {
	case remoteDesc == nil:
		return SessionDescription{}, &InvalidStateError{Err: ErrNoRemoteDescription}
	case useIdentity:
		return SessionDescription{}, errIdentityProviderNotImplemented
	case pc.isClosed.Load():
		return SessionDescription{}, &InvalidStateError{Err: ErrConnectionClosed}
	case pc.signalingState.Get() != SignalingStateHaveRemoteOffer &&
		pc.signalingState.Get() != SignalingStateHaveLocalPranswer:
		return SessionDescription{}, &InvalidStateError{Err: ErrIncorrectSignalingState}
	}

	connectionRole := connectionRoleFromDtlsRole(pc.api.settingEngine.answeringDTLSRole)
	if connectionRole == sdp.ConnectionRole(0) {
		dtlsRole := dtlsRoleFromSDP(remoteDesc.parsed)
		switch dtlsRole {
		case DTLSRoleClient:
			connectionRole = connectionRoleFromDtlsRole(DTLSRoleServer)
		case DTLSRoleServer:
			connectionRole = connectionRoleFromDtlsRole(DTLSRoleClient)
		default:
			connectionRole = connectionRoleFromDtlsRole(defaultDtlsRoleAnswer)
		}

		if isIceLiteSet(remoteDesc.parsed) && !pc.api.settingEngine.candidates.ICELite {
			connectionRole = connectionRoleFromDtlsRole(DTLSRoleServer)
		}
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()

	descr, err := pc.generateMatchedSDP(
		pc.rtpTransceivers,
		useIdentity,
		false,
		connectionRole,
		pc.api.settingEngine.ignoreRidPauseForRecv,
	)
	if err != nil {
		return SessionDescription{}, err
	}

	if options != nil && options.ICETricklingSupported {
		descr.WithICETrickleAdvertised()
	}
	if pc.api.settingEngine.renomination.enabled {
		descr.WithICERenomination()
	}

	updateSDPOrigin(&pc.sdpOrigin, descr)
	sdpBytes, err := descr.Marshal()
	if err != nil {
		return SessionDescription{}, err
	}

	desc := SessionDescription{
		Type:   SDPTypeAnswer,
		SDP:    string(sdpBytes),
		parsed: descr,
	}
	pc.lastAnswer = desc.SDP

	return desc, nil
}

func (pc *PeerConnection) setDescription(sd *SessionDescription, op stateChangeOp) error {
	switch {
	case pc.isClosed.Load():
		return &InvalidStateError{Err: ErrConnectionClosed}
	case NewSDPType(sd.Type.String()) == SDPTypeUnknown:
		return &TypeError{
			Err: fmt.Errorf("%w: '%d' is not a valid enum value of type SDPType", errPeerConnSDPTypeInvalidValue, sd.Type),
		}
	}

	nextState, err := func() (SignalingState, error) {
		pc.mu.Lock()
		defer pc.mu.Unlock()

		cur := pc.SignalingState()
		setLocal := stateChangeOpSetLocal
		setRemote := stateChangeOpSetRemote
		newSDPDoesNotMatchOffer := &InvalidModificationError{Err: errSDPDoesNotMatchOffer}
		newSDPDoesNotMatchAnswer := &InvalidModificationError{Err: errSDPDoesNotMatchAnswer}

		var nextState SignalingState
		var err error
		switch op {
		case setLocal:
			switch sd.Type {

			case SDPTypeOffer:
				if sd.SDP != pc.lastOffer {
					return nextState, newSDPDoesNotMatchOffer
				}
				nextState, err = checkNextSignalingState(cur, SignalingStateHaveLocalOffer, setLocal, sd.Type)
				if err == nil {
					pc.pendingLocalDescription = sd
				}

			case SDPTypeAnswer:
				if sd.SDP != pc.lastAnswer {
					return nextState, newSDPDoesNotMatchAnswer
				}
				nextState, err = checkNextSignalingState(cur, SignalingStateStable, setLocal, sd.Type)
				if err == nil {
					pc.currentLocalDescription = sd
					pc.currentRemoteDescription = pc.pendingRemoteDescription
					pc.pendingRemoteDescription = nil
					pc.pendingLocalDescription = nil
				}
			case SDPTypeRollback:
				nextState, err = checkNextSignalingState(cur, SignalingStateStable, setLocal, sd.Type)
				if err == nil {
					pc.pendingLocalDescription = nil
				}

			case SDPTypePranswer:
				if sd.SDP != pc.lastAnswer {
					return nextState, newSDPDoesNotMatchAnswer
				}
				nextState, err = checkNextSignalingState(cur, SignalingStateHaveLocalPranswer, setLocal, sd.Type)
				if err == nil {
					pc.pendingLocalDescription = sd
				}
			default:
				return nextState, &OperationError{Err: fmt.Errorf("%w: %s(%s)", errPeerConnStateChangeInvalid, op, sd.Type)}
			}
		case setRemote:
			switch sd.Type {

			case SDPTypeOffer:
				nextState, err = checkNextSignalingState(cur, SignalingStateHaveRemoteOffer, setRemote, sd.Type)
				if err == nil {
					pc.pendingRemoteDescription = sd
				}

			case SDPTypeAnswer:
				nextState, err = checkNextSignalingState(cur, SignalingStateStable, setRemote, sd.Type)
				if err == nil {
					pc.currentRemoteDescription = sd
					pc.currentLocalDescription = pc.pendingLocalDescription
					pc.pendingRemoteDescription = nil
					pc.pendingLocalDescription = nil
				}
			case SDPTypeRollback:
				nextState, err = checkNextSignalingState(cur, SignalingStateStable, setRemote, sd.Type)
				if err == nil {
					pc.pendingRemoteDescription = nil
				}

			case SDPTypePranswer:
				nextState, err = checkNextSignalingState(cur, SignalingStateHaveRemotePranswer, setRemote, sd.Type)
				if err == nil {
					pc.pendingRemoteDescription = sd
				}
			default:
				return nextState, &OperationError{Err: fmt.Errorf("%w: %s(%s)", errPeerConnStateChangeInvalid, op, sd.Type)}
			}
		default:
			return nextState, &OperationError{Err: fmt.Errorf("%w: %q", errPeerConnStateChangeUnhandled, op)}
		}

		return nextState, err
	}()

	if err == nil {
		pc.signalingState.Set(nextState)
		if pc.signalingState.Get() == SignalingStateStable {
			pc.isNegotiationNeeded.Store(false)
			pc.mu.Lock()
			pc.onNegotiationNeeded()
			pc.mu.Unlock()
		}
		pc.onSignalingStateChange(nextState)
	}

	return err
}

func (pc *PeerConnection) SetLocalDescription(desc SessionDescription) error {
	if pc.isClosed.Load() {
		return &InvalidStateError{Err: ErrConnectionClosed}
	}

	haveLocalDescription := pc.currentLocalDescription != nil

	if desc.SDP == "" {
		switch desc.Type {
		case SDPTypeAnswer, SDPTypePranswer:
			desc.SDP = pc.lastAnswer
		case SDPTypeOffer:
			desc.SDP = pc.lastOffer
		default:
			return &InvalidModificationError{
				Err: fmt.Errorf("%w: %s", errPeerConnSDPTypeInvalidValueSetLocalDescription, desc.Type),
			}
		}
	}

	desc.parsed = &sdp.SessionDescription{}
	if err := desc.parsed.UnmarshalString(desc.SDP); err != nil {
		return err
	}
	if err := pc.setDescription(&desc, stateChangeOpSetLocal); err != nil {
		return err
	}

	currentTransceivers := append([]*RTPTransceiver{}, pc.GetTransceivers()...)

	weAnswer := desc.Type == SDPTypeAnswer
	remoteDesc := pc.RemoteDescription()
	if weAnswer && remoteDesc != nil {
		_ = setRTPTransceiverCurrentDirection(&desc, currentTransceivers, false)
		if err := pc.startRTPSenders(currentTransceivers); err != nil {
			return err
		}
		pc.configureRTPReceivers(haveLocalDescription, remoteDesc, currentTransceivers)
		pc.ops.Enqueue(func() {
			pc.startRTP(haveLocalDescription, remoteDesc, currentTransceivers)
		})
	}

	mediaSection, ok := selectCandidateMediaSection(desc.parsed)
	if ok {
		pc.iceGatherer.setMediaStreamIdentification(mediaSection.SDPMid, mediaSection.SDPMLineIndex)
	}

	pc.iceGatherer.flushCandidates()

	if pc.iceGatherer.State() == ICEGathererStateNew {
		return pc.iceGatherer.Gather()
	}

	return nil
}

func (pc *PeerConnection) LocalDescription() *SessionDescription {
	if pendingLocalDescription := pc.PendingLocalDescription(); pendingLocalDescription != nil {
		return pendingLocalDescription
	}

	return pc.CurrentLocalDescription()
}

func (pc *PeerConnection) SetRemoteDescription(desc SessionDescription) error {
	if pc.isClosed.Load() {
		return &InvalidStateError{Err: ErrConnectionClosed}
	}

	isRenegotiation := pc.currentRemoteDescription != nil

	if _, err := desc.Unmarshal(); err != nil {
		return err
	}

	if err := pc.setDescription(&desc, stateChangeOpSetRemote); err != nil {
		return err
	}

	if err := pc.api.mediaEngine.updateFromRemoteDescription(*desc.parsed); err != nil {
		return err
	}

	canTrickle := hasICETrickleOption(desc.parsed)
	pc.mu.Lock()
	switch desc.Type {
	case SDPTypeOffer, SDPTypeAnswer, SDPTypePranswer:
		if canTrickle {
			pc.canTrickleICECandidates = ICETrickleCapabilitySupported
		} else {
			pc.canTrickleICECandidates = ICETrickleCapabilityUnsupported
		}
	default:
		pc.canTrickleICECandidates = ICETrickleCapabilityUnknown
	}
	pc.mu.Unlock()

	for _, sender := range pc.GetSenders() {
		sender.configureRTXAndFEC()
	}

	var transceiver *RTPTransceiver
	localTransceivers := append([]*RTPTransceiver{}, pc.GetTransceivers()...)
	detectedPlanB := descriptionIsPlanB(pc.RemoteDescription(), pc.log)
	if pc.configuration.SDPSemantics != SDPSemanticsUnifiedPlan {
		detectedPlanB = descriptionPossiblyPlanB(pc.RemoteDescription())
	}

	weOffer := desc.Type == SDPTypeAnswer

	if !weOffer && !detectedPlanB {
		for _, media := range pc.RemoteDescription().parsed.MediaDescriptions {
			midValue := getMidValue(media)
			if midValue == "" {
				return errPeerConnRemoteDescriptionWithoutMidValue
			}

			if media.MediaName.Media == mediaSectionApplication {
				continue
			}

			kind := NewRTPCodecType(media.MediaName.Media)
			direction := getPeerDirection(media)
			if kind == 0 || direction == RTPTransceiverDirectionUnknown {
				continue
			}

			transceiver, localTransceivers = findByMid(midValue, localTransceivers)
			if transceiver == nil {
				transceiver, localTransceivers = satisfyTypeAndDirection(kind, direction, localTransceivers)
			} else if direction == RTPTransceiverDirectionInactive {
				if err := transceiver.Stop(); err != nil {
					return err
				}
			}
			if transceiver != nil {
				transceiver.setCurrentRemoteDirection(direction)
			}

			switch {
			case transceiver == nil:
				receiver, err := pc.api.NewRTPReceiver(kind, pc.dtlsTransport)
				if err != nil {
					return err
				}

				localDirection := RTPTransceiverDirectionRecvonly
				switch direction {
				case RTPTransceiverDirectionRecvonly:
					localDirection = RTPTransceiverDirectionSendonly
				case RTPTransceiverDirectionInactive:
					localDirection = RTPTransceiverDirectionInactive
				}

				transceiver = newRTPTransceiver(receiver, nil, localDirection, kind, pc.api)
				transceiver.setCurrentRemoteDirection(direction)
				transceiver.setCodecPreferencesFromRemoteDescription(media)
				pc.mu.Lock()
				pc.addRTPTransceiver(transceiver)
				pc.mu.Unlock()

			case direction == RTPTransceiverDirectionRecvonly:
				if transceiver.Direction() == RTPTransceiverDirectionSendrecv {
					transceiver.setDirection(RTPTransceiverDirectionSendonly)
				} else if transceiver.Direction() == RTPTransceiverDirectionRecvonly {
					transceiver.setDirection(RTPTransceiverDirectionInactive)
				}
			case direction == RTPTransceiverDirectionSendrecv:
				if transceiver.Direction() == RTPTransceiverDirectionSendonly {
					transceiver.setDirection(RTPTransceiverDirectionSendrecv)
				} else if transceiver.Direction() == RTPTransceiverDirectionInactive {
					transceiver.setDirection(RTPTransceiverDirectionRecvonly)
				}
			case direction == RTPTransceiverDirectionSendonly:
				if transceiver.Direction() == RTPTransceiverDirectionInactive {
					transceiver.setDirection(RTPTransceiverDirectionRecvonly)
				}
			}

			if transceiver.Mid() == "" {
				if err := transceiver.SetMid(midValue); err != nil {
					return err
				}
			}
		}
	}

	iceDetails, err := extractICEDetails(desc.parsed, pc.log)
	if err != nil {
		return err
	}

	if isRenegotiation && pc.iceTransport.haveRemoteCredentialsChange(iceDetails.Ufrag, iceDetails.Password) {

		if !weOffer {
			if err = pc.iceTransport.restart(); err != nil {
				return err
			}
		}

		if err = pc.iceTransport.setRemoteCredentials(iceDetails.Ufrag, iceDetails.Password); err != nil {
			return err
		}
	}

	for i := range iceDetails.Candidates {
		if err = pc.iceTransport.AddRemoteCandidate(&iceDetails.Candidates[i]); err != nil {
			return err
		}
	}

	currentTransceivers := append([]*RTPTransceiver{}, pc.GetTransceivers()...)

	if isRenegotiation {
		if weOffer {
			_ = setRTPTransceiverCurrentDirection(&desc, currentTransceivers, true)
			if err = pc.startRTPSenders(currentTransceivers); err != nil {
				return err
			}
			pc.configureRTPReceivers(true, &desc, currentTransceivers)
			pc.ops.Enqueue(func() {
				pc.startRTP(true, &desc, currentTransceivers)
			})
		}

		return nil
	}

	remoteIsLite := isIceLiteSet(desc.parsed)

	fingerprint, fingerprintHash, err := extractFingerprint(desc.parsed)
	if err != nil {
		return err
	}

	iceRole := ICERoleControlled

	if (weOffer && remoteIsLite == pc.api.settingEngine.candidates.ICELite) ||
		(remoteIsLite && !pc.api.settingEngine.candidates.ICELite) {
		iceRole = ICERoleControlling
	}

	if weOffer {
		_ = setRTPTransceiverCurrentDirection(&desc, currentTransceivers, true)
		if err := pc.startRTPSenders(currentTransceivers); err != nil {
			return err
		}

		pc.configureRTPReceivers(false, &desc, currentTransceivers)
	}

	pc.ops.Enqueue(func() {
		pc.startTransports(
			iceRole,
			dtlsRoleFromSDP(desc.parsed),
			iceDetails.Ufrag,
			iceDetails.Password,
			fingerprint,
			fingerprintHash,
		)
		if weOffer {
			pc.startRTP(false, &desc, currentTransceivers)
		}
	})

	return nil
}

func (pc *PeerConnection) configureReceiver(incoming trackDetails, receiver *RTPReceiver) {
	receiver.configureReceive(trackDetailsToRTPReceiveParameters(&incoming))

	for i := range receiver.tracks {
		receiver.tracks[i].track.mu.Lock()
		receiver.tracks[i].track.id = incoming.id
		receiver.tracks[i].track.streamID = incoming.streamID
		receiver.tracks[i].track.mu.Unlock()
	}
}

func (pc *PeerConnection) startReceiver(incoming trackDetails, receiver *RTPReceiver) {
	if err := receiver.startReceive(trackDetailsToRTPReceiveParameters(&incoming)); err != nil {
		pc.log.Warnf("RTPReceiver Receive failed %s", err)

		return
	}

	for _, track := range receiver.Tracks() {
		if track.SSRC() == 0 || track.RID() != "" {
			return
		}

		if pc.api.settingEngine.fireOnTrackBeforeFirstRTP {
			pc.onTrack(track, receiver)

			return
		}
		go func(track *TrackRemote) {
			b := make([]byte, pc.api.settingEngine.getReceiveMTU())
			n, _, err := track.peek(b)
			if err != nil {
				pc.log.Warnf("Could not determine PayloadType for SSRC %d (%s)", track.SSRC(), err)

				return
			}

			if err = track.checkAndUpdateTrack(b[:n]); err != nil {
				pc.log.Warnf("Failed to set codec settings for track SSRC %d (%s)", track.SSRC(), err)

				return
			}

			pc.onTrack(track, receiver)
		}(track)
	}
}

func setRTPTransceiverCurrentDirection(
	answer *SessionDescription,
	currentTransceivers []*RTPTransceiver,
	weOffer bool,
) error {
	currentTransceivers = append([]*RTPTransceiver{}, currentTransceivers...)
	for _, media := range answer.parsed.MediaDescriptions {
		midValue := getMidValue(media)
		if midValue == "" {
			return errPeerConnRemoteDescriptionWithoutMidValue
		}

		if media.MediaName.Media == mediaSectionApplication {
			continue
		}

		var transceiver *RTPTransceiver
		transceiver, currentTransceivers = findByMid(midValue, currentTransceivers)

		if transceiver == nil {
			return fmt.Errorf("%w: %q", errPeerConnTranscieverMidNil, midValue)
		}

		direction := getPeerDirection(media)
		if direction == RTPTransceiverDirectionUnknown {
			continue
		}

		if weOffer {
			switch direction {
			case RTPTransceiverDirectionSendonly:
				direction = RTPTransceiverDirectionRecvonly
			case RTPTransceiverDirectionRecvonly:
				direction = RTPTransceiverDirectionSendonly
			default:
			}
		}

		if !weOffer && direction == RTPTransceiverDirectionSendonly && transceiver.Sender() == nil {
			direction = RTPTransceiverDirectionInactive
		}

		transceiver.setCurrentDirection(direction)
	}

	return nil
}

func runIfNewReceiver(
	incomingTrack trackDetails,
	transceivers []*RTPTransceiver,
	callbackFunc func(incomingTrack trackDetails, receiver *RTPReceiver),
) bool {
	for _, t := range transceivers {
		if t.Mid() != incomingTrack.mid {
			continue
		}

		receiver := t.Receiver()
		if (incomingTrack.kind != t.Kind()) ||
			(t.Direction() != RTPTransceiverDirectionRecvonly && t.Direction() != RTPTransceiverDirectionSendrecv) ||
			receiver == nil ||
			(receiver.haveReceived()) {
			continue
		}

		callbackFunc(incomingTrack, receiver)

		return true
	}

	return false
}

func (pc *PeerConnection) configureRTPReceivers(
	isRenegotiation bool,
	remoteDesc *SessionDescription,
	currentTransceivers []*RTPTransceiver,
) {
	incomingTracks := trackDetailsFromSDP(pc.log, remoteDesc.parsed)

	if isRenegotiation {
		for _, transceiver := range currentTransceivers {
			receiver := transceiver.Receiver()
			if receiver == nil {
				continue
			}

			tracks := transceiver.Receiver().Tracks()
			if len(tracks) == 0 {
				continue
			}

			mid := transceiver.Mid()
			receiverNeedsStopped := false
			for _, trackRemote := range tracks {
				func(track *TrackRemote) {
					track.mu.Lock()
					defer track.mu.Unlock()

					if track.rid != "" {
						if details := trackDetailsForRID(incomingTracks, mid, track.rid); details != nil {
							track.id = details.id
							track.streamID = details.streamID

							return
						}
					} else if track.ssrc != 0 {
						if details := trackDetailsForSSRC(incomingTracks, track.ssrc); details != nil {
							track.id = details.id
							track.streamID = details.streamID

							return
						}
					}

					receiverNeedsStopped = true
				}(trackRemote)
			}

			if !receiverNeedsStopped {
				continue
			}

			if err := receiver.Stop(); err != nil {
				pc.log.Warnf("Failed to stop RtpReceiver: %s", err)

				continue
			}

			receiver, err := pc.api.NewRTPReceiver(receiver.kind, pc.dtlsTransport)
			if err != nil {
				pc.log.Warnf("Failed to create new RtpReceiver: %s", err)

				continue
			}
			transceiver.setReceiver(receiver)
		}
	}

	localTransceivers := append([]*RTPTransceiver{}, currentTransceivers...)

	filteredTracks := append([]trackDetails{}, incomingTracks...)
	for _, incomingTrack := range incomingTracks {

		for _, t := range localTransceivers {
			if receiver := t.Receiver(); receiver != nil {
				for _, track := range receiver.Tracks() {
					for _, ssrc := range incomingTrack.ssrcs {
						if ssrc == track.SSRC() {
							filteredTracks = filterTrackWithSSRC(filteredTracks, track.SSRC())
						}
					}
				}
			}
		}
	}

	for _, incomingTrack := range filteredTracks {
		_ = runIfNewReceiver(incomingTrack, localTransceivers, pc.configureReceiver)
	}
}

func (pc *PeerConnection) startRTPReceivers(remoteDesc *SessionDescription, currentTransceivers []*RTPTransceiver) {
	incomingTracks := trackDetailsFromSDP(pc.log, remoteDesc.parsed)
	if len(incomingTracks) == 0 {
		return
	}

	localTransceivers := append([]*RTPTransceiver{}, currentTransceivers...)

	unhandledTracks := incomingTracks[:0]
	for _, incomingTrack := range incomingTracks {
		trackHandled := runIfNewReceiver(incomingTrack, localTransceivers, pc.startReceiver)
		if !trackHandled {
			unhandledTracks = append(unhandledTracks, incomingTrack)
		}
	}

	remoteIsPlanB := false
	switch pc.configuration.SDPSemantics {
	case SDPSemanticsPlanB:
		remoteIsPlanB = true
	case SDPSemanticsUnifiedPlanWithFallback:
		remoteIsPlanB = descriptionPossiblyPlanB(pc.RemoteDescription())
	default:

	}

	if remoteIsPlanB {
		for _, incomingTrack := range unhandledTracks {
			t, err := pc.AddTransceiverFromKind(incomingTrack.kind, RTPTransceiverInit{
				Direction: RTPTransceiverDirectionSendrecv,
			})
			if err != nil {
				pc.log.Warnf("Could not add transceiver for remote SSRC %d: %s", incomingTrack.ssrcs[0], err)

				continue
			}
			pc.configureReceiver(incomingTrack, t.Receiver())
			pc.startReceiver(incomingTrack, t.Receiver())
		}
	}
}

func (pc *PeerConnection) startRTPSenders(currentTransceivers []*RTPTransceiver) error {
	for _, transceiver := range currentTransceivers {
		if sender := transceiver.Sender(); sender != nil && sender.isNegotiated() && !sender.hasSent() {
			err := sender.Send(sender.GetParameters())
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (pc *PeerConnection) startSCTP(maxMessageSize uint32, remoteSctpInit []byte) {

	if err := pc.sctpTransport.Start(SCTPCapabilities{
		MaxMessageSize: maxMessageSize,
		sctpInit:       string(remoteSctpInit),
	}); err != nil {
		pc.log.Warnf("Failed to start SCTP: %s", err)
		if err = pc.sctpTransport.Stop(); err != nil {
			pc.log.Warnf("Failed to stop SCTPTransport: %s", err)
		}

		return
	}
}

func (pc *PeerConnection) handleUndeclaredSSRC(
	ssrc SSRC,
	mediaSection *sdp.MediaDescription,
) (handled bool, err error) {
	streamID := ""
	id := ""
	hasRidAttribute := false
	hasSSRCAttribute := false

	for _, a := range mediaSection.Attributes {
		switch a.Key {
		case sdp.AttrKeyMsid:
			if split := strings.Split(a.Value, " "); len(split) == 2 {
				streamID = split[0]
				id = split[1]
			}
		case sdp.AttrKeySSRC:
			hasSSRCAttribute = true
		case sdpAttributeRid:
			hasRidAttribute = true
		}
	}

	if hasRidAttribute {
		return false, nil
	} else if hasSSRCAttribute {
		return false, errMediaSectionHasExplictSSRCAttribute
	}

	incoming := trackDetails{
		ssrcs:    []SSRC{ssrc},
		kind:     RTPCodecTypeVideo,
		streamID: streamID,
		id:       id,
	}
	if mediaSection.MediaName.Media == RTPCodecTypeAudio.String() {
		incoming.kind = RTPCodecTypeAudio
	}

	t, err := pc.AddTransceiverFromKind(incoming.kind, RTPTransceiverInit{
		Direction: RTPTransceiverDirectionSendrecv,
	})
	if err != nil {

		return false, fmt.Errorf("%w: %d: %s", errPeerConnRemoteSSRCAddTransceiver, ssrc, err)
	}

	pc.configureReceiver(incoming, t.Receiver())
	pc.startReceiver(incoming, t.Receiver())

	return true, nil
}

func (pc *PeerConnection) findMediaSectionByPayloadType(
	payloadType PayloadType,
	remoteDescription *SessionDescription,
) (selectedMediaSection *sdp.MediaDescription, ok bool) {
	for i := range remoteDescription.parsed.MediaDescriptions {
		descr := remoteDescription.parsed.MediaDescriptions[i]
		media := descr.MediaName.Media
		if !strings.EqualFold(media, "video") && !strings.EqualFold(media, "audio") {
			continue
		}

		formats := descr.MediaName.Formats
		for _, payloadStr := range formats {
			payload, err := strconv.ParseUint(payloadStr, 10, 8)
			if err != nil {
				continue
			}

			if PayloadType(payload) == payloadType {
				return remoteDescription.parsed.MediaDescriptions[i], true
			}
		}
	}

	return nil, false
}

func (pc *PeerConnection) handleNonMediaBandwidthProbe() {
	nonMediaBandwidthProbe, err := pc.api.NewRTPReceiver(RTPCodecTypeVideo, pc.dtlsTransport)
	if err != nil {
		pc.log.Errorf("handleNonMediaBandwidthProbe failed to create RTPReceiver: %v", err)

		return
	}

	if err = nonMediaBandwidthProbe.Receive(RTPReceiveParameters{
		Encodings: []RTPDecodingParameters{{RTPCodingParameters: RTPCodingParameters{}}},
	}); err != nil {
		pc.log.Errorf("handleNonMediaBandwidthProbe failed to start RTPReceiver: %v", err)

		return
	}

	pc.nonMediaBandwidthProbe.Store(nonMediaBandwidthProbe)
	b := make([]byte, pc.api.settingEngine.getReceiveMTU())
	for {
		if _, _, err = nonMediaBandwidthProbe.readRTP(b, nonMediaBandwidthProbe.Track()); err != nil {
			pc.log.Tracef("handleNonMediaBandwidthProbe read exiting: %v", err)

			return
		}
	}
}

func (pc *PeerConnection) handleIncomingSSRC(rtpStream *srtp.ReadStreamSRTP, ssrc SSRC) error {
	remoteDescription := pc.RemoteDescription()
	if remoteDescription == nil {
		return errPeerConnRemoteDescriptionNil
	}

	for _, track := range trackDetailsFromSDP(pc.log, remoteDescription.parsed) {
		if track.rtxSsrc != nil && ssrc == *track.rtxSsrc {
			return nil
		}
		if track.fecSsrc != nil && ssrc == *track.fecSsrc {
			return nil
		}
		if slices.Contains(track.ssrcs, ssrc) {
			return nil
		}
	}

	if remoteDescription.Type != SDPTypeAnswer || pc.api.settingEngine.handleUndeclaredSSRCWithoutAnswer {
		if len(remoteDescription.parsed.MediaDescriptions) == 1 {
			mediaSection := remoteDescription.parsed.MediaDescriptions[0]
			if handled, err := pc.handleUndeclaredSSRC(ssrc, mediaSection); handled || err != nil {
				return err
			}
		}
	}

	b := make([]byte, pc.api.settingEngine.getReceiveMTU())

	i, err := rtpStream.Peek(b)
	if err != nil {
		return err
	}

	if i < 4 {
		return errRTPTooShort
	}

	payloadType := PayloadType(b[1] & 0x7f)
	params, err := pc.api.mediaEngine.getRTPParametersByPayloadType(payloadType)
	if err != nil {
		return err
	}

	midExtensionID, audioSupported, videoSupported := pc.api.mediaEngine.getHeaderExtensionID(
		RTPHeaderExtensionCapability{sdp.SDESMidURI},
	)
	if !audioSupported && !videoSupported {
		if remoteDescription.Type == SDPTypeAnswer && !pc.api.settingEngine.handleUndeclaredSSRCWithoutAnswer {

			return errPeerConnEarlyMediaWithoutAnswer
		}

		mediaSection, ok := pc.findMediaSectionByPayloadType(payloadType, remoteDescription)
		if ok {
			if ok, err = pc.handleUndeclaredSSRC(ssrc, mediaSection); ok || err != nil {
				return err
			}
		}

		return errPeerConnSimulcastMidRTPExtensionRequired
	}

	streamIDExtensionID, audioSupported, videoSupported := pc.api.mediaEngine.getHeaderExtensionID(
		RTPHeaderExtensionCapability{sdp.SDESRTPStreamIDURI},
	)
	if !audioSupported && !videoSupported {
		return errPeerConnSimulcastStreamIDRTPExtensionRequired
	}

	repairStreamIDExtensionID, _, _ := pc.api.mediaEngine.getHeaderExtensionID(
		RTPHeaderExtensionCapability{sdp.SDESRepairRTPStreamIDURI},
	)

	streamInfo := createStreamInfo(
		"",
		ssrc,
		0, 0,
		params.Codecs[0].PayloadType,
		0, 0,
		params.Codecs[0].RTPCodecCapability,
		params.HeaderExtensions,
	)
	result, err := pc.dtlsTransport.streamsForSSRC(ssrc, *streamInfo)
	if err != nil {
		return err
	}
	readStream := result.rtpReadStream
	interceptor := result.rtpInterceptor
	rtcpReadStream := result.rtcpReadStream
	rtcpInterceptor := result.rtcpInterceptor

	mid, rid, rsid, _, err := handleUnknownRTPPacket(
		b[:i], uint8(midExtensionID),
		uint8(streamIDExtensionID),
		uint8(repairStreamIDExtensionID),
	)
	if err != nil {
		return err
	}

	peekedPackets := []*peekedPacket(nil)

	var paddingOnly bool
	for readCount := 0; readCount <= simulcastProbeCount; readCount++ {
		if mid == "" || (rid == "" && rsid == "") {

			if paddingOnly {
				readCount--
			}

			i, attributes, err := interceptor.Read(b, nil)
			if err != nil {
				return err
			}

			peekedPackets = append(peekedPackets, &peekedPacket{
				payload:    slices.Clone(b[:i]),
				attributes: attributes,
			})

			mid, rid, rsid, paddingOnly, err = handleUnknownRTPPacket(
				b[:i], uint8(midExtensionID),
				uint8(streamIDExtensionID),
				uint8(repairStreamIDExtensionID),
			)
			if err != nil {
				return err
			}

			continue
		}

		for _, t := range pc.GetTransceivers() {
			receiver := t.Receiver()
			if t.Mid() != mid || receiver == nil {
				continue
			}

			if rsid != "" {
				return receiver.receiveForRtx(SSRC(0), rsid, streamInfo, readStream, interceptor, rtcpReadStream, rtcpInterceptor)
			}

			track, err := receiver.receiveForRid(
				rid,
				params,
				streamInfo,
				readStream,
				interceptor,
				rtcpReadStream,
				rtcpInterceptor,
				peekedPackets,
			)
			if err != nil {
				return err
			}
			pc.onTrack(track, receiver)

			return nil
		}
	}

	pc.api.interceptor.UnbindRemoteStream(streamInfo)

	return errPeerConnSimulcastIncomingSSRCFailed
}

func (pc *PeerConnection) undeclaredMediaProcessor() {
	go pc.undeclaredRTPMediaProcessor()
	go pc.undeclaredRTCPMediaProcessor()
}

func (pc *PeerConnection) undeclaredRTPMediaProcessor() {
	var simulcastRoutineCount uint64
	for {
		srtpSession, err := pc.dtlsTransport.getSRTPSession()
		if err != nil {
			pc.log.Warnf("undeclaredMediaProcessor failed to open SrtpSession: %v", err)

			return
		}

		srtcpSession, err := pc.dtlsTransport.getSRTCPSession()
		if err != nil {
			pc.log.Warnf("undeclaredMediaProcessor failed to open SrtcpSession: %v", err)

			return
		}

		srtpReadStream, ssrc, err := srtpSession.AcceptStream()
		if err != nil {
			pc.log.Warnf("Failed to accept RTP %v", err)

			return
		}

		srtcpReadStream, err := srtcpSession.OpenReadStream(ssrc)
		if err != nil {
			pc.log.Warnf("Failed to open RTCP stream for %d: %v", ssrc, err)

			return
		}

		if pc.isClosed.Load() {
			if err = srtpReadStream.Close(); err != nil {
				pc.log.Warnf("Failed to close RTP stream %v", err)
			}
			if err = srtcpReadStream.Close(); err != nil {
				pc.log.Warnf("Failed to close RTCP stream %v", err)
			}

			continue
		}

		pc.dtlsTransport.storeSimulcastStream(srtpReadStream, srtcpReadStream)

		if ssrc == 0 {
			go pc.handleNonMediaBandwidthProbe()

			continue
		}

		if atomic.AddUint64(&simulcastRoutineCount, 1) >= simulcastMaxProbeRoutines {
			atomic.AddUint64(&simulcastRoutineCount, ^uint64(0))
			pc.log.Warn(ErrSimulcastProbeOverflow.Error())

			continue
		}

		go func(rtpStream *srtp.ReadStreamSRTP, ssrc SSRC) {
			if err := pc.handleIncomingSSRC(rtpStream, ssrc); err != nil {
				pc.log.Errorf(incomingUnhandledRTPSsrc, ssrc, err)
			}
			atomic.AddUint64(&simulcastRoutineCount, ^uint64(0))
		}(srtpReadStream, SSRC(ssrc))
	}
}

func (pc *PeerConnection) undeclaredRTCPMediaProcessor() {
	var unhandledStreams []*srtp.ReadStreamSRTCP
	defer func() {
		for _, s := range unhandledStreams {
			_ = s.Close()
		}
	}()
	for {
		srtcpSession, err := pc.dtlsTransport.getSRTCPSession()
		if err != nil {
			pc.log.Warnf("undeclaredMediaProcessor failed to open SrtcpSession: %v", err)

			return
		}

		stream, ssrc, err := srtcpSession.AcceptStream()
		if err != nil {
			pc.log.Warnf("Failed to accept RTCP %v", err)

			return
		}
		pc.log.Warnf("Incoming unhandled RTCP ssrc(%d), OnTrack will not be fired", ssrc)
		unhandledStreams = append(unhandledStreams, stream)
	}
}

func (pc *PeerConnection) RemoteDescription() *SessionDescription {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	if pc.pendingRemoteDescription != nil {
		return pc.pendingRemoteDescription
	}

	return pc.currentRemoteDescription
}

func (pc *PeerConnection) AddICECandidate(candidate ICECandidateInit) error {
	remoteDesc := pc.RemoteDescription()
	if remoteDesc == nil {
		return &InvalidStateError{Err: ErrNoRemoteDescription}
	}

	candidateValue := strings.TrimPrefix(candidate.Candidate, "candidate:")

	if candidateValue == "" {
		return pc.iceTransport.AddRemoteCandidate(nil)
	}

	cand, err := ice.UnmarshalCandidate(candidateValue)
	if err != nil {
		if errors.Is(err, ice.ErrUnknownCandidateTyp) || errors.Is(err, ice.ErrDetermineNetworkType) {
			pc.log.Warnf("Discarding remote candidate: %s", err)

			return nil
		}

		return err
	}

	if ufrag, ok := cand.GetExtension("ufrag"); ok {
		if !pc.descriptionContainsUfrag(remoteDesc.parsed, ufrag.Value) {
			pc.log.Errorf("dropping candidate with ufrag %s because it doesn't match the current ufrags", ufrag.Value)

			return nil
		}
	}

	c, err := newICECandidateFromICE(cand, "", 0)
	if err != nil {
		return err
	}

	return pc.iceTransport.AddRemoteCandidate(&c)
}

func (pc *PeerConnection) descriptionContainsUfrag(sdp *sdp.SessionDescription, matchUfrag string) bool {
	ufrag, ok := sdp.Attribute("ice-ufrag")
	if ok && ufrag == matchUfrag {
		return true
	}

	for _, media := range sdp.MediaDescriptions {
		ufrag, ok := media.Attribute("ice-ufrag")
		if ok && ufrag == matchUfrag {
			return true
		}
	}

	return false
}

func (pc *PeerConnection) ICEConnectionState() ICEConnectionState {
	if state, ok := pc.iceConnectionState.Load().(ICEConnectionState); ok {
		return state
	}

	return ICEConnectionState(0)
}

func (pc *PeerConnection) GetSenders() (result []*RTPSender) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for _, transceiver := range pc.rtpTransceivers {
		if sender := transceiver.Sender(); sender != nil {
			result = append(result, sender)
		}
	}

	return result
}

func (pc *PeerConnection) GetReceivers() (receivers []*RTPReceiver) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for _, transceiver := range pc.rtpTransceivers {
		if receiver := transceiver.Receiver(); receiver != nil {
			receivers = append(receivers, receiver)
		}
	}

	return
}

func (pc *PeerConnection) GetTransceivers() []*RTPTransceiver {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	return pc.rtpTransceivers
}

func (pc *PeerConnection) AddTrack(track TrackLocal) (*RTPSender, error) {
	if pc.isClosed.Load() {
		return nil, &InvalidStateError{Err: ErrConnectionClosed}
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()
	for _, transceiver := range pc.rtpTransceivers {
		if !transceiver.isSendAllowed(track.Kind()) {
			continue
		}

		sender, err := pc.api.NewRTPSender(track, pc.dtlsTransport)
		if err == nil {
			err = transceiver.SetSender(sender, track)
			if err != nil {
				_ = sender.Stop()
				transceiver.setSender(nil)
			}
		}
		if err != nil {
			return nil, err
		}
		pc.onNegotiationNeeded()

		return sender, nil
	}

	transceiver, err := pc.newTransceiverFromTrack(RTPTransceiverDirectionSendrecv, track)
	if err != nil {
		return nil, err
	}
	pc.addRTPTransceiver(transceiver)

	return transceiver.Sender(), nil
}

func (pc *PeerConnection) RemoveTrack(sender *RTPSender) (err error) {
	if pc.isClosed.Load() {
		return &InvalidStateError{Err: ErrConnectionClosed}
	}

	var transceiver *RTPTransceiver
	pc.mu.Lock()
	defer pc.mu.Unlock()
	for _, t := range pc.rtpTransceivers {
		if t.Sender() == sender {
			transceiver = t

			break
		}
	}
	if transceiver == nil {
		return &InvalidAccessError{Err: ErrSenderNotCreatedByConnection}
	} else if err = sender.Stop(); err == nil {
		err = transceiver.setSendingTrack(nil)
		if err == nil {
			pc.onNegotiationNeeded()
		}
	}

	return
}

func (pc *PeerConnection) newTransceiverFromTrack(
	direction RTPTransceiverDirection,
	track TrackLocal,
	init ...RTPTransceiverInit,
) (t *RTPTransceiver, err error) {
	var (
		receiver *RTPReceiver
		sender   *RTPSender
	)
	switch direction {
	case RTPTransceiverDirectionSendrecv:
		receiver, err = pc.api.NewRTPReceiver(track.Kind(), pc.dtlsTransport)
		if err != nil {
			return t, err
		}
		sender, err = pc.api.NewRTPSender(track, pc.dtlsTransport)
	case RTPTransceiverDirectionSendonly:
		sender, err = pc.api.NewRTPSender(track, pc.dtlsTransport)
	default:
		err = errPeerConnAddTransceiverFromTrackSupport
	}
	if err != nil {
		return t, err
	}

	if sender != nil && len(sender.trackEncodings) == 1 &&
		len(init) == 1 && len(init[0].SendEncodings) == 1 && init[0].SendEncodings[0].SSRC != 0 {
		sender.trackEncodings[0].ssrc = init[0].SendEncodings[0].SSRC
	}

	return newRTPTransceiver(receiver, sender, direction, track.Kind(), pc.api), nil
}

func (pc *PeerConnection) AddTransceiverFromKind(
	kind RTPCodecType,
	init ...RTPTransceiverInit,
) (t *RTPTransceiver, err error) {
	if pc.isClosed.Load() {
		return nil, &InvalidStateError{Err: ErrConnectionClosed}
	}

	direction := RTPTransceiverDirectionSendrecv
	if len(init) > 1 {
		return nil, errPeerConnAddTransceiverFromKindOnlyAcceptsOne
	} else if len(init) == 1 {
		direction = init[0].Direction
	}
	switch direction {
	case RTPTransceiverDirectionSendonly, RTPTransceiverDirectionSendrecv:
		codecs := pc.api.mediaEngine.getCodecsByKind(kind)
		if len(codecs) == 0 {
			return nil, ErrNoCodecsAvailable
		}
		track, err := NewTrackLocalStaticSample(codecs[0].RTPCodecCapability, wutil.RandAlphaString(16), wutil.RandAlphaString(16))
		if err != nil {
			return nil, err
		}
		t, err = pc.newTransceiverFromTrack(direction, track, init...)
		if err != nil {
			return nil, err
		}
	case RTPTransceiverDirectionRecvonly:
		receiver, err := pc.api.NewRTPReceiver(kind, pc.dtlsTransport)
		if err != nil {
			return nil, err
		}
		t = newRTPTransceiver(receiver, nil, RTPTransceiverDirectionRecvonly, kind, pc.api)
	default:
		return nil, errPeerConnAddTransceiverFromKindSupport
	}
	pc.mu.Lock()
	pc.addRTPTransceiver(t)
	pc.mu.Unlock()

	return t, nil
}

func (pc *PeerConnection) AddTransceiverFromTrack(
	track TrackLocal,
	init ...RTPTransceiverInit,
) (t *RTPTransceiver, err error) {
	if pc.isClosed.Load() {
		return nil, &InvalidStateError{Err: ErrConnectionClosed}
	}

	direction := RTPTransceiverDirectionSendrecv
	if len(init) > 1 {
		return nil, errPeerConnAddTransceiverFromTrackOnlyAcceptsOne
	} else if len(init) == 1 {
		direction = init[0].Direction
	}

	t, err = pc.newTransceiverFromTrack(direction, track, init...)
	if err == nil {
		pc.mu.Lock()
		pc.addRTPTransceiver(t)
		pc.mu.Unlock()
	}

	return
}

func (pc *PeerConnection) CreateDataChannel(label string, options *DataChannelInit) (*DataChannel, error) {

	if pc.isClosed.Load() {
		return nil, &InvalidStateError{Err: ErrConnectionClosed}
	}

	params := &DataChannelParameters{
		Label:   label,
		Ordered: true,
	}

	if options != nil {
		params.ID = options.ID
	}

	if options != nil {

		if options.Ordered != nil {
			params.Ordered = *options.Ordered
		}

		if options.MaxPacketLifeTime != nil {
			params.MaxPacketLifeTime = options.MaxPacketLifeTime
		}

		if options.MaxRetransmits != nil {
			params.MaxRetransmits = options.MaxRetransmits
		}

		if options.Protocol != nil {
			params.Protocol = *options.Protocol
		}

		if len(params.Protocol) > 65535 {
			return nil, &TypeError{Err: ErrProtocolTooLarge}
		}

		if options.Negotiated != nil {
			params.Negotiated = *options.Negotiated
		}
	}

	dataChannel, err := pc.api.newDataChannel(params, nil, pc.log)
	if err != nil {
		return nil, err
	}

	if dataChannel.maxPacketLifeTime != nil && dataChannel.maxRetransmits != nil {
		return nil, &TypeError{Err: ErrRetransmitsOrPacketLifeTime}
	}

	pc.sctpTransport.lock.Lock()
	pc.sctpTransport.dataChannels = append(pc.sctpTransport.dataChannels, dataChannel)
	if dataChannel.ID() != nil {
		pc.sctpTransport.dataChannelIDsUsed[*dataChannel.ID()] = struct{}{}
	}
	pc.sctpTransport.dataChannelsRequested++
	pc.sctpTransport.lock.Unlock()

	if pc.sctpTransport.State() == SCTPTransportStateConnected {
		if err = dataChannel.open(pc.sctpTransport); err != nil {
			return nil, err
		}
	}

	pc.mu.Lock()
	pc.onNegotiationNeeded()
	pc.mu.Unlock()

	return dataChannel, nil
}

func (pc *PeerConnection) SetIdentityProvider(string) error {
	return errPeerConnSetIdentityProviderNotImplemented
}

func (pc *PeerConnection) WriteRTCP(pkts []rtcp.Packet) error {
	_, err := pc.interceptorRTCPWriter.Write(pkts, make(interceptor.Attributes))

	return err
}

func (pc *PeerConnection) writeRTCP(pkts []rtcp.Packet, _ interceptor.Attributes) (int, error) {
	return pc.dtlsTransport.WriteRTCP(pkts)
}

func (pc *PeerConnection) Close() error {
	return pc.close(false)
}

func (pc *PeerConnection) GracefulClose() error {
	return pc.close(true)
}

func (pc *PeerConnection) close(shouldGracefullyClose bool) error {

	pc.mu.Lock()

	isAlreadyClosingOrClosed := pc.isClosed.Swap(true)
	isAlreadyGracefullyClosingOrClosed := pc.isGracefullyClosingOrClosed
	if shouldGracefullyClose && !isAlreadyGracefullyClosingOrClosed {
		pc.isGracefullyClosingOrClosed = true
	}
	pc.mu.Unlock()

	if isAlreadyClosingOrClosed {
		if !shouldGracefullyClose {
			return nil
		}

		if isAlreadyGracefullyClosingOrClosed {
			<-pc.isGracefulCloseDone

			return nil
		}

		<-pc.isCloseDone
	} else {
		defer close(pc.isCloseDone)
	}

	if shouldGracefullyClose {
		defer close(pc.isGracefulCloseDone)
	}

	closeErrs := make([]error, 0, 4)

	doGracefulCloseOps := func() []error {
		if !shouldGracefullyClose {
			return nil
		}

		var gracefulCloseErrors []error
		if pc.iceTransport != nil {
			gracefulCloseErrors = append(gracefulCloseErrors, pc.iceTransport.GracefulStop())
		}

		pc.ops.GracefulClose()

		pc.sctpTransport.lock.Lock()
		for _, d := range pc.sctpTransport.dataChannels {
			gracefulCloseErrors = append(gracefulCloseErrors, d.GracefulClose())
		}
		pc.sctpTransport.lock.Unlock()

		return gracefulCloseErrors
	}

	if isAlreadyClosingOrClosed {
		return wutil.JoinErrors(doGracefulCloseOps())
	}

	pc.signalingState.Set(SignalingStateClosed)

	pc.mu.Lock()
	for _, t := range pc.rtpTransceivers {
		closeErrs = append(closeErrs, t.Stop())
	}
	if nonMediaBandwidthProbe, ok := pc.nonMediaBandwidthProbe.Load().(*RTPReceiver); ok {
		closeErrs = append(closeErrs, nonMediaBandwidthProbe.Stop())
	}
	pc.mu.Unlock()

	pc.sctpTransport.lock.Lock()
	for _, d := range pc.sctpTransport.dataChannels {
		d.setReadyState(DataChannelStateClosed)
	}
	pc.sctpTransport.lock.Unlock()

	if pc.sctpTransport != nil {
		closeErrs = append(closeErrs, pc.sctpTransport.Stop())
	}

	closeErrs = append(closeErrs, pc.dtlsTransport.Stop())

	if pc.iceTransport != nil && !shouldGracefullyClose {

		closeErrs = append(closeErrs, pc.iceTransport.Stop())
	}

	pc.updateConnectionState(pc.ICEConnectionState(), pc.dtlsTransport.State())

	closeErrs = append(closeErrs, doGracefulCloseOps()...)

	pc.statsGetter = nil
	cleanupStats(pc.id)

	closeErrs = append(closeErrs, pc.api.interceptor.Close())

	return wutil.JoinErrors(closeErrs)
}

func (pc *PeerConnection) addRTPTransceiver(t *RTPTransceiver) {
	pc.rtpTransceivers = append(pc.rtpTransceivers, t)
	pc.onNegotiationNeeded()
}

func (pc *PeerConnection) CurrentLocalDescription() *SessionDescription {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	localDescription := pc.currentLocalDescription
	iceGather := pc.iceGatherer
	iceGatheringState := pc.ICEGatheringState()

	return populateLocalCandidates(localDescription, iceGather, iceGatheringState)
}

func (pc *PeerConnection) PendingLocalDescription() *SessionDescription {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	localDescription := pc.pendingLocalDescription
	iceGather := pc.iceGatherer
	iceGatheringState := pc.ICEGatheringState()

	return populateLocalCandidates(localDescription, iceGather, iceGatheringState)
}

func (pc *PeerConnection) CurrentRemoteDescription() *SessionDescription {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	return pc.currentRemoteDescription
}

func (pc *PeerConnection) PendingRemoteDescription() *SessionDescription {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	return pc.pendingRemoteDescription
}

func (pc *PeerConnection) CanTrickleICECandidates() ICETrickleCapability {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	return pc.canTrickleICECandidates
}

func (pc *PeerConnection) SignalingState() SignalingState {
	return pc.signalingState.Get()
}

func (pc *PeerConnection) ICEGatheringState() ICEGatheringState {
	if pc.iceGatherer == nil {
		return ICEGatheringStateNew
	}

	switch pc.iceGatherer.State() {
	case ICEGathererStateNew:
		return ICEGatheringStateNew
	case ICEGathererStateGathering:
		return ICEGatheringStateGathering
	default:
		return ICEGatheringStateComplete
	}
}

func (pc *PeerConnection) ConnectionState() PeerConnectionState {
	if state, ok := pc.connectionState.Load().(PeerConnectionState); ok {
		return state
	}

	return PeerConnectionState(0)
}

func (pc *PeerConnection) GetStats() StatsReport {
	var (
		dataChannelsAccepted  uint32
		dataChannelsClosed    uint32
		dataChannelsOpened    uint32
		dataChannelsRequested uint32
	)
	statsCollector := newStatsReportCollector()
	statsCollector.Collecting()

	pc.mu.Lock()
	if pc.iceGatherer != nil {
		pc.iceGatherer.collectStats(statsCollector)
	}
	if pc.iceTransport != nil {
		pc.iceTransport.collectStats(statsCollector)
	}

	pc.sctpTransport.lock.Lock()
	dataChannels := append([]*DataChannel{}, pc.sctpTransport.dataChannels...)
	dataChannelsAccepted = pc.sctpTransport.dataChannelsAccepted
	dataChannelsOpened = pc.sctpTransport.dataChannelsOpened
	dataChannelsRequested = pc.sctpTransport.dataChannelsRequested
	pc.sctpTransport.lock.Unlock()

	for _, d := range dataChannels {
		state := d.ReadyState()
		if state != DataChannelStateConnecting && state != DataChannelStateOpen {
			dataChannelsClosed++
		}

		d.collectStats(statsCollector)
	}
	pc.sctpTransport.collectStats(statsCollector)

	stats := PeerConnectionStats{
		Timestamp:             statsTimestampNow(),
		Type:                  StatsTypePeerConnection,
		ID:                    pc.id,
		DataChannelsAccepted:  dataChannelsAccepted,
		DataChannelsClosed:    dataChannelsClosed,
		DataChannelsOpened:    dataChannelsOpened,
		DataChannelsRequested: dataChannelsRequested,
	}

	statsCollector.Collect(stats.ID, stats)

	certificates := pc.configuration.Certificates
	for _, certificate := range certificates {
		if err := certificate.collectStats(statsCollector); err != nil {
			continue
		}
	}
	pc.mu.Unlock()

	receivers := pc.GetReceivers()
	for _, receiver := range receivers {
		receiver.collectStats(statsCollector, pc.statsGetter)
	}

	pc.api.mediaEngine.collectStats(statsCollector)

	return statsCollector.Ready()
}

func (pc *PeerConnection) startTransports(
	iceRole ICERole,
	dtlsRole DTLSRole,
	remoteUfrag, remotePwd, fingerprint, fingerprintHash string,
) {

	err := pc.iceTransport.Start(
		pc.iceGatherer,
		ICEParameters{
			UsernameFragment: remoteUfrag,
			Password:         remotePwd,
			ICELite:          false,
		},
		&iceRole,
	)
	if err != nil {
		pc.log.Warnf("Failed to start manager: %s", err)

		return
	}

	pc.dtlsTransport.internalOnCloseHandler = func() {
		if pc.isClosed.Load() || pc.api.settingEngine.disableCloseByDTLS {
			return
		}

		pc.log.Info("Closing PeerConnection from DTLS CloseNotify")
		go func() {
			if pcClosErr := pc.Close(); pcClosErr != nil {
				pc.log.Warnf("Failed to close PeerConnection from DTLS CloseNotify: %s", pcClosErr)
			}
		}()
	}

	err = pc.dtlsTransport.Start(DTLSParameters{
		Role:         dtlsRole,
		Fingerprints: []DTLSFingerprint{{Algorithm: fingerprintHash, Value: fingerprint}},
	})
	pc.updateConnectionState(pc.ICEConnectionState(), pc.dtlsTransport.State())
	if err != nil {
		pc.log.Warnf("Failed to start manager: %s", err)

		return
	}
}

func (pc *PeerConnection) startRTP(
	isRenegotiation bool,
	remoteDesc *SessionDescription,
	currentTransceivers []*RTPTransceiver,
) {
	if !isRenegotiation {
		pc.undeclaredMediaProcessor()
	}

	pc.startRTPReceivers(remoteDesc, currentTransceivers)
	if d := haveDataChannel(remoteDesc); d != nil && d.MediaName.Port.Value != 0 {
		remoteSctpInit, _ := getSctpInit(d)
		pc.startSCTP(getMaxMessageSize(d), remoteSctpInit)
	}
}

func (pc *PeerConnection) generateUnmatchedSDP(
	transceivers []*RTPTransceiver,
	useIdentity bool,
) (*sdp.SessionDescription, error) {
	desc, err := sdp.NewJSEPSessionDescription(useIdentity)
	if err != nil {
		return nil, err
	}
	desc.Attributes = append(desc.Attributes, sdp.Attribute{Key: sdp.AttrKeyMsidSemantic, Value: "WMS *"})

	iceParams, err := pc.iceGatherer.GetLocalParameters()
	if err != nil {
		return nil, err
	}

	candidates, err := pc.iceGatherer.GetLocalCandidates()
	if err != nil {
		return nil, err
	}

	isPlanB := pc.configuration.SDPSemantics == SDPSemanticsPlanB
	mediaSections := []mediaSection{}

	pc.sctpTransport.lock.Lock()

	var localSctpInit []byte
	if pc.sctpTransport.dataChannelsRequested != 0 && pc.api.settingEngine.sctp.enableSnap {
		localSctpInit = pc.sctpTransport.GetSctpInit()
	}
	defer pc.sctpTransport.lock.Unlock()

	if isPlanB {
		video := make([]*RTPTransceiver, 0)
		audio := make([]*RTPTransceiver, 0)

		for _, t := range transceivers {
			switch t.kind {
			case RTPCodecTypeVideo:
				video = append(video, t)
			case RTPCodecTypeAudio:
				audio = append(audio, t)
			}
			if sender := t.Sender(); sender != nil {
				sender.setNegotiated()
			}
		}

		if len(video) > 0 {
			mediaSections = append(mediaSections, mediaSection{id: "video", transceivers: video})
		}
		if len(audio) > 0 {
			mediaSections = append(mediaSections, mediaSection{id: "audio", transceivers: audio})
		}

		if pc.configuration.AlwaysNegotiateDataChannels || pc.sctpTransport.dataChannelsRequested != 0 {
			mediaSections = append(mediaSections, mediaSection{id: "data", data: true})
		}
	} else {
		for _, t := range transceivers {
			if sender := t.Sender(); sender != nil {
				sender.setNegotiated()
			}
			mediaSections = append(mediaSections, mediaSection{id: t.Mid(), transceivers: []*RTPTransceiver{t}})
		}

		if pc.configuration.AlwaysNegotiateDataChannels || pc.sctpTransport.dataChannelsRequested != 0 {
			mediaSections = append(mediaSections, mediaSection{
				id:       strconv.Itoa(len(mediaSections)),
				data:     true,
				sctpInit: localSctpInit,
			})
		}
	}

	dtlsFingerprints, err := pc.configuration.Certificates[0].GetFingerprints()
	if err != nil {
		return nil, err
	}

	return populateSDP(
		desc,
		isPlanB,
		dtlsFingerprints,
		pc.api.settingEngine.sdpMediaLevelFingerprints,
		pc.api.settingEngine.candidates.ICELite,
		true,
		pc.api.mediaEngine,
		connectionRoleFromDtlsRole(defaultDtlsRoleOffer),
		candidates,
		iceParams,
		mediaSections,
		pc.ICEGatheringState(),
		nil,
		pc.api.settingEngine.getSCTPMaxMessageSize(),
		false,
	)
}

func (pc *PeerConnection) generateMatchedSDP(
	transceivers []*RTPTransceiver,
	useIdentity, includeUnmatched bool,
	connectionRole sdp.ConnectionRole,
	ignoreRidPauseForRecv bool,
) (*sdp.SessionDescription, error) {
	desc, err := sdp.NewJSEPSessionDescription(useIdentity)
	if err != nil {
		return nil, err
	}
	desc.Attributes = append(desc.Attributes, sdp.Attribute{Key: sdp.AttrKeyMsidSemantic, Value: "WMS *"})

	iceParams, err := pc.iceGatherer.GetLocalParameters()
	if err != nil {
		return nil, err
	}

	candidates, err := pc.iceGatherer.GetLocalCandidates()
	if err != nil {
		return nil, err
	}

	var transceiver *RTPTransceiver
	remoteDescription := pc.currentRemoteDescription
	if pc.pendingRemoteDescription != nil {
		remoteDescription = pc.pendingRemoteDescription
	}
	isExtmapAllowMixed := isExtMapAllowMixedSet(remoteDescription.parsed)
	localTransceivers := append([]*RTPTransceiver{}, transceivers...)

	detectedPlanB := descriptionIsPlanB(remoteDescription, pc.log)
	if pc.configuration.SDPSemantics != SDPSemanticsUnifiedPlan {
		detectedPlanB = descriptionPossiblyPlanB(remoteDescription)
	}

	mediaSections := []mediaSection{}
	alreadyHaveApplicationMediaSection := false
	var localSctpInit []byte
	for _, media := range remoteDescription.parsed.MediaDescriptions {
		midValue := getMidValue(media)
		if midValue == "" {
			return nil, errPeerConnRemoteDescriptionWithoutMidValue
		}

		if media.MediaName.Media == mediaSectionApplication {
			init, _ := getSctpInit(media)
			if init != nil && pc.api.settingEngine.sctp.enableSnap {
				pc.sctpTransport.lock.Lock()
				localSctpInit = pc.sctpTransport.GetSctpInit()
				pc.sctpTransport.lock.Unlock()
			}

			mediaSections = append(mediaSections, mediaSection{id: midValue, data: true, sctpInit: localSctpInit})
			alreadyHaveApplicationMediaSection = true

			continue
		}

		kind := NewRTPCodecType(media.MediaName.Media)
		direction := getPeerDirection(media)
		if kind == 0 || direction == RTPTransceiverDirectionUnknown {
			continue
		}

		sdpSemantics := pc.configuration.SDPSemantics

		switch {
		case sdpSemantics == SDPSemanticsPlanB || sdpSemantics == SDPSemanticsUnifiedPlanWithFallback && detectedPlanB:
			if !detectedPlanB {
				return nil, &TypeError{
					Err: fmt.Errorf("%w: Expected PlanB, but RemoteDescription is UnifiedPlan", ErrIncorrectSDPSemantics),
				}
			}

			mediaTransceivers := []*RTPTransceiver{}
			for {

				transceiver, localTransceivers = satisfyTypeAndDirection(kind, direction, localTransceivers)
				if transceiver == nil {
					if len(mediaTransceivers) == 0 {
						transceiver = &RTPTransceiver{kind: kind, api: pc.api, codecs: pc.api.mediaEngine.getCodecsByKind(kind)}
						transceiver.setDirection(RTPTransceiverDirectionInactive)
						mediaTransceivers = append(mediaTransceivers, transceiver)
					}

					break
				}
				if sender := transceiver.Sender(); sender != nil {
					sender.setNegotiated()
				}
				mediaTransceivers = append(mediaTransceivers, transceiver)
			}
			mediaSections = append(mediaSections, mediaSection{id: midValue, transceivers: mediaTransceivers})
		case sdpSemantics == SDPSemanticsUnifiedPlan || sdpSemantics == SDPSemanticsUnifiedPlanWithFallback:
			if detectedPlanB {
				return nil, &TypeError{
					Err: fmt.Errorf(
						"%w: Expected UnifiedPlan, but RemoteDescription is PlanB",
						ErrIncorrectSDPSemantics,
					),
				}
			}
			transceiver, localTransceivers = findByMid(midValue, localTransceivers)
			if transceiver == nil {
				return nil, fmt.Errorf("%w: %q", errPeerConnTranscieverMidNil, midValue)
			}
			if sender := transceiver.Sender(); sender != nil {
				sender.setNegotiated()
			}
			mediaTransceivers := []*RTPTransceiver{transceiver}

			extensions, _ := rtpExtensionsFromMediaDescription(media)
			mediaSections = append(
				mediaSections,
				mediaSection{id: midValue, transceivers: mediaTransceivers, matchExtensions: extensions, rids: getRids(media)},
			)
		}
	}

	pc.sctpTransport.lock.Lock()
	defer pc.sctpTransport.lock.Unlock()

	var bundleGroup *string

	if includeUnmatched {
		if !detectedPlanB {
			for _, t := range localTransceivers {
				if sender := t.Sender(); sender != nil {
					sender.setNegotiated()
				}
				mediaSections = append(mediaSections, mediaSection{id: t.Mid(), transceivers: []*RTPTransceiver{t}})
			}
		}

		if (pc.configuration.AlwaysNegotiateDataChannels || pc.sctpTransport.dataChannelsRequested != 0) &&
			!alreadyHaveApplicationMediaSection {
			if detectedPlanB {
				mediaSections = append(mediaSections, mediaSection{id: "data", data: true})
			} else {
				mediaSections = append(mediaSections, mediaSection{
					id:       strconv.Itoa(len(mediaSections)),
					data:     true,
					sctpInit: localSctpInit,
				})
			}
		}
	} else if remoteDescription != nil {
		groupValue, _ := remoteDescription.parsed.Attribute(sdp.AttrKeyGroup)
		groupValue = strings.TrimLeft(groupValue, "BUNDLE")
		bundleGroup = &groupValue
	}

	if pc.configuration.SDPSemantics == SDPSemanticsUnifiedPlanWithFallback && detectedPlanB {
		pc.log.Info("Plan-B Offer detected; responding with Plan-B Answer")
	}

	dtlsFingerprints, err := pc.configuration.Certificates[0].GetFingerprints()
	if err != nil {
		return nil, err
	}

	return populateSDP(
		desc,
		detectedPlanB,
		dtlsFingerprints,
		pc.api.settingEngine.sdpMediaLevelFingerprints,
		pc.api.settingEngine.candidates.ICELite,
		isExtmapAllowMixed,
		pc.api.mediaEngine,
		connectionRole,
		candidates,
		iceParams,
		mediaSections,
		pc.ICEGatheringState(),
		bundleGroup,
		pc.api.settingEngine.getSCTPMaxMessageSize(),
		ignoreRidPauseForRecv,
	)
}

func (pc *PeerConnection) setGatherCompleteHandler(handler func()) {
	pc.iceGatherer.onGatheringCompleteHandler.Store(handler)
}

func (pc *PeerConnection) SCTP() *SCTPTransport {
	return pc.sctpTransport
}

type trackStreams struct {
	track                        *TrackRemote
	streamInfo, repairStreamInfo *interceptor.StreamInfo
	rtpReadStream                *srtp.ReadStreamSRTP
	rtpInterceptor               interceptor.RTPReader
	rtcpReadStream               *srtp.ReadStreamSRTCP
	rtcpInterceptor              interceptor.RTCPReader
	repairReadStream             *srtp.ReadStreamSRTP
	repairInterceptor            interceptor.RTPReader
	repairStreamChannel          chan rtxPacketWithAttributes
	repairRtcpReadStream         *srtp.ReadStreamSRTCP
	repairRtcpInterceptor        interceptor.RTCPReader
}

type rtxPacketWithAttributes struct {
	pkt        []byte
	attributes interceptor.Attributes
	pool       *sync.Pool
}

func (p *rtxPacketWithAttributes) release() {
	if p.pkt != nil {
		b := p.pkt[:cap(p.pkt)]
		p.pool.Put(b)
		p.pkt = nil
	}
}

type RTPReceiver struct {
	kind                 RTPCodecType
	transport            *DTLSTransport
	tracks               []trackStreams
	closed               atomic.Bool
	closedChan, received chan any
	mu                   sync.RWMutex
	tr                   *RTPTransceiver
	api                  *API
	rtxPool              sync.Pool
	log                  logging.LeveledLogger
}

func (api *API) NewRTPReceiver(kind RTPCodecType, transport *DTLSTransport) (*RTPReceiver, error) {
	if transport == nil {
		return nil, errRTPReceiverDTLSTransportNil
	}

	rtpReceiver := &RTPReceiver{
		kind:       kind,
		transport:  transport,
		api:        api,
		closedChan: make(chan any),
		received:   make(chan any),
		tracks:     []trackStreams{},
		rtxPool: sync.Pool{New: func() any {
			return make([]byte, api.settingEngine.getReceiveMTU())
		}},
		log: api.settingEngine.LoggerFactory.NewLogger("RTPReceiver"),
	}

	return rtpReceiver, nil
}

func (r *RTPReceiver) setRTPTransceiver(tr *RTPTransceiver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tr = tr
}

func (r *RTPReceiver) Transport() *DTLSTransport {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.transport
}

func (r *RTPReceiver) getParameters() RTPParameters {
	parameters := r.api.mediaEngine.getRTPParametersByKind(
		r.kind,
		[]RTPTransceiverDirection{RTPTransceiverDirectionRecvonly},
	)
	if r.tr != nil {
		parameters.Codecs = r.tr.getCodecs()
	}

	return parameters
}

func (r *RTPReceiver) GetParameters() RTPParameters {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.getParameters()
}

func (r *RTPReceiver) Track() *TrackRemote {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.tracks) != 1 {
		return nil
	}

	return r.tracks[0].track
}

func (r *RTPReceiver) Tracks() []*TrackRemote {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var tracks []*TrackRemote
	for i := range r.tracks {
		tracks = append(tracks, r.tracks[i].track)
	}

	return tracks
}

func (r *RTPReceiver) RTPTransceiver() *RTPTransceiver {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.tr
}

func (r *RTPReceiver) configureReceive(parameters RTPReceiveParameters) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range parameters.Encodings {
		t := trackStreams{
			track: newTrackRemote(
				r.kind,
				parameters.Encodings[i].SSRC,
				parameters.Encodings[i].RTX.SSRC,
				parameters.Encodings[i].RID,
				r,
			),
		}

		r.tracks = append(r.tracks, t)
	}
}

func (r *RTPReceiver) startReceive(parameters RTPReceiveParameters) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.received:
		return errRTPReceiverReceiveAlreadyCalled
	default:
	}

	globalParams := r.getParameters()
	codec := RTPCodecCapability{}
	if len(globalParams.Codecs) != 0 {
		codec = globalParams.Codecs[0].RTPCodecCapability
	}

	for i := range parameters.Encodings {
		if parameters.Encodings[i].RID != "" {

			continue
		}

		var streams *trackStreams
		for idx, ts := range r.tracks {
			if ts.track != nil && ts.track.SSRC() == parameters.Encodings[i].SSRC {
				streams = &r.tracks[idx]

				break
			}
		}
		if streams == nil {
			return fmt.Errorf("%w: %d", errRTPReceiverWithSSRCTrackStreamNotFound, parameters.Encodings[i].SSRC)
		}

		streams.streamInfo = createStreamInfo(
			"",
			parameters.Encodings[i].SSRC,
			0, 0, 0, 0, 0,
			codec,
			globalParams.HeaderExtensions,
		)

		result, err := r.transport.streamsForSSRC(parameters.Encodings[i].SSRC, *streams.streamInfo)
		if err != nil {
			return err
		}
		streams.rtpReadStream = result.rtpReadStream
		streams.rtpInterceptor = result.rtpInterceptor
		streams.rtcpReadStream = result.rtcpReadStream
		streams.rtcpInterceptor = result.rtcpInterceptor

		if rtxSsrc := parameters.Encodings[i].RTX.SSRC; rtxSsrc != 0 {

			rtxCodec := codec
			rtxCodec.RTCPFeedback = nil
			rtxCodec.MimeType = MimeTypeRTX
			streamInfo := createStreamInfo("", rtxSsrc, 0, 0, 0, 0, 0, rtxCodec, globalParams.HeaderExtensions)
			result, err = r.transport.streamsForSSRC(
				rtxSsrc,
				*streamInfo,
			)
			if err != nil {
				return err
			}
			rtpReadStream := result.rtpReadStream
			rtpInterceptor := result.rtpInterceptor
			rtcpReadStream := result.rtcpReadStream
			rtcpInterceptor := result.rtcpInterceptor

			if err = r.receiveForRtxInternal(
				rtxSsrc,
				"",
				streamInfo,
				rtpReadStream,
				rtpInterceptor,
				rtcpReadStream,
				rtcpInterceptor,
			); err != nil {
				return err
			}
		}
	}

	close(r.received)

	return nil
}

func (r *RTPReceiver) Receive(parameters RTPReceiveParameters) error {
	r.configureReceive(parameters)

	return r.startReceive(parameters)
}

func (r *RTPReceiver) Read(b []byte) (n int, a interceptor.Attributes, err error) {
	select {
	case <-r.received:
		if len(r.tracks) > 1 {
			r.log.Errorf(useReadSimulcast)
		}

		return r.tracks[0].rtcpInterceptor.Read(b, a)
	case <-r.closedChan:
		return 0, nil, io.ErrClosedPipe
	}
}

func (r *RTPReceiver) ReadSimulcast(b []byte, rid string) (n int, a interceptor.Attributes, err error) {
	select {
	case <-r.received:
		var rtcpInterceptor interceptor.RTCPReader

		r.mu.Lock()
		for _, t := range r.tracks {
			if t.track != nil && t.track.rid == rid {
				rtcpInterceptor = t.rtcpInterceptor
			}
		}
		r.mu.Unlock()

		if rtcpInterceptor == nil {
			return 0, nil, fmt.Errorf("%w: %s", errRTPReceiverForRIDTrackStreamNotFound, rid)
		}

		return rtcpInterceptor.Read(b, a)

	case <-r.closedChan:
		return 0, nil, io.ErrClosedPipe
	}
}

func (r *RTPReceiver) ReadRTCP() ([]rtcp.Packet, interceptor.Attributes, error) {
	b := make([]byte, r.api.settingEngine.getReceiveMTU())
	i, attributes, err := r.Read(b)
	if err != nil {
		return nil, nil, err
	}

	pkts, err := rtcp.Unmarshal(b[:i])
	if err != nil {
		return nil, nil, err
	}

	return pkts, attributes, nil
}

func (r *RTPReceiver) ReadSimulcastRTCP(rid string) ([]rtcp.Packet, interceptor.Attributes, error) {
	b := make([]byte, r.api.settingEngine.getReceiveMTU())
	i, attributes, err := r.ReadSimulcast(b, rid)
	if err != nil {
		return nil, nil, err
	}

	pkts, err := rtcp.Unmarshal(b[:i])

	return pkts, attributes, err
}

func (r *RTPReceiver) haveReceived() bool {
	select {
	case <-r.received:
		return true
	default:
		return false
	}
}

func (r *RTPReceiver) haveClosed() bool {
	return r.closed.Load()
}

func (r *RTPReceiver) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error

	select {
	case <-r.closedChan:
		return err
	default:
	}

	select {
	case <-r.received:
		for i := range r.tracks {
			errs := []error{}

			if r.tracks[i].rtcpReadStream != nil {
				errs = append(errs, r.tracks[i].rtcpReadStream.Close())
			}

			if r.tracks[i].rtpReadStream != nil {
				errs = append(errs, r.tracks[i].rtpReadStream.Close())
			}

			if r.tracks[i].repairReadStream != nil {
				errs = append(errs, r.tracks[i].repairReadStream.Close())
			}

			if r.tracks[i].repairRtcpReadStream != nil {
				errs = append(errs, r.tracks[i].repairRtcpReadStream.Close())
			}

			if r.tracks[i].streamInfo != nil {
				r.api.interceptor.UnbindRemoteStream(r.tracks[i].streamInfo)
			}

			if r.tracks[i].repairStreamInfo != nil {
				r.api.interceptor.UnbindRemoteStream(r.tracks[i].repairStreamInfo)
			}

			err = wutil.JoinErrors(errs)
		}
	default:
	}

	close(r.closedChan)
	r.closed.Store(true)

	return err
}

func (r *RTPReceiver) collectStats(collector *statsReportCollector, statsGetter stats.Getter) {
	if statsGetter == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	mid := ""
	if r.tr != nil {
		mid = r.tr.Mid()
	}
	now := statsTimestampNow()
	nowTime := now.Time()
	for trackIndex := range r.tracks {
		remoteTrack := r.tracks[trackIndex].track
		if remoteTrack == nil {
			continue
		}

		collector.Collecting()

		inboundID := fmt.Sprintf("inbound-rtp-%d", uint32(remoteTrack.SSRC()))
		codecID := ""
		if remoteTrack.codec.statsID != "" {
			codecID = remoteTrack.codec.statsID
		}

		inboundStats := InboundRTPStreamStats{
			Rid:         remoteTrack.RID(),
			Mid:         mid,
			Timestamp:   now,
			Type:        StatsTypeInboundRTP,
			ID:          inboundID,
			SSRC:        remoteTrack.SSRC(),
			Kind:        r.kind.String(),
			TransportID: "iceTransport",
			CodecID:     codecID,
		}
		r.populateInboundStats(&inboundStats, statsGetter, remoteTrack)

		collector.Collect(inboundID, inboundStats)

		if remoteTrack.Kind() == RTPCodecTypeAudio {
			r.collectAudioPlayoutStats(collector, nowTime, remoteTrack)
		}
	}
}

func (r *RTPReceiver) populateInboundStats(
	inboundStats *InboundRTPStreamStats,
	statsGetter stats.Getter,
	remoteTrack *TrackRemote,
) {
	stats := statsGetter.Get(uint32(remoteTrack.SSRC()))
	if stats == nil {
		return
	}

	pr := stats.InboundRTPStreamStats.PacketsReceived
	if pr > math.MaxUint32 {
		r.log.Warnf("Inbound PacketsReceived exceeds uint32 and will wrap: %d", pr)
	}
	inboundStats.PacketsReceived = uint32(pr)

	pl := stats.InboundRTPStreamStats.PacketsLost
	if pl > math.MaxInt32 || pl < math.MinInt32 {
		r.log.Warnf("Inbound PacketsLost exceeds int32 range and will wrap: %d", pl)
	}
	inboundStats.PacketsLost = int32(pl)

	inboundStats.Jitter = stats.InboundRTPStreamStats.Jitter
	inboundStats.BytesReceived = stats.InboundRTPStreamStats.BytesReceived
	inboundStats.HeaderBytesReceived = stats.InboundRTPStreamStats.HeaderBytesReceived
	timestamp := stats.InboundRTPStreamStats.LastPacketReceivedTimestamp
	inboundStats.LastPacketReceivedTimestamp = StatsTimestamp(
		timestamp.UnixNano() / int64(time.Millisecond))
	inboundStats.FIRCount = stats.InboundRTPStreamStats.FIRCount
	inboundStats.PLICount = stats.InboundRTPStreamStats.PLICount
	inboundStats.NACKCount = stats.InboundRTPStreamStats.NACKCount
}

func (r *RTPReceiver) collectAudioPlayoutStats(
	collector *statsReportCollector,
	nowTime time.Time,
	remoteTrack *TrackRemote,
) {
	playoutStats := remoteTrack.pullAudioPlayoutStats(nowTime)
	for _, stats := range playoutStats {
		collector.Collecting()
		collector.Collect(stats.ID, stats)
	}
}

func (r *RTPReceiver) streamsForTrack(t *TrackRemote) *trackStreams {
	for i := range r.tracks {
		if r.tracks[i].track == t {
			return &r.tracks[i]
		}
	}

	return nil
}

func (r *RTPReceiver) readRTP(b []byte, reader *TrackRemote) (n int, a interceptor.Attributes, err error) {
	select {
	case <-r.received:
	case <-r.closedChan:
		return 0, nil, io.EOF
	}

	if t := r.streamsForTrack(reader); t != nil {
		return t.rtpInterceptor.Read(b, a)
	}

	return 0, nil, fmt.Errorf("%w: %d", errRTPReceiverWithSSRCTrackStreamNotFound, reader.SSRC())
}

func (r *RTPReceiver) receiveForRid(
	rid string,
	params RTPParameters,
	streamInfo *interceptor.StreamInfo,
	rtpReadStream *srtp.ReadStreamSRTP,
	rtpInterceptor interceptor.RTPReader,
	rtcpReadStream *srtp.ReadStreamSRTCP,
	rtcpInterceptor interceptor.RTCPReader,
	peekedPackets []*peekedPacket,
) (*TrackRemote, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.haveClosed() {
		return nil, io.EOF
	}

	for i := range r.tracks {
		if r.tracks[i].track.RID() == rid {
			r.tracks[i].track.mu.Lock()
			r.tracks[i].track.kind = r.kind
			r.tracks[i].track.codec = params.Codecs[0]
			r.tracks[i].track.params = params
			r.tracks[i].track.ssrc = SSRC(streamInfo.SSRC)
			r.tracks[i].track.peekedPackets = peekedPackets
			r.tracks[i].track.mu.Unlock()

			r.tracks[i].streamInfo = streamInfo
			r.tracks[i].rtpReadStream = rtpReadStream
			r.tracks[i].rtpInterceptor = rtpInterceptor
			r.tracks[i].rtcpReadStream = rtcpReadStream
			r.tracks[i].rtcpInterceptor = rtcpInterceptor

			return r.tracks[i].track, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", errRTPReceiverForRIDTrackStreamNotFound, rid)
}

func (r *RTPReceiver) receiveForRtx(
	ssrc SSRC,
	rsid string,
	streamInfo *interceptor.StreamInfo,
	rtpReadStream *srtp.ReadStreamSRTP,
	rtpInterceptor interceptor.RTPReader,
	rtcpReadStream *srtp.ReadStreamSRTCP,
	rtcpInterceptor interceptor.RTCPReader,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.receiveForRtxInternal(
		ssrc,
		rsid,
		streamInfo,
		rtpReadStream,
		rtpInterceptor,
		rtcpReadStream,
		rtcpInterceptor,
	)
}

func (r *RTPReceiver) receiveForRtxInternal(
	ssrc SSRC,
	rsid string,
	streamInfo *interceptor.StreamInfo,
	rtpReadStream *srtp.ReadStreamSRTP,
	rtpInterceptor interceptor.RTPReader,
	rtcpReadStream *srtp.ReadStreamSRTCP,
	rtcpInterceptor interceptor.RTCPReader,
) error {
	if r.haveClosed() {
		return io.EOF
	}

	var track *trackStreams
	if ssrc != 0 && len(r.tracks) == 1 {
		track = &r.tracks[0]
	} else {
		for i := range r.tracks {
			if r.tracks[i].track.RID() == rsid {
				track = &r.tracks[i]
				if track.track.RtxSSRC() == 0 {
					track.track.setRtxSSRC(SSRC(streamInfo.SSRC))
				}

				break
			}
		}
	}

	if track == nil {
		return fmt.Errorf("%w: ssrc(%d) rsid(%s)", errRTPReceiverForRIDTrackStreamNotFound, ssrc, rsid)
	}

	track.repairStreamInfo = streamInfo
	track.repairReadStream = rtpReadStream
	track.repairInterceptor = rtpInterceptor
	track.repairRtcpReadStream = rtcpReadStream
	track.repairRtcpInterceptor = rtcpInterceptor
	track.repairStreamChannel = make(chan rtxPacketWithAttributes, 50)

	repairInterceptor := track.repairInterceptor
	repairStreamChannel := track.repairStreamChannel
	go func() {
		for {
			b := r.rtxPool.Get().([]byte)
			i, attributes, err := repairInterceptor.Read(b, nil)
			if err != nil {
				r.rtxPool.Put(b)

				return
			}

			hasExtension := b[0]&0b10000 > 0
			hasPadding := b[0]&0b100000 > 0
			csrcCount := b[0] & 0b1111
			headerLength := uint16(12 + (4 * csrcCount))
			paddingLength := 0
			if hasExtension {
				headerLength += 4 * (1 + binary.BigEndian.Uint16(b[headerLength+2:headerLength+4]))
			}
			if hasPadding {
				paddingLength = int(b[i-1])
			}

			if i-int(headerLength)-paddingLength < 2 {

				r.rtxPool.Put(b)

				continue
			}

			if attributes == nil {
				attributes = make(interceptor.Attributes)
			}
			attributes.Set(AttributeRtxPayloadType, b[1]&0x7F)
			attributes.Set(AttributeRtxSequenceNumber, binary.BigEndian.Uint16(b[2:4]))
			attributes.Set(AttributeRtxSsrc, binary.BigEndian.Uint32(b[8:12]))

			b[1] = (b[1] & 0x80) | uint8(track.track.PayloadType())
			b[2] = b[headerLength]
			b[3] = b[headerLength+1]
			binary.BigEndian.PutUint32(b[8:12], uint32(track.track.SSRC()))
			copy(b[headerLength:i-2], b[headerLength+2:i])

			select {
			case <-r.closedChan:
				r.rtxPool.Put(b)

				return
			case repairStreamChannel <- rtxPacketWithAttributes{pkt: b[:i-2], attributes: attributes, pool: &r.rtxPool}:
			default:

			}
		}
	}()

	return nil
}

func (r *RTPReceiver) SetReadDeadline(t time.Time) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.tracks[0].rtcpReadStream.SetReadDeadline(t)
}

func (r *RTPReceiver) SetReadDeadlineSimulcast(deadline time.Time, rid string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, t := range r.tracks {
		if t.track != nil && t.track.rid == rid {
			return t.rtcpReadStream.SetReadDeadline(deadline)
		}
	}

	return fmt.Errorf("%w: %s", errRTPReceiverForRIDTrackStreamNotFound, rid)
}

func (r *RTPReceiver) setRTPReadDeadline(deadline time.Time, reader *TrackRemote) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if t := r.streamsForTrack(reader); t != nil {
		return t.rtpReadStream.SetReadDeadline(deadline)
	}

	return fmt.Errorf("%w: %d", errRTPReceiverWithSSRCTrackStreamNotFound, reader.SSRC())
}

func (r *RTPReceiver) readRTX(reader *TrackRemote) *rtxPacketWithAttributes {
	if !reader.HasRTX() || r.haveClosed() {
		return nil
	}

	select {
	case <-r.received:
	default:
		return nil
	}

	r.mu.RLock()
	var ch chan rtxPacketWithAttributes
	if t := r.streamsForTrack(reader); t != nil {
		ch = t.repairStreamChannel
	}
	r.mu.RUnlock()

	select {
	case rtxPacketReceived := <-ch:
		return &rtxPacketReceived
	default:
	}

	return nil
}

func (r *RTPReceiver) SetRTPParameters(params RTPParameters) {
	headerExtensions := make([]interceptor.RTPHeaderExtension, 0, len(params.HeaderExtensions))
	for _, h := range params.HeaderExtensions {
		headerExtensions = append(headerExtensions, interceptor.RTPHeaderExtension{ID: h.ID, URI: h.URI})
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for ndx, codec := range params.Codecs {
		currentTrack := r.tracks[ndx].track

		r.tracks[ndx].streamInfo.RTPHeaderExtensions = headerExtensions

		currentTrack.mu.Lock()
		currentTrack.codec = codec
		currentTrack.params = params
		currentTrack.mu.Unlock()
	}
}

type trackEncoding struct {
	track                  TrackLocal
	srtpStream             *srtpWriterFuture
	rtcpInterceptor        interceptor.RTCPReader
	streamInfo             interceptor.StreamInfo
	context                *baseTrackLocalContext
	ssrc, ssrcRTX, ssrcFEC SSRC
}

type RTPSender struct {
	trackEncodings         []*trackEncoding
	transport              *DTLSTransport
	payloadType            PayloadType
	kind                   RTPCodecType
	negotiated             bool
	api                    *API
	id                     string
	rtpTransceiver         *RTPTransceiver
	mu                     sync.RWMutex
	sendCalled, stopCalled chan struct{}
}

func (api *API) NewRTPSender(track TrackLocal, transport *DTLSTransport) (*RTPSender, error) {
	if track == nil {
		return nil, errRTPSenderTrackNil
	} else if transport == nil {
		return nil, errRTPSenderDTLSTransportNil
	}

	id, err := wutil.CryptoRandString(32, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if err != nil {
		return nil, err
	}

	r := &RTPSender{
		transport:  transport,
		api:        api,
		sendCalled: make(chan struct{}),
		stopCalled: make(chan struct{}),
		id:         id,
		kind:       track.Kind(),
	}

	r.addEncoding(track)

	return r, nil
}

func (r *RTPSender) isNegotiated() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.negotiated
}

func (r *RTPSender) setNegotiated() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.negotiated = true
}

func (r *RTPSender) setRTPTransceiver(rtpTransceiver *RTPTransceiver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rtpTransceiver = rtpTransceiver
}

func (r *RTPSender) Transport() *DTLSTransport {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.transport
}

func (r *RTPSender) GetParameters() RTPSendParameters {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var encodings []RTPEncodingParameters
	for _, trackEncoding := range r.trackEncodings {
		var rid string
		if trackEncoding.track != nil {
			rid = trackEncoding.track.RID()
		}
		encodings = append(encodings, RTPEncodingParameters{
			RTPCodingParameters: RTPCodingParameters{
				RID:         rid,
				SSRC:        trackEncoding.ssrc,
				RTX:         RTPRtxParameters{SSRC: trackEncoding.ssrcRTX},
				FEC:         RTPFecParameters{SSRC: trackEncoding.ssrcFEC},
				PayloadType: r.payloadType,
			},
		})
	}
	sendParameters := RTPSendParameters{
		RTPParameters: r.api.mediaEngine.getRTPParametersByKind(
			r.kind,
			[]RTPTransceiverDirection{RTPTransceiverDirectionSendonly},
		),
		Encodings: encodings,
	}
	if r.rtpTransceiver != nil {
		sendParameters.Codecs = r.rtpTransceiver.getCodecs()
	} else {
		sendParameters.Codecs = r.api.mediaEngine.getCodecsByKind(r.kind)
	}

	return sendParameters
}

func (r *RTPSender) AddEncoding(track TrackLocal) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if track == nil {
		return errRTPSenderTrackNil
	}

	if track.RID() == "" {
		return errRTPSenderRidNil
	}

	if r.hasStopped() {
		return errRTPSenderStopped
	}

	if r.hasSent() {
		return errRTPSenderSendAlreadyCalled
	}

	var refTrack TrackLocal
	if len(r.trackEncodings) != 0 {
		refTrack = r.trackEncodings[0].track
	}
	if refTrack == nil || refTrack.RID() == "" {
		return errRTPSenderNoBaseEncoding
	}

	if refTrack.ID() != track.ID() || refTrack.StreamID() != track.StreamID() || refTrack.Kind() != track.Kind() {
		return errRTPSenderBaseEncodingMismatch
	}

	for _, encoding := range r.trackEncodings {
		if encoding.track == nil {
			continue
		}

		if encoding.track.RID() == track.RID() {
			return errRTPSenderRIDCollision
		}
	}

	r.addEncoding(track)

	return nil
}

func (r *RTPSender) addEncoding(track TrackLocal) {
	trackEncoding := &trackEncoding{
		track: track,
		ssrc:  SSRC(wutil.RandUint32()),
	}

	if r.api.mediaEngine.isRTXEnabled(r.kind, []RTPTransceiverDirection{RTPTransceiverDirectionSendonly}) {
		trackEncoding.ssrcRTX = SSRC(wutil.RandUint32())
	}

	if r.api.mediaEngine.isFECEnabled(r.kind, []RTPTransceiverDirection{RTPTransceiverDirectionSendonly}) {
		trackEncoding.ssrcFEC = SSRC(wutil.RandUint32())
	}

	r.trackEncodings = append(r.trackEncodings, trackEncoding)
}

func (r *RTPSender) Track() TrackLocal {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.trackEncodings) == 0 {
		return nil
	}

	return r.trackEncodings[0].track
}

func (r *RTPSender) ReplaceTrack(track TrackLocal) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if track != nil && r.kind != track.Kind() {
		return ErrRTPSenderNewTrackHasIncorrectKind
	}

	if track != nil && len(r.trackEncodings) > 1 {
		return ErrRTPSenderNewTrackHasIncorrectEnvelope
	}

	var replacedTrack TrackLocal
	var context *baseTrackLocalContext
	for _, e := range r.trackEncodings {
		replacedTrack = e.track
		context = e.context

		if r.hasSent() && replacedTrack != nil {
			if err := replacedTrack.Unbind(context); err != nil {
				return err
			}
		}

		if !r.hasSent() || track == nil {
			e.track = track
		}
	}

	if !r.hasSent() || track == nil {
		return nil
	}

	params := r.api.mediaEngine.getRTPParametersByKind(
		track.Kind(),
		[]RTPTransceiverDirection{RTPTransceiverDirectionSendonly},
	)

	codec, err := track.Bind(&baseTrackLocalContext{
		id:              context.ID(),
		params:          params,
		ssrc:            context.SSRC(),
		ssrcRTX:         context.SSRCRetransmission(),
		ssrcFEC:         context.SSRCForwardErrorCorrection(),
		writeStream:     context.WriteStream(),
		rtcpInterceptor: context.RTCPReader(),
	})
	if err != nil {

		if _, reBindErr := replacedTrack.Bind(context); reBindErr != nil {
			return reBindErr
		}

		return err
	}

	if r.payloadType != codec.PayloadType {
		context.params.Codecs = []RTPCodecParameters{codec}
	}

	r.trackEncodings[0].track = track

	return nil
}

func (r *RTPSender) Send(parameters RTPSendParameters) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch {
	case r.hasSent():
		return errRTPSenderSendAlreadyCalled
	case r.trackEncodings[0].track == nil:
		return errRTPSenderTrackRemoved
	}

	for idx := range r.trackEncodings {
		trackEncoding := r.trackEncodings[idx]
		srtpStream := &srtpWriterFuture{ssrc: parameters.Encodings[idx].SSRC, rtpSender: r}
		writeStream := &interceptorToTrackLocalWriter{}
		rtpParameters := r.api.mediaEngine.getRTPParametersByKind(
			trackEncoding.track.Kind(),
			[]RTPTransceiverDirection{RTPTransceiverDirectionSendonly},
		)

		trackEncoding.srtpStream = srtpStream
		trackEncoding.ssrc = parameters.Encodings[idx].SSRC
		trackEncoding.ssrcRTX = parameters.Encodings[idx].RTX.SSRC
		trackEncoding.ssrcFEC = parameters.Encodings[idx].FEC.SSRC
		trackEncoding.rtcpInterceptor = r.api.interceptor.BindRTCPReader(
			interceptor.RTCPReaderFunc(
				func(in []byte, a interceptor.Attributes) (n int, attributes interceptor.Attributes, err error) {
					n, err = trackEncoding.srtpStream.Read(in)

					return n, a, err
				},
			),
		)
		trackEncoding.context = &baseTrackLocalContext{
			id:              r.id,
			params:          rtpParameters,
			ssrc:            parameters.Encodings[idx].SSRC,
			ssrcFEC:         parameters.Encodings[idx].FEC.SSRC,
			ssrcRTX:         parameters.Encodings[idx].RTX.SSRC,
			writeStream:     writeStream,
			rtcpInterceptor: trackEncoding.rtcpInterceptor,
		}

		codec, err := trackEncoding.track.Bind(trackEncoding.context)
		if err != nil {
			return err
		}
		trackEncoding.context.params.Codecs = []RTPCodecParameters{codec}

		trackEncoding.streamInfo = *createStreamInfo(
			r.id,
			parameters.Encodings[idx].SSRC,
			parameters.Encodings[idx].RTX.SSRC,
			parameters.Encodings[idx].FEC.SSRC,
			codec.PayloadType,
			findRTXPayloadType(codec.PayloadType, rtpParameters.Codecs),
			findFECPayloadType(rtpParameters.Codecs),
			codec.RTPCodecCapability,
			parameters.HeaderExtensions,
		)

		rtpInterceptor := r.api.interceptor.BindLocalStream(
			&trackEncoding.streamInfo,
			interceptor.RTPWriterFunc(func(header *rtp.Header, payload []byte, _ interceptor.Attributes) (int, error) {
				return srtpStream.WriteRTP(header, payload)
			}),
		)

		writeStream.interceptor.Store(rtpInterceptor)
	}

	close(r.sendCalled)

	return nil
}

func (r *RTPSender) Stop() error {
	r.mu.Lock()

	if stopped := r.hasStopped(); stopped {
		r.mu.Unlock()

		return nil
	}

	close(r.stopCalled)
	r.mu.Unlock()

	if !r.hasSent() {
		return nil
	}

	if err := r.ReplaceTrack(nil); err != nil {
		return err
	}

	errs := []error{}
	for _, trackEncoding := range r.trackEncodings {
		r.api.interceptor.UnbindLocalStream(&trackEncoding.streamInfo)
		if trackEncoding.srtpStream != nil {
			errs = append(errs, trackEncoding.srtpStream.Close())
		}
	}

	return wutil.JoinErrors(errs)
}

func (r *RTPSender) Read(b []byte) (n int, a interceptor.Attributes, err error) {
	select {
	case <-r.sendCalled:
		return r.trackEncodings[0].rtcpInterceptor.Read(b, a)
	case <-r.stopCalled:
		return 0, nil, io.ErrClosedPipe
	}
}

func (r *RTPSender) ReadRTCP() ([]rtcp.Packet, interceptor.Attributes, error) {
	b := make([]byte, r.api.settingEngine.getReceiveMTU())
	i, attributes, err := r.Read(b)
	if err != nil {
		return nil, nil, err
	}

	pkts, err := rtcp.Unmarshal(b[:i])
	if err != nil {
		return nil, nil, err
	}

	return pkts, attributes, nil
}

func (r *RTPSender) ReadSimulcast(b []byte, rid string) (n int, a interceptor.Attributes, err error) {
	select {
	case <-r.sendCalled:
		r.mu.Lock()
		for _, t := range r.trackEncodings {
			if t.track != nil && t.track.RID() == rid {
				reader := t.rtcpInterceptor
				r.mu.Unlock()

				return reader.Read(b, a)
			}
		}
		r.mu.Unlock()

		return 0, nil, fmt.Errorf("%w: %s", errRTPSenderNoTrackForRID, rid)
	case <-r.stopCalled:
		return 0, nil, io.ErrClosedPipe
	}
}

func (r *RTPSender) ReadSimulcastRTCP(rid string) ([]rtcp.Packet, interceptor.Attributes, error) {
	b := make([]byte, r.api.settingEngine.getReceiveMTU())
	i, attributes, err := r.ReadSimulcast(b, rid)
	if err != nil {
		return nil, nil, err
	}

	pkts, err := rtcp.Unmarshal(b[:i])

	return pkts, attributes, err
}

func (r *RTPSender) SetReadDeadline(t time.Time) error {
	if r.trackEncodings[0].srtpStream == nil {
		return errRTPSenderSendNotCalled
	}

	return r.trackEncodings[0].srtpStream.SetReadDeadline(t)
}

func (r *RTPSender) SetReadDeadlineSimulcast(deadline time.Time, rid string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, t := range r.trackEncodings {
		if t.track != nil && t.track.RID() == rid {
			return t.srtpStream.SetReadDeadline(deadline)
		}
	}

	return fmt.Errorf("%w: %s", errRTPSenderNoTrackForRID, rid)
}

func (r *RTPSender) hasSent() bool {
	select {
	case <-r.sendCalled:
		return true
	default:
		return false
	}
}

func (r *RTPSender) hasStopped() bool {
	select {
	case <-r.stopCalled:
		return true
	default:
		return false
	}
}

func (r *RTPSender) configureRTXAndFEC() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, trackEncoding := range r.trackEncodings {
		if !r.api.mediaEngine.isRTXEnabled(r.kind, []RTPTransceiverDirection{RTPTransceiverDirectionSendonly}) {
			trackEncoding.ssrcRTX = SSRC(0)
		}

		if !r.api.mediaEngine.isFECEnabled(r.kind, []RTPTransceiverDirection{RTPTransceiverDirectionSendonly}) {
			trackEncoding.ssrcFEC = SSRC(0)
		}
	}
}

type RTPTransceiver struct {
	mid                    atomic.Value
	sender                 atomic.Value
	receiver               atomic.Value
	direction              atomic.Value
	currentDirection       atomic.Value
	currentRemoteDirection atomic.Value
	codecs                 []RTPCodecParameters
	kind                   RTPCodecType
	api                    *API
	mu                     sync.RWMutex
}

func newRTPTransceiver(
	receiver *RTPReceiver,
	sender *RTPSender,
	direction RTPTransceiverDirection,
	kind RTPCodecType,
	api *API,
) *RTPTransceiver {
	t := &RTPTransceiver{kind: kind, api: api}
	t.setReceiver(receiver)
	t.setSender(sender)
	t.setDirection(direction)
	t.setCurrentDirection(RTPTransceiverDirectionUnknown)

	return t
}

func (t *RTPTransceiver) SetCodecPreferences(codecs []RTPCodecParameters) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, codec := range codecs {
		if _, matchType := codecParametersFuzzySearch(
			codec, t.api.mediaEngine.getCodecsByKind(t.kind),
		); matchType == codecMatchNone {
			return fmt.Errorf("%w %s", errRTPTransceiverCodecUnsupported, codec.MimeType)
		}
	}

	t.codecs = filterUnattachedRTX(codecs)

	return nil
}

func (t *RTPTransceiver) getCodecs() []RTPCodecParameters {
	t.mu.RLock()
	defer t.mu.RUnlock()

	mediaEngineCodecs := t.api.mediaEngine.getCodecsByKind(t.kind)
	if len(t.codecs) == 0 {
		return filterUnattachedRTX(mediaEngineCodecs)
	}

	filteredCodecs := []RTPCodecParameters{}
	for _, codec := range t.codecs {
		if c, matchType := codecParametersFuzzySearch(codec, mediaEngineCodecs); matchType != codecMatchNone {
			if codec.PayloadType == 0 {
				codec.PayloadType = c.PayloadType
			}
			codec.RTCPFeedback = rtcpFeedbackIntersection(codec.RTCPFeedback, c.RTCPFeedback)
			filteredCodecs = append(filteredCodecs, codec)
		}
	}

	return filterUnattachedRTX(filteredCodecs)
}

func (t *RTPTransceiver) setCodecPreferencesFromRemoteDescription(media *sdp.MediaDescription) {
	remoteCodecs, err := codecsFromMediaDescription(media)
	if err != nil {
		return
	}

	leftCodecs := append([]RTPCodecParameters{}, t.api.mediaEngine.getCodecsByKind(t.kind)...)

	payloadMapping := make(map[PayloadType]PayloadType)
	filterByMatchType := func(matchFilter codecMatchType) []RTPCodecParameters {
		filteredCodecs := []RTPCodecParameters{}
		for remoteCodecIdx := len(remoteCodecs) - 1; remoteCodecIdx >= 0; remoteCodecIdx-- {
			remoteCodec := remoteCodecs[remoteCodecIdx]
			if strings.EqualFold(remoteCodec.RTPCodecCapability.MimeType, MimeTypeRTX) {
				continue
			}

			matchCodec, matchType := codecParametersFuzzySearch(
				remoteCodec,
				leftCodecs,
			)
			if matchType == matchFilter {
				payloadMapping[remoteCodec.PayloadType] = matchCodec.PayloadType

				remoteCodec.PayloadType = matchCodec.PayloadType
				filteredCodecs = append([]RTPCodecParameters{remoteCodec}, filteredCodecs...)

				remoteCodecs = append(remoteCodecs[:remoteCodecIdx], remoteCodecs[remoteCodecIdx+1:]...)

				needleFmtp := wutil.ParseFMTP(
					matchCodec.RTPCodecCapability.MimeType,
					matchCodec.RTPCodecCapability.ClockRate,
					matchCodec.RTPCodecCapability.Channels,
					matchCodec.RTPCodecCapability.SDPFmtpLine,
				)

				for leftCodecIdx := len(leftCodecs) - 1; leftCodecIdx >= 0; leftCodecIdx-- {
					leftCodec := leftCodecs[leftCodecIdx]
					leftCodecFmtp := wutil.ParseFMTP(
						leftCodec.RTPCodecCapability.MimeType,
						leftCodec.RTPCodecCapability.ClockRate,
						leftCodec.RTPCodecCapability.Channels,
						leftCodec.RTPCodecCapability.SDPFmtpLine,
					)

					if needleFmtp.Match(leftCodecFmtp) {
						leftCodecs = append(leftCodecs[:leftCodecIdx], leftCodecs[leftCodecIdx+1:]...)

						break
					}
				}
			}
		}

		return filteredCodecs
	}

	filteredCodecs := filterByMatchType(codecMatchExact)
	filteredCodecs = append(filteredCodecs, filterByMatchType(codecMatchPartial)...)

	for remotePayloadType, mediaEnginePayloadType := range payloadMapping {
		remoteRTX := findRTXPayloadType(remotePayloadType, remoteCodecs)
		if remoteRTX == PayloadType(0) {
			continue
		}

		mediaEngineRTX := findRTXPayloadType(mediaEnginePayloadType, leftCodecs)
		if mediaEngineRTX == PayloadType(0) {
			continue
		}

		for _, rtxCodec := range leftCodecs {
			if rtxCodec.PayloadType == mediaEngineRTX {
				filteredCodecs = append(filteredCodecs, rtxCodec)

				break
			}
		}
	}
	_ = t.SetCodecPreferences(filteredCodecs)
}

func (t *RTPTransceiver) Sender() *RTPSender {
	if v, ok := t.sender.Load().(*RTPSender); ok {
		return v
	}

	return nil
}

func (t *RTPTransceiver) SetSender(s *RTPSender, track TrackLocal) error {
	t.setSender(s)

	return t.setSendingTrack(track)
}

func (t *RTPTransceiver) setSender(s *RTPSender) {
	if s != nil {
		s.setRTPTransceiver(t)
	}

	if prevSender := t.Sender(); prevSender != nil {
		prevSender.setRTPTransceiver(nil)
	}

	t.sender.Store(s)
}

func (t *RTPTransceiver) Receiver() *RTPReceiver {
	if v, ok := t.receiver.Load().(*RTPReceiver); ok {
		return v
	}

	return nil
}

func (t *RTPTransceiver) SetMid(mid string) error {
	if currentMid := t.Mid(); currentMid != "" {
		return fmt.Errorf("%w: %s to %s", errRTPTransceiverCannotChangeMid, currentMid, mid)
	}
	t.mid.Store(mid)

	return nil
}

func (t *RTPTransceiver) Mid() string {
	if v, ok := t.mid.Load().(string); ok {
		return v
	}

	return ""
}

func (t *RTPTransceiver) Kind() RTPCodecType {
	return t.kind
}

func (t *RTPTransceiver) Direction() RTPTransceiverDirection {
	if direction, ok := t.direction.Load().(RTPTransceiverDirection); ok {
		return direction
	}

	return RTPTransceiverDirection(0)
}

func (t *RTPTransceiver) Stop() error {
	if sender := t.Sender(); sender != nil {
		if err := sender.Stop(); err != nil {
			return err
		}
	}
	if receiver := t.Receiver(); receiver != nil {
		if err := receiver.Stop(); err != nil {
			return err
		}
	}

	t.setDirection(RTPTransceiverDirectionInactive)
	t.setCurrentDirection(RTPTransceiverDirectionInactive)

	return nil
}

func (t *RTPTransceiver) setReceiver(r *RTPReceiver) {
	if r != nil {
		r.setRTPTransceiver(t)
	}

	if prevReceiver := t.Receiver(); prevReceiver != nil {
		prevReceiver.setRTPTransceiver(nil)
	}

	t.receiver.Store(r)
}

func (t *RTPTransceiver) setDirection(d RTPTransceiverDirection) {
	t.direction.Store(d)
}

func (t *RTPTransceiver) setCurrentDirection(d RTPTransceiverDirection) {
	t.currentDirection.Store(d)
}

func (t *RTPTransceiver) getCurrentDirection() RTPTransceiverDirection {
	if v, ok := t.currentDirection.Load().(RTPTransceiverDirection); ok {
		return v
	}

	return RTPTransceiverDirectionUnknown
}

func (t *RTPTransceiver) setCurrentRemoteDirection(d RTPTransceiverDirection) {
	t.currentRemoteDirection.Store(d)
}

func (t *RTPTransceiver) getCurrentRemoteDirection() RTPTransceiverDirection {
	if v, ok := t.currentRemoteDirection.Load().(RTPTransceiverDirection); ok {
		return v
	}

	return RTPTransceiverDirectionUnknown
}

func (t *RTPTransceiver) setSendingTrack(track TrackLocal) error {
	if err := t.Sender().ReplaceTrack(track); err != nil {
		return err
	}
	if track == nil {
		t.setSender(nil)
	}

	switch {
	case track != nil && t.Direction() == RTPTransceiverDirectionRecvonly:
		t.setDirection(RTPTransceiverDirectionSendrecv)
	case track != nil && t.Direction() == RTPTransceiverDirectionInactive:
		t.setDirection(RTPTransceiverDirectionSendonly)
	case track == nil && t.Direction() == RTPTransceiverDirectionSendrecv:
		t.setDirection(RTPTransceiverDirectionRecvonly)
	case track != nil && t.Direction() == RTPTransceiverDirectionSendonly:

	case track != nil && t.Direction() == RTPTransceiverDirectionSendrecv:

	case track == nil && t.Direction() == RTPTransceiverDirectionSendonly:
		t.setDirection(RTPTransceiverDirectionInactive)
	default:
		return errRTPTransceiverSetSendingInvalidState
	}

	return nil
}

func (t *RTPTransceiver) isSendAllowed(kind RTPCodecType) bool {
	if t.kind != kind || t.Sender() != nil {
		return false
	}

	currentDirection := t.getCurrentDirection()
	if currentDirection == RTPTransceiverDirectionSendrecv ||
		currentDirection == RTPTransceiverDirectionSendonly {
		return false
	}

	currentRemoteDirection := t.getCurrentRemoteDirection()
	if currentRemoteDirection == RTPTransceiverDirectionSendonly ||
		currentRemoteDirection == RTPTransceiverDirectionInactive {
		return false
	}

	return true
}

func findByMid(mid string, localTransceivers []*RTPTransceiver) (*RTPTransceiver, []*RTPTransceiver) {
	for i, t := range localTransceivers {
		if t.Mid() == mid {
			return t, append(localTransceivers[:i], localTransceivers[i+1:]...)
		}
	}

	return nil, localTransceivers
}

func satisfyTypeAndDirection(
	remoteKind RTPCodecType,
	remoteDirection RTPTransceiverDirection,
	localTransceivers []*RTPTransceiver,
) (*RTPTransceiver, []*RTPTransceiver) {

	getPreferredDirections := func() []RTPTransceiverDirection {
		switch remoteDirection {
		case RTPTransceiverDirectionSendrecv:
			return []RTPTransceiverDirection{
				RTPTransceiverDirectionRecvonly,
				RTPTransceiverDirectionSendrecv,
				RTPTransceiverDirectionSendonly,
			}
		case RTPTransceiverDirectionSendonly:
			return []RTPTransceiverDirection{RTPTransceiverDirectionRecvonly}
		case RTPTransceiverDirectionRecvonly:
			return []RTPTransceiverDirection{RTPTransceiverDirectionSendonly, RTPTransceiverDirectionSendrecv}
		default:
			return []RTPTransceiverDirection{}
		}
	}

	for _, possibleDirection := range getPreferredDirections() {
		for i := range localTransceivers {
			t := localTransceivers[i]
			if t.Mid() == "" && t.kind == remoteKind && possibleDirection == t.Direction() {
				return t, append(localTransceivers[:i], localTransceivers[i+1:]...)
			}
		}
	}

	return nil, localTransceivers
}

func handleUnknownRTPPacket(
	buf []byte,
	midExtensionID,
	streamIDExtensionID,
	repairStreamIDExtensionID uint8,
) (mid, rid, rsid string, paddingOnly bool, err error) {
	rp := &rtp.Packet{}
	if err = rp.Unmarshal(buf); err != nil {
		return mid, rid, rsid, false, err
	}

	isPaddingOnlyPacket := rp.Padding && len(rp.Payload) == 0

	if !rp.Header.Extension {
		return mid, rid, rsid, isPaddingOnlyPacket, nil
	}

	if payload := rp.GetExtension(midExtensionID); payload != nil {
		mid = string(payload)
	}

	if payload := rp.GetExtension(streamIDExtensionID); payload != nil {
		rid = string(payload)
	}

	if payload := rp.GetExtension(repairStreamIDExtensionID); payload != nil {
		rsid = string(payload)
	}

	return mid, rid, rsid, isPaddingOnlyPacket, nil
}

const sctpMaxChannels = uint16(65535)

var errSCTPDisabled = errors.New("SCTP/data channels are disabled in this build")

type SCTPTransport struct {
	lock                       sync.RWMutex
	dtlsTransport              *DTLSTransport
	state                      SCTPTransportState
	isStarted                  bool
	maxChannels                *uint16
	onErrorHandler             func(error)
	onCloseHandler             func(error)
	onDataChannelHandler       func(*DataChannel)
	onDataChannelOpenedHandler func(*DataChannel)
	dataChannels               []*DataChannel
	dataChannelIDsUsed         map[uint16]struct{}
	dataChannelsOpened         uint32
	dataChannelsRequested      uint32
	dataChannelsAccepted       uint32
	api                        *API
	log                        logging.LeveledLogger
}

func (api *API) NewSCTPTransport(dtls *DTLSTransport) *SCTPTransport {
	mc := sctpMaxChannels
	return &SCTPTransport{
		dtlsTransport:      dtls,
		state:              SCTPTransportStateConnecting,
		api:                api,
		log:                api.settingEngine.LoggerFactory.NewLogger("ortc"),
		dataChannelIDsUsed: make(map[uint16]struct{}),
		maxChannels:        &mc,
	}
}

func (r *SCTPTransport) Transport() *DTLSTransport { return r.dtlsTransport }

func (r *SCTPTransport) GetCapabilities() SCTPCapabilities {
	return SCTPCapabilities{MaxMessageSize: 0}
}

func (r *SCTPTransport) Start(_ SCTPCapabilities) error {
	r.lock.Lock()
	r.isStarted = true
	r.state = SCTPTransportStateConnected
	r.lock.Unlock()
	return nil
}

func (r *SCTPTransport) Stop() error {
	r.lock.Lock()
	r.state = SCTPTransportStateClosed
	r.lock.Unlock()
	return nil
}

func (r *SCTPTransport) OnError(f func(err error)) {
	r.lock.Lock()
	r.onErrorHandler = f
	r.lock.Unlock()
}

func (r *SCTPTransport) OnClose(f func(err error)) {
	r.lock.Lock()
	r.onCloseHandler = f
	r.lock.Unlock()
}

func (r *SCTPTransport) OnDataChannel(f func(*DataChannel)) {
	r.lock.Lock()
	r.onDataChannelHandler = f
	r.lock.Unlock()
}

func (r *SCTPTransport) OnDataChannelOpened(f func(*DataChannel)) {
	r.lock.Lock()
	r.onDataChannelOpenedHandler = f
	r.lock.Unlock()
}

func (r *SCTPTransport) MaxChannels() uint16 {
	if r.maxChannels == nil {
		return sctpMaxChannels
	}
	return *r.maxChannels
}

func (r *SCTPTransport) State() SCTPTransportState {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return r.state
}

func (r *SCTPTransport) Metadata() (SCTPTransportMetadata, bool) {
	return SCTPTransportMetadata{}, false
}

func (r *SCTPTransport) Stats() SCTPTransportStats { return SCTPTransportStats{} }

func (r *SCTPTransport) collectStats(_ *statsReportCollector) {}

func (r *SCTPTransport) BufferedAmount() int { return 0 }

func (r *SCTPTransport) GetSctpInit() []byte { return nil }

type trackDetails struct {
	mid      string
	kind     RTPCodecType
	streamID string
	id       string
	ssrcs    []SSRC
	rtxSsrc  *SSRC
	fecSsrc  *SSRC
	rids     []string
}

func trackDetailsForSSRC(trackDetails []trackDetails, ssrc SSRC) *trackDetails {
	for i := range trackDetails {
		if slices.Contains(trackDetails[i].ssrcs, ssrc) {
			return &trackDetails[i]
		}
	}

	return nil
}

func trackDetailsForRID(trackDetails []trackDetails, mid, rid string) *trackDetails {
	for i := range trackDetails {
		if trackDetails[i].mid != mid {
			continue
		}

		if slices.Contains(trackDetails[i].rids, rid) {
			return &trackDetails[i]
		}
	}

	return nil
}

func filterTrackWithSSRC(incomingTracks []trackDetails, ssrc SSRC) []trackDetails {
	filtered := []trackDetails{}
	doesTrackHaveSSRC := func(t trackDetails) bool {
		return slices.Contains(t.ssrcs, ssrc)
	}

	for i := range incomingTracks {
		if !doesTrackHaveSSRC(incomingTracks[i]) {
			filtered = append(filtered, incomingTracks[i])
		}
	}

	return filtered
}

func trackDetailsFromSDP(
	log logging.LeveledLogger,
	s *sdp.SessionDescription,
) (incomingTracks []trackDetails) {
	for _, media := range s.MediaDescriptions {
		tracksInMediaSection := []trackDetails{}
		rtxRepairFlows := map[uint64]uint64{}
		fecRepairFlows := map[uint64]uint64{}

		streamID := ""
		trackID := ""

		if _, ok := media.Attribute(sdp.AttrKeyRecvOnly); ok {
			continue
		} else if _, ok := media.Attribute(sdp.AttrKeyInactive); ok {
			continue
		}

		midValue := getMidValue(media)
		if midValue == "" {
			continue
		}

		codecType := NewRTPCodecType(media.MediaName.Media)
		if codecType == 0 {
			continue
		}

		for _, attr := range media.Attributes {
			switch attr.Key {
			case sdp.AttrKeySSRCGroup:
				split := strings.Split(attr.Value, " ")
				if split[0] == sdp.SemanticTokenFlowIdentification {

					if len(split) == 3 {
						baseSsrc, err := strconv.ParseUint(split[1], 10, 32)
						if err != nil {
							log.Warnf("Failed to parse SSRC: %v", err)

							continue
						}
						rtxRepairFlow, err := strconv.ParseUint(split[2], 10, 32)
						if err != nil {
							log.Warnf("Failed to parse SSRC: %v", err)

							continue
						}
						rtxRepairFlows[rtxRepairFlow] = baseSsrc
						tracksInMediaSection = filterTrackWithSSRC(
							tracksInMediaSection,
							SSRC(rtxRepairFlow),
						)
						for i := range tracksInMediaSection {
							if tracksInMediaSection[i].ssrcs[0] == SSRC(baseSsrc) {
								repairSsrc := SSRC(rtxRepairFlow)
								tracksInMediaSection[i].rtxSsrc = &repairSsrc
							}
						}
					}
				} else if split[0] == sdp.SemanticTokenForwardErrorCorrectionFramework {

					if len(split) == 3 {
						baseSsrc, err := strconv.ParseUint(split[1], 10, 32)
						if err != nil {
							log.Warnf("Failed to parse SSRC: %v", err)

							continue
						}
						fecRepairFlow, err := strconv.ParseUint(split[2], 10, 32)
						if err != nil {
							log.Warnf("Failed to parse SSRC: %v", err)

							continue
						}
						fecRepairFlows[fecRepairFlow] = baseSsrc
						tracksInMediaSection = filterTrackWithSSRC(
							tracksInMediaSection,
							SSRC(fecRepairFlow),
						)
						for i := range tracksInMediaSection {
							if tracksInMediaSection[i].ssrcs[0] == SSRC(baseSsrc) {
								repairSsrc := SSRC(fecRepairFlow)
								tracksInMediaSection[i].fecSsrc = &repairSsrc
							}
						}
					}
				}

			case sdp.AttrKeyMsid:
				split := strings.Split(attr.Value, " ")
				if len(split) == 2 {
					streamID = split[0]
					trackID = split[1]
				}

			case sdp.AttrKeySSRC:
				split := strings.Split(attr.Value, " ")
				ssrc, err := strconv.ParseUint(split[0], 10, 32)
				if err != nil {
					log.Warnf("Failed to parse SSRC: %v", err)

					continue
				}

				if _, ok := rtxRepairFlows[ssrc]; ok {
					continue
				}
				if _, ok := fecRepairFlows[ssrc]; ok {
					continue
				}

				if len(split) == 3 && strings.HasPrefix(split[1], "msid:") {
					streamID = split[1][len("msid:"):]
					trackID = split[2]
				}

				isNewTrack := true
				trackDetails := &trackDetails{}
				for i := range tracksInMediaSection {
					for j := range tracksInMediaSection[i].ssrcs {
						if tracksInMediaSection[i].ssrcs[j] == SSRC(ssrc) {
							trackDetails = &tracksInMediaSection[i]
							isNewTrack = false
						}
					}
				}

				trackDetails.mid = midValue
				trackDetails.kind = codecType
				trackDetails.streamID = streamID
				trackDetails.id = trackID
				trackDetails.ssrcs = []SSRC{SSRC(ssrc)}

				for r, baseSsrc := range rtxRepairFlows {
					if baseSsrc == ssrc {
						repairSsrc := SSRC(r)
						trackDetails.rtxSsrc = &repairSsrc
					}
				}
				for r, baseSsrc := range fecRepairFlows {
					if baseSsrc == ssrc {
						fecSsrc := SSRC(r)
						trackDetails.fecSsrc = &fecSsrc
					}
				}

				if isNewTrack {
					tracksInMediaSection = append(tracksInMediaSection, *trackDetails)
				}
			}
		}

		if rids := getRids(media); len(rids) != 0 && trackID != "" && streamID != "" {
			simulcastTrack := trackDetails{
				mid:      midValue,
				kind:     codecType,
				streamID: streamID,
				id:       trackID,
				rids:     []string{},
			}
			for _, rid := range rids {
				simulcastTrack.rids = append(simulcastTrack.rids, rid.id)
			}

			tracksInMediaSection = []trackDetails{simulcastTrack}
		}

		incomingTracks = append(incomingTracks, tracksInMediaSection...)
	}

	return incomingTracks
}

func trackDetailsToRTPReceiveParameters(trackDetails *trackDetails) RTPReceiveParameters {
	encodingSize := max(len(trackDetails.rids), len(trackDetails.ssrcs))

	encodings := make([]RTPDecodingParameters, encodingSize)
	for i := range encodings {
		if len(trackDetails.rids) > i {
			encodings[i].RID = trackDetails.rids[i]
		}
		if len(trackDetails.ssrcs) > i {
			encodings[i].SSRC = trackDetails.ssrcs[i]
		}

		if trackDetails.rtxSsrc != nil {
			encodings[i].RTX.SSRC = *trackDetails.rtxSsrc
		}

		if trackDetails.fecSsrc != nil {
			encodings[i].FEC.SSRC = *trackDetails.fecSsrc
		}
	}

	return RTPReceiveParameters{Encodings: encodings}
}

func getRids(media *sdp.MediaDescription) []*simulcastRid {
	rids := []*simulcastRid{}
	var simulcastAttr string
	for _, attr := range media.Attributes {
		switch attr.Key {
		case sdpAttributeRid:
			split := strings.Split(attr.Value, " ")
			rids = append(rids, &simulcastRid{id: split[0], attrValue: attr.Value})
		case sdpAttributeSimulcast:
			simulcastAttr = attr.Value
		}
	}

	if simulcastAttr != "" {
		if space := strings.Index(simulcastAttr, " "); space > 0 {
			simulcastAttr = simulcastAttr[space+1:]
		}
		ridStates := strings.SplitSeq(simulcastAttr, ";")
		for ridState := range ridStates {
			if ridState[:1] == "~" {
				ridID := ridState[1:]
				for _, rid := range rids {
					if rid.id == ridID {
						rid.paused = true

						break
					}
				}
			}
		}
	}

	return rids
}

func addCandidatesToMediaDescriptions(
	candidates []ICECandidate,
	mediaDescr *sdp.MediaDescription,
	iceGatheringState ICEGatheringState,
) error {
	appendCandidateIfNew := func(c ice.Candidate, attributes []sdp.Attribute) {
		marshaled := c.Marshal()
		for _, a := range attributes {
			if marshaled == a.Value {
				return
			}
		}

		mediaDescr.WithValueAttribute("candidate", marshaled)
	}

	for _, c := range candidates {
		candidate, err := c.ToICE()
		if err != nil {
			return err
		}

		candidate.SetComponent(1)
		appendCandidateIfNew(candidate, mediaDescr.Attributes)

		candidate.SetComponent(2)
		appendCandidateIfNew(candidate, mediaDescr.Attributes)
	}

	if iceGatheringState != ICEGatheringStateComplete {
		return nil
	}
	for _, a := range mediaDescr.Attributes {
		if a.Key == "end-of-candidates" {
			return nil
		}
	}

	mediaDescr.WithPropertyAttribute("end-of-candidates")

	return nil
}

func addDataMediaSection(
	descr *sdp.SessionDescription,
	shouldAddCandidates bool,
	dtlsFingerprints []DTLSFingerprint,
	midValue string,
	iceParams ICEParameters,
	candidates []ICECandidate,
	dtlsRole sdp.ConnectionRole,
	iceGatheringState ICEGatheringState,
	sctpMaxMessageSize uint32,
	sctpInit []byte,
) error {
	media := (&sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   mediaSectionApplication,
			Port:    sdp.RangedPort{Value: 9},
			Protos:  []string{"UDP", "DTLS", "SCTP"},
			Formats: []string{"webrtc-datachannel"},
		},
		ConnectionInformation: &sdp.ConnectionInformation{
			NetworkType: "IN",
			AddressType: "IP4",
			Address: &sdp.Address{
				Address: "0.0.0.0",
			},
		},
	}).
		WithValueAttribute(sdp.AttrKeyConnectionSetup, dtlsRole.String()).
		WithValueAttribute(sdp.AttrKeyMID, midValue).
		WithPropertyAttribute(RTPTransceiverDirectionSendrecv.String()).
		WithPropertyAttribute("sctp-port:5000").
		WithValueAttribute("max-message-size", fmt.Sprintf("%d", sctpMaxMessageSize)).
		WithICECredentials(iceParams.UsernameFragment, iceParams.Password)

	if len(sctpInit) != 0 {
		media = media.WithValueAttribute("sctp-init", base64.StdEncoding.EncodeToString(sctpInit))
	}
	for _, f := range dtlsFingerprints {
		media = media.WithFingerprint(f.Algorithm, strings.ToUpper(f.Value))
	}

	if shouldAddCandidates {
		if err := addCandidatesToMediaDescriptions(candidates, media, iceGatheringState); err != nil {
			return err
		}
	}

	descr.WithMedia(media)

	return nil
}

func populateLocalCandidates(
	sessionDescription *SessionDescription,
	i *ICEGatherer,
	iceGatheringState ICEGatheringState,
) *SessionDescription {
	if sessionDescription == nil || i == nil {
		return sessionDescription
	}

	candidates, err := i.GetLocalCandidates()
	if err != nil {
		return sessionDescription
	}

	parsed := sessionDescription.parsed
	if len(parsed.MediaDescriptions) > 0 {
		mediaDescr := parsed.MediaDescriptions[0]
		if err = addCandidatesToMediaDescriptions(candidates, mediaDescr, iceGatheringState); err != nil {
			return sessionDescription
		}
	}

	sdp, err := parsed.Marshal()
	if err != nil {
		return sessionDescription
	}

	return &SessionDescription{
		SDP:    string(sdp),
		Type:   sessionDescription.Type,
		parsed: parsed,
	}
}

func addSenderSDP(
	mediaSection mediaSection,
	isPlanB bool,
	media *sdp.MediaDescription,
) {
	for _, mt := range mediaSection.transceivers {
		sender := mt.Sender()
		if sender == nil {
			continue
		}

		track := sender.Track()
		if track == nil {
			continue
		}

		sendParameters := sender.GetParameters()
		for _, encoding := range sendParameters.Encodings {
			if encoding.RTX.SSRC != 0 {
				media = media.WithValueAttribute(
					"ssrc-group",
					fmt.Sprintf(
						"%s %d %d",
						sdp.SemanticTokenFlowIdentification,
						encoding.SSRC,
						encoding.RTX.SSRC,
					),
				)
			}
			if encoding.FEC.SSRC != 0 {
				media = media.WithValueAttribute(
					"ssrc-group",
					fmt.Sprintf(
						"%s %d %d",
						sdp.SemanticTokenForwardErrorCorrectionFramework,
						encoding.SSRC,
						encoding.FEC.SSRC,
					),
				)
			}

			media = media.WithMediaSource(
				uint32(encoding.SSRC),
				track.StreamID(),
				track.StreamID(),
				track.ID(),
			)

			if !isPlanB {
				if encoding.RTX.SSRC != 0 {
					media = media.WithMediaSource(
						uint32(encoding.RTX.SSRC),
						track.StreamID(),
						track.StreamID(),
						track.ID(),
					)
				}
				if encoding.FEC.SSRC != 0 {
					media = media.WithMediaSource(
						uint32(encoding.FEC.SSRC),
						track.StreamID(),
						track.StreamID(),
						track.ID(),
					)
				}

				media = media.WithPropertyAttribute("msid:" + track.StreamID() + " " + track.ID())
			}
		}

		if len(sendParameters.Encodings) > 1 {
			sendRids := make([]string, 0, len(sendParameters.Encodings))

			for _, encoding := range sendParameters.Encodings {
				media.WithValueAttribute(sdpAttributeRid, encoding.RID+" send")
				sendRids = append(sendRids, encoding.RID)
			}

			media.WithValueAttribute(sdpAttributeSimulcast, "send "+strings.Join(sendRids, ";"))
		}

		if !isPlanB {
			break
		}
	}
}

func addTransceiverSDP(
	descr *sdp.SessionDescription,
	isPlanB bool,
	shouldAddCandidates bool,
	dtlsFingerprints []DTLSFingerprint,
	mediaEngine *MediaEngine,
	midValue string,
	iceParams ICEParameters,
	candidates []ICECandidate,
	dtlsRole sdp.ConnectionRole,
	iceGatheringState ICEGatheringState,
	mediaSection mediaSection,
	ignoreRidPauseForRecv bool,
) (bool, error) {
	transceivers := mediaSection.transceivers
	if len(transceivers) < 1 {
		return false, errSDPZeroTransceivers
	}

	transceiver := transceivers[0]
	media := sdp.NewJSEPMediaDescription(transceiver.kind.String(), []string{}).
		WithValueAttribute(sdp.AttrKeyConnectionSetup, dtlsRole.String()).
		WithValueAttribute(sdp.AttrKeyMID, midValue).
		WithICECredentials(iceParams.UsernameFragment, iceParams.Password).
		WithPropertyAttribute(sdp.AttrKeyRTCPMux).
		WithPropertyAttribute(sdp.AttrKeyRTCPRsize)

	codecs := transceiver.getCodecs()
	for _, codec := range codecs {
		name := strings.TrimPrefix(codec.MimeType, "audio/")
		name = strings.TrimPrefix(name, "video/")
		media.WithCodec(uint8(codec.PayloadType), name, codec.ClockRate, codec.Channels, codec.SDPFmtpLine)

		for _, feedback := range codec.RTPCodecCapability.RTCPFeedback {
			if feedback.Parameter == "" {
				media.WithValueAttribute("rtcp-fb", fmt.Sprintf("%d %s", codec.PayloadType, feedback.Type))
			} else {
				media.WithValueAttribute("rtcp-fb", fmt.Sprintf("%d %s %s", codec.PayloadType, feedback.Type, feedback.Parameter))
			}
		}
	}
	if len(codecs) == 0 {

		if transceiver.Sender() != nil {
			return false, ErrSenderWithNoCodecs
		}

		descr.WithMedia(&sdp.MediaDescription{
			MediaName: sdp.MediaName{
				Media:   transceiver.kind.String(),
				Port:    sdp.RangedPort{Value: 0},
				Protos:  []string{"UDP", "TLS", "RTP", "SAVPF"},
				Formats: []string{"0"},
			},
			ConnectionInformation: &sdp.ConnectionInformation{
				NetworkType: "IN",
				AddressType: "IP4",
				Address: &sdp.Address{
					Address: "0.0.0.0",
				},
			},
		})

		return false, nil
	}

	directions := []RTPTransceiverDirection{}
	if transceiver.Sender() != nil {
		directions = append(directions, RTPTransceiverDirectionSendonly)
	}
	if transceiver.Receiver() != nil {
		directions = append(directions, RTPTransceiverDirectionRecvonly)
	}

	parameters := mediaEngine.getRTPParametersByKind(transceiver.kind, directions)
	for _, rtpExtension := range parameters.HeaderExtensions {
		if mediaSection.matchExtensions != nil {
			if _, enabled := mediaSection.matchExtensions[rtpExtension.URI]; !enabled {
				continue
			}
		}
		extURL, err := url.Parse(rtpExtension.URI)
		if err != nil {
			return false, err
		}
		media.WithExtMap(sdp.ExtMap{Value: rtpExtension.ID, URI: extURL})
	}

	if len(mediaSection.rids) > 0 {
		recvRids := make([]string, 0, len(mediaSection.rids))

		for _, rid := range mediaSection.rids {
			ridID := rid.id
			media.WithValueAttribute(sdpAttributeRid, ridID+" recv")
			if rid.paused && !ignoreRidPauseForRecv {
				ridID = "~" + ridID
			}
			recvRids = append(recvRids, ridID)
		}

		media.WithValueAttribute(sdpAttributeSimulcast, "recv "+strings.Join(recvRids, ";"))
	}

	addSenderSDP(mediaSection, isPlanB, media)

	media = media.WithPropertyAttribute(transceiver.Direction().String())

	for _, fingerprint := range dtlsFingerprints {
		media = media.WithFingerprint(fingerprint.Algorithm, strings.ToUpper(fingerprint.Value))
	}

	if shouldAddCandidates {
		if err := addCandidatesToMediaDescriptions(candidates, media, iceGatheringState); err != nil {
			return false, err
		}
	}

	descr.WithMedia(media)

	return true, nil
}

type simulcastRid struct {
	id        string
	attrValue string
	paused    bool
}

type mediaSection struct {
	id              string
	transceivers    []*RTPTransceiver
	data            bool
	sctpInit        []byte
	matchExtensions map[string]int
	rids            []*simulcastRid
}

func bundleMatchFromRemote(matchBundleGroup *string) func(mid string) bool {
	if matchBundleGroup == nil {
		return func(string) bool {
			return true
		}
	}
	bundleTags := strings.Split(*matchBundleGroup, " ")

	return func(midValue string) bool {
		return slices.Contains(bundleTags, midValue)
	}
}

func populateSDP(
	descr *sdp.SessionDescription,
	isPlanB bool,
	dtlsFingerprints []DTLSFingerprint,
	mediaDescriptionFingerprint bool,
	isICELite bool,
	isExtmapAllowMixed bool,
	mediaEngine *MediaEngine,
	connectionRole sdp.ConnectionRole,
	candidates []ICECandidate,
	iceParams ICEParameters,
	mediaSections []mediaSection,
	iceGatheringState ICEGatheringState,
	matchBundleGroup *string,
	sctpMaxMessageSize uint32,
	ignoreRidPauseForRecv bool,
) (*sdp.SessionDescription, error) {
	var err error
	mediaDtlsFingerprints := []DTLSFingerprint{}

	if mediaDescriptionFingerprint {
		mediaDtlsFingerprints = dtlsFingerprints
	}

	bundleValue := "BUNDLE"
	bundleCount := 0

	bundleMatch := bundleMatchFromRemote(matchBundleGroup)
	appendBundle := func(midValue string) {
		bundleValue += " " + midValue
		bundleCount++
	}

	for i, section := range mediaSections {
		if section.data && len(section.transceivers) != 0 {
			return nil, errSDPMediaSectionMediaDataChanInvalid
		} else if !isPlanB && len(section.transceivers) > 1 {
			return nil, errSDPMediaSectionMultipleTrackInvalid
		}

		shouldAddID := true
		shouldAddCandidates := i == 0
		if section.data {
			if err = addDataMediaSection(
				descr,
				shouldAddCandidates,
				mediaDtlsFingerprints,
				section.id,
				iceParams,
				candidates,
				connectionRole,
				iceGatheringState,
				sctpMaxMessageSize,
				section.sctpInit,
			); err != nil {
				return nil, err
			}
		} else {
			shouldAddID, err = addTransceiverSDP(
				descr,
				isPlanB,
				shouldAddCandidates,
				mediaDtlsFingerprints,
				mediaEngine,
				section.id,
				iceParams,
				candidates,
				connectionRole,
				iceGatheringState,
				section,
				ignoreRidPauseForRecv,
			)
			if err != nil {
				return nil, err
			}
		}

		if shouldAddID {
			if bundleMatch(section.id) {
				appendBundle(section.id)
			} else {
				descr.MediaDescriptions[len(descr.MediaDescriptions)-1].MediaName.Port = sdp.RangedPort{Value: 0}
			}
		}
	}

	if !mediaDescriptionFingerprint {
		for _, fingerprint := range dtlsFingerprints {
			descr.WithFingerprint(fingerprint.Algorithm, strings.ToUpper(fingerprint.Value))
		}
	}

	if isICELite {

		descr = descr.WithValueAttribute(sdp.AttrKeyICELite, "")
	}

	if isExtmapAllowMixed {
		descr = descr.WithPropertyAttribute(sdp.AttrKeyExtMapAllowMixed)
	}

	if bundleCount > 0 {
		descr = descr.WithValueAttribute(sdp.AttrKeyGroup, bundleValue)
	}

	return descr, nil
}

func getMidValue(media *sdp.MediaDescription) string {
	for _, attr := range media.Attributes {
		if attr.Key == "mid" {
			return attr.Value
		}
	}

	return ""
}

func descriptionIsPlanB(desc *SessionDescription, log logging.LeveledLogger) bool {
	if desc == nil || desc.parsed == nil {
		return false
	}

	midWithTrack := map[string]bool{}

	for _, trackDetail := range trackDetailsFromSDP(log, desc.parsed) {
		if _, ok := midWithTrack[trackDetail.mid]; ok {
			return true
		}
		midWithTrack[trackDetail.mid] = true
	}

	return false
}

func descriptionPossiblyPlanB(desc *SessionDescription) bool {
	if desc == nil || desc.parsed == nil {
		return false
	}

	detectionRegex := regexp.MustCompile(`(?i)^(audio|video|data)$`)
	for _, media := range desc.parsed.MediaDescriptions {
		if len(detectionRegex.FindStringSubmatch(getMidValue(media))) == 2 {
			return true
		}
	}

	return false
}

func getPeerDirection(media *sdp.MediaDescription) RTPTransceiverDirection {
	for _, a := range media.Attributes {
		if direction := NewRTPTransceiverDirection(a.Key); direction != RTPTransceiverDirectionUnknown {
			return direction
		}
	}

	return RTPTransceiverDirectionUnknown
}

func extractBundleID(desc *sdp.SessionDescription) string {
	groupAttribute, _ := desc.Attribute(sdp.AttrKeyGroup)

	isBundled := strings.Contains(groupAttribute, "BUNDLE")

	if !isBundled {
		return ""
	}

	bundleIDs := strings.Split(groupAttribute, " ")

	if len(bundleIDs) < 2 {
		return ""
	}

	return bundleIDs[1]
}

func extractFingerprint(desc *sdp.SessionDescription) (string, string, error) {
	fingerprint := ""

	if sessionFingerprint, haveFingerprint := desc.Attribute("fingerprint"); haveFingerprint {
		fingerprint = sessionFingerprint
	}

	if fingerprint == "" {
		bundleID := extractBundleID(desc)
		if bundleID != "" {

			for _, mediaDescr := range desc.MediaDescriptions {
				if mid, haveMid := mediaDescr.Attribute("mid"); haveMid {
					if mid == bundleID && fingerprint == "" {
						if mediaFingerprint, haveFingerprint := mediaDescr.Attribute("fingerprint"); haveFingerprint {
							fingerprint = mediaFingerprint
						}
					}
				}
			}
		} else {

			for _, mediaDescr := range desc.MediaDescriptions {
				mediaFingerprint, haveFingerprint := mediaDescr.Attribute("fingerprint")
				if haveFingerprint && fingerprint == "" {
					fingerprint = mediaFingerprint
				}
			}
		}
	}

	if fingerprint == "" {
		return "", "", ErrSessionDescriptionNoFingerprint
	}

	parts := strings.Split(fingerprint, " ")
	if len(parts) != 2 {
		return "", "", ErrSessionDescriptionInvalidFingerprint
	}

	return parts[1], parts[0], nil
}

type identifiedMediaDescription struct {
	MediaDescription *sdp.MediaDescription
	SDPMid           string
	SDPMLineIndex    uint16
}

func extractICEDetailsFromMedia(
	media *identifiedMediaDescription,
	log logging.LeveledLogger,
) (string, string, []ICECandidate, error) {
	remoteUfrag := ""
	remotePwd := ""
	candidates := []ICECandidate{}
	descr := media.MediaDescription

	if ufrag, haveUfrag := descr.Attribute("ice-ufrag"); haveUfrag {
		remoteUfrag = ufrag
	}
	if pwd, havePwd := descr.Attribute("ice-pwd"); havePwd {
		remotePwd = pwd
	}

	var prevErr error

	for _, attr := range descr.Attributes {
		if !attr.IsICECandidate() {
			continue
		}

		cand, err := ice.UnmarshalCandidate(attr.Value)
		if err != nil {

			if errors.Is(err, ice.ErrUnknownCandidateTyp) || errors.Is(err, ice.ErrDetermineNetworkType) {
				if log != nil {
					log.Warnf("Discarding remote candidate: %s", err)
				}

				continue
			}

			if log != nil {
				log.Warnf("Failed to parse remote candidate %q: %v", attr.Value, err)
			}

			prevErr = err

			continue
		}

		candidate, err := newICECandidateFromICE(cand, media.SDPMid, media.SDPMLineIndex)
		if err != nil {
			if log != nil {
				log.Warnf("Failed to convert remote candidate %q: %v", attr.Value, err)
			}

			prevErr = err

			continue
		}

		candidates = append(candidates, candidate)
	}

	if len(candidates) == 0 && prevErr != nil {
		return "", "", nil, prevErr
	}

	return remoteUfrag, remotePwd, candidates, nil
}

type sdpICEDetails struct {
	Ufrag      string
	Password   string
	Candidates []ICECandidate
}

func extractICEDetails(
	desc *sdp.SessionDescription,
	log logging.LeveledLogger,
) (*sdpICEDetails, error) {
	details := &sdpICEDetails{
		Candidates: []ICECandidate{},
	}

	if ufrag, haveUfrag := desc.Attribute("ice-ufrag"); haveUfrag {
		details.Ufrag = ufrag
	}
	if pwd, havePwd := desc.Attribute("ice-pwd"); havePwd {
		details.Password = pwd
	}

	mediaDescr, ok := selectCandidateMediaSection(desc)
	if ok {
		ufrag, pwd, candidates, err := extractICEDetailsFromMedia(mediaDescr, log)
		if err != nil {
			return nil, err
		}

		if details.Ufrag == "" && ufrag != "" {
			details.Ufrag = ufrag
			details.Password = pwd
		}

		details.Candidates = candidates
	}

	if details.Ufrag == "" {
		return nil, ErrSessionDescriptionMissingIceUfrag
	} else if details.Password == "" {
		return nil, ErrSessionDescriptionMissingIcePwd
	}

	return details, nil
}

func selectCandidateMediaSection(sessionDescription *sdp.SessionDescription) (
	descr *identifiedMediaDescription,
	ok bool,
) {
	bundleID := extractBundleID(sessionDescription)

	for mLineIndex, mediaDescr := range sessionDescription.MediaDescriptions {
		mid := getMidValue(mediaDescr)

		if bundleID != "" {
			if mid == bundleID {
				return &identifiedMediaDescription{
					MediaDescription: mediaDescr,
					SDPMid:           mid,
					SDPMLineIndex:    uint16(mLineIndex),
				}, true
			}
		} else {

			return &identifiedMediaDescription{
				MediaDescription: mediaDescr,
				SDPMid:           mid,
				SDPMLineIndex:    uint16(mLineIndex),
			}, true
		}
	}

	return nil, false
}

func getByMid(searchMid string, desc *SessionDescription) *sdp.MediaDescription {
	for _, m := range desc.parsed.MediaDescriptions {
		if mid, ok := m.Attribute(sdp.AttrKeyMID); ok && mid == searchMid {
			return m
		}
	}

	return nil
}

func haveDataChannel(desc *SessionDescription) *sdp.MediaDescription {
	for _, d := range desc.parsed.MediaDescriptions {
		if d.MediaName.Media == mediaSectionApplication {
			return d
		}
	}

	return nil
}

func codecsFromMediaDescription(mediaDescr *sdp.MediaDescription) (out []RTPCodecParameters, err error) {
	s := &sdp.SessionDescription{
		MediaDescriptions: []*sdp.MediaDescription{mediaDescr},
	}

	for _, payloadStr := range mediaDescr.MediaName.Formats {
		payloadType, err := strconv.ParseUint(payloadStr, 10, 8)
		if err != nil {
			return nil, err
		}

		codec, err := s.GetCodecForPayloadType(uint8(payloadType))
		if err != nil {
			if payloadType == 0 {
				continue
			}

			return nil, err
		}

		channels := uint16(0)
		val, err := strconv.ParseUint(codec.EncodingParameters, 10, 16)
		if err == nil {
			channels = uint16(val)
		}

		feedback := []RTCPFeedback{}
		for _, raw := range codec.RTCPFeedback {
			split := strings.Split(raw, " ")
			entry := RTCPFeedback{Type: split[0]}
			if len(split) == 2 {
				entry.Parameter = split[1]
			}

			feedback = append(feedback, entry)
		}

		out = append(out, RTPCodecParameters{
			RTPCodecCapability: RTPCodecCapability{
				mediaDescr.MediaName.Media + "/" + codec.Name,
				codec.ClockRate,
				channels,
				codec.Fmtp,
				feedback,
			},
			PayloadType: PayloadType(payloadType),
		})
	}

	return out, nil
}

func rtpExtensionsFromMediaDescription(m *sdp.MediaDescription) (map[string]int, error) {
	out := map[string]int{}

	for _, a := range m.Attributes {
		if a.Key == sdp.AttrKeyExtMap {
			e := sdp.ExtMap{}
			if err := e.Unmarshal(a.String()); err != nil {
				return nil, err
			}

			out[e.URI.String()] = e.Value
		}
	}

	return out, nil
}

func updateSDPOrigin(origin *sdp.Origin, descr *sdp.SessionDescription) {
	if atomic.CompareAndSwapUint64(&origin.SessionVersion, 0, descr.Origin.SessionVersion) {
		atomic.StoreUint64(&origin.SessionID, descr.Origin.SessionID)
	} else {
		for {
			descr.Origin.SessionID = atomic.LoadUint64(&origin.SessionID)
			if descr.Origin.SessionID != 0 {
				break
			}
		}
		descr.Origin.SessionVersion = atomic.AddUint64(&origin.SessionVersion, 1)
	}
}

func isIceLiteSet(desc *sdp.SessionDescription) bool {
	for _, a := range desc.Attributes {
		if strings.TrimSpace(a.Key) == sdp.AttrKeyICELite {
			return true
		}
	}

	return false
}

func isExtMapAllowMixedSet(desc *sdp.SessionDescription) bool {
	for _, a := range desc.Attributes {
		if strings.TrimSpace(a.Key) == sdp.AttrKeyExtMapAllowMixed {
			return true
		}
	}

	return false
}

func getMaxMessageSize(desc *sdp.MediaDescription) uint32 {
	for _, a := range desc.Attributes {
		if strings.TrimSpace(a.Key) == "max-message-size" {
			if v, err := strconv.ParseUint(a.Value, 10, 32); err == nil {
				return uint32(v)
			}
		}
	}

	return 0
}

func getSctpInit(desc *sdp.MediaDescription) ([]byte, error) {
	for _, a := range desc.Attributes {
		if strings.TrimSpace(a.Key) == "sctp-init" {
			decoded, err := base64.StdEncoding.DecodeString(a.Value)
			if err != nil {
				return nil, err
			}

			return decoded, nil
		}
	}

	return nil, nil
}

type SettingEngine struct {
	ephemeralUDP struct {
		PortMin uint16
		PortMax uint16
	}
	detach struct {
		DataChannels bool
	}
	timeout struct {
		ICEDisconnectedTimeout    *time.Duration
		ICEFailedTimeout          *time.Duration
		ICEKeepaliveInterval      *time.Duration
		ICEHostAcceptanceMinWait  *time.Duration
		ICESrflxAcceptanceMinWait *time.Duration
		ICEPrflxAcceptanceMinWait *time.Duration
		ICERelayAcceptanceMinWait *time.Duration
		ICESTUNGatherTimeout      *time.Duration
	}
	renomination renominationSettings
	candidates   struct {
		ICELite                  bool
		ICENetworkTypes          []NetworkType
		InterfaceFilter          func(string) (keep bool)
		IPFilter                 func(net.IP) (keep bool)
		RemoteIPFilter           func(net.IP) (keep bool)
		NAT1To1IPs               []string
		NAT1To1IPCandidateType   ICECandidateType
		addressRewriteRules      []ice.AddressRewriteRule
		MulticastDNSMode         ice.MulticastDNSMode
		MulticastDNSHostName     string
		UsernameFragment         string
		Password                 string
		IncludeLoopbackCandidate bool
	}
	replayProtection struct {
		DTLS  *uint
		SRTP  *uint
		SRTCP *uint
	}
	dtls struct {
		insecureSkipHelloVerify       bool
		disableInsecureSkipVerify     bool
		retransmissionInterval        time.Duration
		ellipticCurves                []dtls.Curve
		connectContextMaker           func() (context.Context, func())
		extendedMasterSecret          dtls.ExtendedMasterSecretType
		clientAuth                    *dtls.ClientAuthType
		clientCAs                     *x509.CertPool
		rootCAs                       *x509.CertPool
		keyLogWriter                  io.Writer
		cipherSuites                  []dtls.CipherSuiteID
		customCipherSuites            func() []dtls.CipherSuite
		clientHelloMessageHook        func(dtls.MessageClientHello) dtls.Message
		serverHelloMessageHook        func(dtls.MessageServerHello) dtls.Message
		certificateRequestMessageHook func(dtls.MessageCertificateRequest) dtls.Message
		supportedProtocols            []string
	}
	sctp struct {
		maxReceiveBufferSize uint32
		enableZeroChecksum   bool
		rtoMax               time.Duration
		maxMessageSize       uint32
		minCwnd              uint32
		fastRtxWnd           uint32
		cwndCAStep           uint32
		enableSnap           bool
	}
	sdpMediaLevelFingerprints                 bool
	answeringDTLSRole                         DTLSRole
	disableCertificateFingerprintVerification bool
	disableSRTPReplayProtection               bool
	disableSRTCPReplayProtection              bool
	net                                       transport.Net
	BufferFactory                             func(packetType transport.BufferPacketType, ssrc uint32) io.ReadWriteCloser
	LoggerFactory                             logging.LoggerFactory
	iceTCPMux                                 ice.TCPMux
	iceUDPMux                                 ice.UDPMux
	iceProxyDialer                            proxy.Dialer
	iceDisableActiveTCP                       bool
	iceBindingRequestHandler                  func(m *stun.Message, local, remote ice.Candidate, pair *ice.CandidatePair) bool
	disableMediaEngineCopy                    bool
	disableMediaEngineMultipleCodecs          bool
	srtpProtectionProfiles                    []dtls.SRTPProtectionProfile
	receiveMTU                                uint
	iceMaxBindingRequests                     *uint16
	fireOnTrackBeforeFirstRTP                 bool
	disableCloseByDTLS                        bool
	dataChannelBlockWrite                     bool
	handleUndeclaredSSRCWithoutAnswer         bool
	ignoreRidPauseForRecv                     bool
}

type renominationSettings struct {
	enabled           bool
	generator         ice.NominationValueGenerator
	automatic         bool
	automaticInterval *time.Duration
	attributeType     *uint16
}

type RenominationOption func(*renominationSettings)

var errInvalidRenominationInterval = errors.New("renomination interval must be greater than zero")

func (e *SettingEngine) SetICERenomination(options ...RenominationOption) error {
	cfg := e.renomination
	for _, opt := range options {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.automaticInterval != nil && *cfg.automaticInterval <= 0 {
		return errInvalidRenominationInterval
	}

	if cfg.generator == nil {
		cfg.generator = ice.DefaultNominationValueGenerator()
	}

	e.renomination.enabled = true
	e.renomination.generator = cfg.generator
	e.renomination.automatic = true
	e.renomination.automaticInterval = cfg.automaticInterval
	e.renomination.attributeType = cfg.attributeType

	return nil
}

func (e *SettingEngine) getSCTPMaxMessageSize() uint32 {
	if e.sctp.maxMessageSize != 0 {
		return e.sctp.maxMessageSize
	}

	return defaultMaxSCTPMessageSize
}

func (e *SettingEngine) getReceiveMTU() uint {
	if e.receiveMTU != 0 {
		return e.receiveMTU
	}

	return receiveMTU
}

func (e *SettingEngine) DetachDataChannels() {
	e.detach.DataChannels = true
}

func (e *SettingEngine) EnableDataChannelBlockWrite(nonblockWrite bool) {
	e.dataChannelBlockWrite = nonblockWrite
}

func (e *SettingEngine) SetSRTPProtectionProfiles(profiles ...dtls.SRTPProtectionProfile) {
	e.srtpProtectionProfiles = profiles
}

func (e *SettingEngine) SetICETimeouts(disconnectedTimeout, failedTimeout, keepAliveInterval time.Duration) {
	e.timeout.ICEDisconnectedTimeout = &disconnectedTimeout
	e.timeout.ICEFailedTimeout = &failedTimeout
	e.timeout.ICEKeepaliveInterval = &keepAliveInterval
}

func (e *SettingEngine) SetHostAcceptanceMinWait(t time.Duration) {
	e.timeout.ICEHostAcceptanceMinWait = &t
}

func (e *SettingEngine) SetSrflxAcceptanceMinWait(t time.Duration) {
	e.timeout.ICESrflxAcceptanceMinWait = &t
}

func (e *SettingEngine) SetPrflxAcceptanceMinWait(t time.Duration) {
	e.timeout.ICEPrflxAcceptanceMinWait = &t
}

func (e *SettingEngine) SetRelayAcceptanceMinWait(t time.Duration) {
	e.timeout.ICERelayAcceptanceMinWait = &t
}

func (e *SettingEngine) SetSTUNGatherTimeout(t time.Duration) {
	e.timeout.ICESTUNGatherTimeout = &t
}

func (e *SettingEngine) SetEphemeralUDPPortRange(portMin, portMax uint16) error {
	if portMax < portMin {
		return ice.ErrPort
	}

	e.ephemeralUDP.PortMin = portMin
	e.ephemeralUDP.PortMax = portMax

	return nil
}

func (e *SettingEngine) SetLite(lite bool) {
	e.candidates.ICELite = lite
}

func (e *SettingEngine) SetNetworkTypes(candidateTypes []NetworkType) {
	e.candidates.ICENetworkTypes = candidateTypes
}

func (e *SettingEngine) SetInterfaceFilter(filter func(string) (keep bool)) {
	e.candidates.InterfaceFilter = filter
}

func (e *SettingEngine) SetIPFilter(filter func(net.IP) (keep bool)) {
	e.candidates.IPFilter = filter
}

func (e *SettingEngine) SetRemoteIPFilter(filter func(net.IP) (keep bool)) {
	e.candidates.RemoteIPFilter = filter
}

func (e *SettingEngine) SetNAT1To1IPs(ips []string, candidateType ICECandidateType) {
	e.candidates.NAT1To1IPs = ips
	e.candidates.NAT1To1IPCandidateType = candidateType
}

func (e *SettingEngine) SetICEAddressRewriteRules(rules ...ICEAddressRewriteRule) error {
	if len(rules) == 0 {
		e.candidates.addressRewriteRules = nil

		return nil
	}

	if len(e.candidates.NAT1To1IPs) > 0 {
		return errAddressRewriteWithNAT1To1
	}

	converted := make([]ice.AddressRewriteRule, 0, len(rules))
	for _, rule := range rules {
		converted = append(converted, rule.toICE())
	}

	e.candidates.addressRewriteRules = converted

	return nil
}

func (e *SettingEngine) SetIncludeLoopbackCandidate(include bool) {
	e.candidates.IncludeLoopbackCandidate = include
}

func (e *SettingEngine) SetAnsweringDTLSRole(role DTLSRole) error {
	if role != DTLSRoleClient && role != DTLSRoleServer {
		return errSettingEngineSetAnsweringDTLSRole
	}

	e.answeringDTLSRole = role

	return nil
}

func (e *SettingEngine) SetNet(net transport.Net) {
	e.net = net
}

func (e *SettingEngine) SetICEMulticastDNSMode(multicastDNSMode ice.MulticastDNSMode) {
	e.candidates.MulticastDNSMode = multicastDNSMode
}

func (e *SettingEngine) SetMulticastDNSHostName(hostName string) {
	e.candidates.MulticastDNSHostName = hostName
}

func (e *SettingEngine) SetICECredentials(usernameFragment, password string) {
	e.candidates.UsernameFragment = usernameFragment
	e.candidates.Password = password
}

func (e *SettingEngine) DisableCertificateFingerprintVerification(isDisabled bool) {
	e.disableCertificateFingerprintVerification = isDisabled
}

func (e *SettingEngine) SetDTLSReplayProtectionWindow(n uint) {
	e.replayProtection.DTLS = &n
}

func (e *SettingEngine) SetSRTPReplayProtectionWindow(n uint) {
	e.disableSRTPReplayProtection = false
	e.replayProtection.SRTP = &n
}

func (e *SettingEngine) SetSRTCPReplayProtectionWindow(n uint) {
	e.disableSRTCPReplayProtection = false
	e.replayProtection.SRTCP = &n
}

func (e *SettingEngine) DisableSRTPReplayProtection(isDisabled bool) {
	e.disableSRTPReplayProtection = isDisabled
}

func (e *SettingEngine) DisableSRTCPReplayProtection(isDisabled bool) {
	e.disableSRTCPReplayProtection = isDisabled
}

func (e *SettingEngine) SetSDPMediaLevelFingerprints(sdpMediaLevelFingerprints bool) {
	e.sdpMediaLevelFingerprints = sdpMediaLevelFingerprints
}

func (e *SettingEngine) SetICETCPMux(tcpMux ice.TCPMux) {
	e.iceTCPMux = tcpMux
}

func (e *SettingEngine) SetICEUDPMux(udpMux ice.UDPMux) {
	e.iceUDPMux = udpMux
}

func (e *SettingEngine) SetICEProxyDialer(d proxy.Dialer) {
	e.iceProxyDialer = d
}

func (e *SettingEngine) SetICEMaxBindingRequests(d uint16) {
	e.iceMaxBindingRequests = &d
}

func (e *SettingEngine) DisableActiveTCP(isDisabled bool) {
	e.iceDisableActiveTCP = isDisabled
}

func (e *SettingEngine) DisableMediaEngineCopy(isDisabled bool) {
	e.disableMediaEngineCopy = isDisabled
}

func (e *SettingEngine) DisableMediaEngineMultipleCodecs(isDisabled bool) {
	e.disableMediaEngineMultipleCodecs = isDisabled
}

func (e *SettingEngine) SetReceiveMTU(receiveMTU uint) {
	e.receiveMTU = receiveMTU
}

func (e *SettingEngine) SetDTLSRetransmissionInterval(interval time.Duration) {
	e.dtls.retransmissionInterval = interval
}

func (e *SettingEngine) SetDTLSInsecureSkipHelloVerify(skip bool) {
	e.dtls.insecureSkipHelloVerify = skip
}

func (e *SettingEngine) SetDTLSDisableInsecureSkipVerify(disable bool) {
	e.dtls.disableInsecureSkipVerify = disable
}

func (e *SettingEngine) SetDTLSEllipticCurves(ellipticCurves ...dtls.Curve) {
	e.dtls.ellipticCurves = ellipticCurves
}

func (e *SettingEngine) SetDTLSConnectContextMaker(connectContextMaker func() (context.Context, func())) {
	e.dtls.connectContextMaker = connectContextMaker
}

func (e *SettingEngine) SetDTLSExtendedMasterSecret(extendedMasterSecret dtls.ExtendedMasterSecretType) {
	e.dtls.extendedMasterSecret = extendedMasterSecret
}

func (e *SettingEngine) SetDTLSClientAuth(clientAuth dtls.ClientAuthType) {
	e.dtls.clientAuth = &clientAuth
}

func (e *SettingEngine) SetDTLSClientCAs(clientCAs *x509.CertPool) {
	e.dtls.clientCAs = clientCAs
}

func (e *SettingEngine) SetDTLSRootCAs(rootCAs *x509.CertPool) {
	e.dtls.rootCAs = rootCAs
}

func (e *SettingEngine) SetDTLSKeyLogWriter(writer io.Writer) {
	e.dtls.keyLogWriter = writer
}

func (e *SettingEngine) SetSCTPMaxReceiveBufferSize(maxReceiveBufferSize uint32) {
	e.sctp.maxReceiveBufferSize = maxReceiveBufferSize
}

func (e *SettingEngine) EnableSCTPZeroChecksum(isEnabled bool) {
	e.sctp.enableZeroChecksum = isEnabled
}

func (e *SettingEngine) EnableSctpSnap(isEnabled bool) {
	e.sctp.enableSnap = isEnabled
}

func (e *SettingEngine) SetSCTPMaxMessageSize(maxMessageSize uint32) {
	e.sctp.maxMessageSize = maxMessageSize
}

func (e *SettingEngine) SetDTLSCipherSuites(cipherSuites ...dtls.CipherSuiteID) {
	e.dtls.cipherSuites = cipherSuites
}

func (e *SettingEngine) SetDTLSCustomerCipherSuites(customCipherSuites func() []dtls.CipherSuite) {
	e.dtls.customCipherSuites = customCipherSuites
}

func (e *SettingEngine) SetDTLSClientHelloMessageHook(hook func(dtls.MessageClientHello) dtls.Message) {
	e.dtls.clientHelloMessageHook = hook
}

func (e *SettingEngine) SetDTLSServerHelloMessageHook(hook func(dtls.MessageServerHello) dtls.Message) {
	e.dtls.serverHelloMessageHook = hook
}

func (e *SettingEngine) SetDTLSCertificateRequestMessageHook(
	hook func(dtls.MessageCertificateRequest) dtls.Message,
) {
	e.dtls.certificateRequestMessageHook = hook
}

func (e *SettingEngine) SetDTLSSupportedProtocols(protocols ...string) {
	e.dtls.supportedProtocols = protocols
}

func (e *SettingEngine) SetSCTPRTOMax(rtoMax time.Duration) {
	e.sctp.rtoMax = rtoMax
}

func (e *SettingEngine) SetSCTPMinCwnd(minCwnd uint32) {
	e.sctp.minCwnd = minCwnd
}

func (e *SettingEngine) SetSCTPFastRtxWnd(fastRtxWnd uint32) {
	e.sctp.fastRtxWnd = fastRtxWnd
}

func (e *SettingEngine) SetSCTPCwndCAStep(cwndCAStep uint32) {
	e.sctp.cwndCAStep = cwndCAStep
}

func (e *SettingEngine) SetICEBindingRequestHandler(
	bindingRequestHandler func(m *stun.Message, local, remote ice.Candidate, pair *ice.CandidatePair) bool,
) {
	e.iceBindingRequestHandler = bindingRequestHandler
}

func (e *SettingEngine) SetFireOnTrackBeforeFirstRTP(fireOnTrackBeforeFirstRTP bool) {
	e.fireOnTrackBeforeFirstRTP = fireOnTrackBeforeFirstRTP
}

func (e *SettingEngine) DisableCloseByDTLS(isEnabled bool) {
	e.disableCloseByDTLS = isEnabled
}

func (e *SettingEngine) SetHandleUndeclaredSSRCWithoutAnswer(handleUndeclaredSSRCWithoutAnswer bool) {
	e.handleUndeclaredSSRCWithoutAnswer = handleUndeclaredSSRCWithoutAnswer
}

func (e *SettingEngine) SetIgnoreRidPauseForRecv(ignoreRidPauseForRecv bool) {
	e.ignoreRidPauseForRecv = ignoreRidPauseForRecv
}

type srtpWriterFuture struct {
	ssrc           SSRC
	rtpSender      *RTPSender
	rtcpReadStream atomic.Value
	rtpWriteStream atomic.Value
	mu             sync.Mutex
	closed         bool
}

func (s *srtpWriterFuture) init(returnWhenNoSRTP bool) error {
	if returnWhenNoSRTP {
		select {
		case <-s.rtpSender.stopCalled:
			return io.ErrClosedPipe
		case <-s.rtpSender.transport.srtpReady:
		default:
			return nil
		}
	} else {
		select {
		case <-s.rtpSender.stopCalled:
			return io.ErrClosedPipe
		case <-s.rtpSender.transport.srtpReady:
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return io.ErrClosedPipe
	}

	srtcpSession, err := s.rtpSender.transport.getSRTCPSession()
	if err != nil {
		return err
	}

	rtcpReadStream, err := srtcpSession.OpenReadStream(uint32(s.ssrc))
	if err != nil {
		return err
	}

	srtpSession, err := s.rtpSender.transport.getSRTPSession()
	if err != nil {
		return err
	}

	rtpWriteStream, err := srtpSession.OpenWriteStream()
	if err != nil {
		return err
	}

	s.rtcpReadStream.Store(rtcpReadStream)
	s.rtpWriteStream.Store(rtpWriteStream)

	return nil
}

func (s *srtpWriterFuture) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if value, ok := s.rtcpReadStream.Load().(*srtp.ReadStreamSRTCP); ok {
		return value.Close()
	}

	return nil
}

func (s *srtpWriterFuture) Read(b []byte) (n int, err error) {
	if value, ok := s.rtcpReadStream.Load().(*srtp.ReadStreamSRTCP); ok {
		return value.Read(b)
	}

	if err := s.init(false); err != nil || s.rtcpReadStream.Load() == nil {
		return 0, err
	}

	return s.Read(b)
}

func (s *srtpWriterFuture) SetReadDeadline(t time.Time) error {
	if value, ok := s.rtcpReadStream.Load().(*srtp.ReadStreamSRTCP); ok {
		return value.SetReadDeadline(t)
	}

	if err := s.init(false); err != nil || s.rtcpReadStream.Load() == nil {
		return err
	}

	return s.SetReadDeadline(t)
}

func (s *srtpWriterFuture) WriteRTP(header *rtp.Header, payload []byte) (int, error) {
	if value, ok := s.rtpWriteStream.Load().(*srtp.WriteStreamSRTP); ok {
		return value.WriteRTP(header, payload)
	}

	if err := s.init(true); err != nil || s.rtpWriteStream.Load() == nil {
		return 0, err
	}

	return s.WriteRTP(header, payload)
}

func (s *srtpWriterFuture) Write(b []byte) (int, error) {
	if value, ok := s.rtpWriteStream.Load().(*srtp.WriteStreamSRTP); ok {
		return value.Write(b)
	}

	if err := s.init(true); err != nil || s.rtpWriteStream.Load() == nil {
		return 0, err
	}

	return s.Write(b)
}

func (r StatsReport) GetConnectionStats(conn *PeerConnection) (PeerConnectionStats, bool) {
	statsID := conn.ID()
	stats, ok := r[statsID]
	if !ok {
		return PeerConnectionStats{}, false
	}

	pcStats, ok := stats.(PeerConnectionStats)
	if !ok {
		return PeerConnectionStats{}, false
	}

	return pcStats, true
}

func (r StatsReport) GetDataChannelStats(dc *DataChannel) (DataChannelStats, bool) {
	statsID := dc.getStatsID()
	stats, ok := r[statsID]
	if !ok {
		return DataChannelStats{}, false
	}

	dcStats, ok := stats.(DataChannelStats)
	if !ok {
		return DataChannelStats{}, false
	}

	return dcStats, true
}

func (r StatsReport) GetICECandidateStats(c *ICECandidate) (ICECandidateStats, bool) {
	statsID := c.statsID
	stats, ok := r[statsID]
	if !ok {
		return ICECandidateStats{}, false
	}

	candidateStats, ok := stats.(ICECandidateStats)
	if !ok {
		return ICECandidateStats{}, false
	}

	return candidateStats, true
}

func (r StatsReport) GetICECandidatePairStats(c *ICECandidatePair) (ICECandidatePairStats, bool) {
	statsID := c.statsID
	stats, ok := r[statsID]
	if !ok {
		return ICECandidatePairStats{}, false
	}

	candidateStats, ok := stats.(ICECandidatePairStats)
	if !ok {
		return ICECandidatePairStats{}, false
	}

	return candidateStats, true
}

func (r StatsReport) GetCertificateStats(c *Certificate) (CertificateStats, bool) {
	statsID := c.statsID
	stats, ok := r[statsID]
	if !ok {
		return CertificateStats{}, false
	}

	certificateStats, ok := stats.(CertificateStats)
	if !ok {
		return CertificateStats{}, false
	}

	return certificateStats, true
}

func (r StatsReport) GetCodecStats(c *RTPCodecParameters) (CodecStats, bool) {
	statsID := c.statsID
	stats, ok := r[statsID]
	if !ok {
		return CodecStats{}, false
	}

	codecStats, ok := stats.(CodecStats)
	if !ok {
		return CodecStats{}, false
	}

	return codecStats, true
}

type AudioPlayoutStatsProvider interface {
	AddTrack(track *TrackRemote) error
	RemoveTrack(track *TrackRemote)
	Snapshot(now time.Time) (AudioPlayoutStats, bool)
}

type trackBinding struct {
	id                          string
	ssrc, ssrcRTX, ssrcFEC      SSRC
	payloadType, payloadTypeRTX PayloadType
	writeStream                 TrackLocalWriter
}

type TrackLocalStaticRTP struct {
	mu                sync.RWMutex
	bindings          []trackBinding
	codec             RTPCodecCapability
	payloader         func(RTPCodecCapability) (rtp.Payloader, error)
	id, rid, streamID string
	initalTimestamp   *uint32
	initialSeqNumber  *uint16
}

func NewTrackLocalStaticRTP(
	c RTPCodecCapability,
	id, streamID string,
	options ...func(*TrackLocalStaticRTP),
) (*TrackLocalStaticRTP, error) {
	t := &TrackLocalStaticRTP{
		codec:    c,
		bindings: []trackBinding{},
		id:       id,
		streamID: streamID,
	}

	for _, option := range options {
		option(t)
	}

	return t, nil
}

func (s *TrackLocalStaticRTP) Bind(trackContext TrackLocalContext) (RTPCodecParameters, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parameters := RTPCodecParameters{RTPCodecCapability: s.codec}
	if codec, matchType := codecParametersFuzzySearch(
		parameters,
		trackContext.CodecParameters(),
	); matchType != codecMatchNone {
		s.bindings = append(s.bindings, trackBinding{
			ssrc:           trackContext.SSRC(),
			ssrcRTX:        trackContext.SSRCRetransmission(),
			ssrcFEC:        trackContext.SSRCForwardErrorCorrection(),
			payloadType:    codec.PayloadType,
			payloadTypeRTX: findRTXPayloadType(codec.PayloadType, trackContext.CodecParameters()),
			writeStream:    trackContext.WriteStream(),
			id:             trackContext.ID(),
		})

		return codec, nil
	}

	return RTPCodecParameters{}, ErrUnsupportedCodec
}

func (s *TrackLocalStaticRTP) Unbind(t TrackLocalContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.bindings {
		if s.bindings[i].id == t.ID() {
			s.bindings[i] = s.bindings[len(s.bindings)-1]
			s.bindings = s.bindings[:len(s.bindings)-1]

			return nil
		}
	}

	return ErrUnbindFailed
}

func (s *TrackLocalStaticRTP) ID() string { return s.id }

func (s *TrackLocalStaticRTP) StreamID() string { return s.streamID }

func (s *TrackLocalStaticRTP) RID() string { return s.rid }

func (s *TrackLocalStaticRTP) Kind() RTPCodecType {
	switch {
	case strings.HasPrefix(s.codec.MimeType, "audio/"):
		return RTPCodecTypeAudio
	case strings.HasPrefix(s.codec.MimeType, "video/"):
		return RTPCodecTypeVideo
	default:
		return RTPCodecType(0)
	}
}

func (s *TrackLocalStaticRTP) Codec() RTPCodecCapability {
	return s.codec
}

var rtpPacketPool = sync.Pool{
	New: func() any {
		return &rtp.Packet{}
	},
}

func resetPacketPoolAllocation(localPacket *rtp.Packet) {
	*localPacket = rtp.Packet{}
	rtpPacketPool.Put(localPacket)
}

func getPacketAllocationFromPool() *rtp.Packet {
	ipacket := rtpPacketPool.Get()

	return ipacket.(*rtp.Packet)
}

func (s *TrackLocalStaticRTP) WriteRTP(p *rtp.Packet) error {
	packet := getPacketAllocationFromPool()

	defer resetPacketPoolAllocation(packet)

	*packet = *p

	return s.writeRTP(packet)
}

func (s *TrackLocalStaticRTP) writeRTP(packet *rtp.Packet) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	writeErrs := []error{}

	for _, b := range s.bindings {
		packet.Header.SSRC = uint32(b.ssrc)
		packet.Header.PayloadType = uint8(b.payloadType)

		if packet.PaddingSize != 0 && packet.Header.PaddingSize == 0 {
			packet.Header.PaddingSize = packet.PaddingSize
		}
		if _, err := b.writeStream.WriteRTP(&packet.Header, packet.Payload); err != nil {
			writeErrs = append(writeErrs, err)
		}
	}

	return wutil.JoinErrors(writeErrs)
}

func (s *TrackLocalStaticRTP) Write(b []byte) (n int, err error) {
	packet := getPacketAllocationFromPool()

	defer resetPacketPoolAllocation(packet)

	if err = packet.Unmarshal(b); err != nil {
		return 0, err
	}

	return len(b), s.writeRTP(packet)
}

type TrackLocalStaticSample struct {
	mu         sync.Mutex
	packetizer rtp.Packetizer
	sequencer  rtp.Sequencer
	rtpTrack   *TrackLocalStaticRTP
	clockRate  float64
	remainder  float64
}

func NewTrackLocalStaticSample(
	c RTPCodecCapability,
	id, streamID string,
	options ...func(*TrackLocalStaticRTP),
) (*TrackLocalStaticSample, error) {
	rtpTrack, err := NewTrackLocalStaticRTP(c, id, streamID, options...)
	if err != nil {
		return nil, err
	}

	return &TrackLocalStaticSample{
		rtpTrack: rtpTrack,
	}, nil
}

func (s *TrackLocalStaticSample) ID() string { return s.rtpTrack.ID() }

func (s *TrackLocalStaticSample) StreamID() string { return s.rtpTrack.StreamID() }

func (s *TrackLocalStaticSample) RID() string { return s.rtpTrack.RID() }

func (s *TrackLocalStaticSample) Kind() RTPCodecType { return s.rtpTrack.Kind() }

func (s *TrackLocalStaticSample) Codec() RTPCodecCapability {
	return s.rtpTrack.Codec()
}

func (s *TrackLocalStaticSample) Bind(t TrackLocalContext) (RTPCodecParameters, error) {
	codec, err := s.rtpTrack.Bind(t)
	if err != nil {
		return codec, err
	}

	s.rtpTrack.mu.Lock()
	defer s.rtpTrack.mu.Unlock()

	if s.packetizer != nil {
		return codec, nil
	}

	payloadHandler := s.rtpTrack.payloader
	if payloadHandler == nil {
		payloadHandler = payloaderForCodec
	}

	payloader, err := payloadHandler(codec.RTPCodecCapability)
	if err != nil {
		return codec, err
	}

	options := []rtp.PacketizerOption{}

	if s.rtpTrack.initalTimestamp != nil {
		options = append(options, rtp.WithTimestamp(*s.rtpTrack.initalTimestamp))
	}

	if s.rtpTrack.initialSeqNumber != nil {
		s.sequencer = rtp.NewFixedSequencer(*s.rtpTrack.initialSeqNumber)
	}

	if s.sequencer == nil {
		s.sequencer = rtp.NewRandomSequencer()
	}

	s.packetizer = rtp.NewPacketizerWithOptions(
		outboundMTU,
		payloader,
		s.sequencer,
		codec.ClockRate,
		options...,
	)

	s.clockRate = float64(codec.RTPCodecCapability.ClockRate)

	return codec, nil
}

func (s *TrackLocalStaticSample) Unbind(t TrackLocalContext) error {
	return s.rtpTrack.Unbind(t)
}

func (s *TrackLocalStaticSample) WriteSample(sample Sample) error {
	s.rtpTrack.mu.RLock()
	packetizer := s.packetizer
	clockRate := s.clockRate
	sequencer := s.sequencer
	s.rtpTrack.mu.RUnlock()
	if packetizer == nil {
		return nil
	}

	s.mu.Lock()
	remainder := s.remainder

	for i := uint16(0); i < sample.PrevDroppedPackets; i++ {
		sequencer.NextSequenceNumber()
	}

	tickF := sample.Duration.Seconds() * clockRate

	if sample.PrevDroppedPackets > 0 {
		dropTotal := tickF*float64(sample.PrevDroppedPackets) + remainder
		dropTicks := uint32(dropTotal)
		remainder = dropTotal - float64(dropTicks)
		packetizer.SkipSamples(dropTicks)
	}

	curTotal := tickF + remainder
	curTicks := uint32(curTotal)
	remainder = curTotal - float64(curTicks)

	s.remainder = remainder
	packets := packetizer.Packetize(sample.Data, curTicks)
	s.mu.Unlock()

	writeErrs := []error{}
	for _, p := range packets {
		if err := s.rtpTrack.WriteRTP(p); err != nil {
			writeErrs = append(writeErrs, err)
		}
	}

	return wutil.JoinErrors(writeErrs)
}

func (s *TrackLocalStaticSample) GeneratePadding(samples uint32) error {
	s.rtpTrack.mu.RLock()
	p := s.packetizer
	s.rtpTrack.mu.RUnlock()

	if p == nil {
		return nil
	}

	packets := p.GeneratePadding(samples)

	writeErrs := []error{}
	for _, p := range packets {
		if err := s.rtpTrack.WriteRTP(p); err != nil {
			writeErrs = append(writeErrs, err)
		}
	}

	return wutil.JoinErrors(writeErrs)
}

type peekedPacket struct {
	payload    []byte
	attributes interceptor.Attributes
}

type TrackRemote struct {
	mu                         sync.RWMutex
	id                         string
	streamID                   string
	payloadType                PayloadType
	kind                       RTPCodecType
	ssrc                       SSRC
	rtxSsrc                    SSRC
	codec                      RTPCodecParameters
	params                     RTPParameters
	rid                        string
	receiver                   *RTPReceiver
	peekedPackets              []*peekedPacket
	audioPlayoutStatsProviders []AudioPlayoutStatsProvider
}

func newTrackRemote(kind RTPCodecType, ssrc, rtxSsrc SSRC, rid string, receiver *RTPReceiver) *TrackRemote {
	return &TrackRemote{
		kind:     kind,
		ssrc:     ssrc,
		rtxSsrc:  rtxSsrc,
		rid:      rid,
		receiver: receiver,
	}
}

func (t *TrackRemote) ID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.id
}

func (t *TrackRemote) RID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.rid
}

func (t *TrackRemote) PayloadType() PayloadType {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.payloadType
}

func (t *TrackRemote) Kind() RTPCodecType {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.kind
}

func (t *TrackRemote) StreamID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.streamID
}

func (t *TrackRemote) SSRC() SSRC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.ssrc
}

func (t *TrackRemote) Msid() string {
	return t.StreamID() + " " + t.ID()
}

func (t *TrackRemote) Codec() RTPCodecParameters {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.codec
}

func (t *TrackRemote) Read(b []byte) (n int, attributes interceptor.Attributes, err error) {
	t.mu.RLock()
	receiver := t.receiver
	var peekedPkt *peekedPacket
	if len(t.peekedPackets) != 0 {
		peekedPkt = t.peekedPackets[0]
		t.peekedPackets = t.peekedPackets[1:]
	}
	t.mu.RUnlock()

	if receiver.haveClosed() {
		return 0, nil, io.EOF
	}

	if peekedPkt != nil {
		n = copy(b, peekedPkt.payload)
		err = t.checkAndUpdateTrack(b)

		return n, peekedPkt.attributes, err
	}

	if rtxPacketReceived := receiver.readRTX(t); rtxPacketReceived != nil {
		n = copy(b, rtxPacketReceived.pkt)
		attributes = rtxPacketReceived.attributes
		rtxPacketReceived.release()

		return n, attributes, nil
	}

	n, attributes, err = receiver.readRTP(b, t)
	if err != nil {
		return n, attributes, err
	}
	err = t.checkAndUpdateTrack(b)

	return n, attributes, err
}

func (t *TrackRemote) checkAndUpdateTrack(b []byte) error {
	if len(b) < 2 {
		return errRTPTooShort
	}

	payloadType := PayloadType(b[1] & rtpPayloadTypeBitmask)
	if payloadType != t.PayloadType() || len(t.params.Codecs) == 0 {
		t.mu.Lock()
		defer t.mu.Unlock()

		params, err := t.receiver.api.mediaEngine.getRTPParametersByPayloadType(payloadType)
		if err != nil {
			return err
		}

		t.kind = t.receiver.kind
		t.payloadType = payloadType
		t.codec = params.Codecs[0]
		t.params = params
	}

	return nil
}

func (t *TrackRemote) ReadRTP() (*rtp.Packet, interceptor.Attributes, error) {
	b := make([]byte, t.receiver.api.settingEngine.getReceiveMTU())
	i, attributes, err := t.Read(b)
	if err != nil {
		return nil, nil, err
	}

	r := &rtp.Packet{}
	if err := r.Unmarshal(b[:i]); err != nil {
		return nil, nil, err
	}

	return r, attributes, nil
}

func (t *TrackRemote) peek(b []byte) (n int, a interceptor.Attributes, err error) {
	n, a, err = t.Read(b)
	if err != nil {
		return
	}

	t.mu.Lock()

	data := make([]byte, n)
	n = copy(data, b[:n])
	t.peekedPackets = append(t.peekedPackets, &peekedPacket{payload: data, attributes: a})
	t.mu.Unlock()

	return
}

func (t *TrackRemote) SetReadDeadline(deadline time.Time) error {
	return t.receiver.setRTPReadDeadline(deadline, t)
}

func (t *TrackRemote) RtxSSRC() SSRC {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.rtxSsrc
}

func (t *TrackRemote) HasRTX() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.rtxSsrc != 0
}

func (t *TrackRemote) pullAudioPlayoutStats(now time.Time) []AudioPlayoutStats {
	t.mu.RLock()
	providers := t.audioPlayoutStatsProviders
	t.mu.RUnlock()

	if len(providers) == 0 {
		return nil
	}

	var allStats []AudioPlayoutStats
	for _, provider := range providers {
		stats, ok := provider.Snapshot(now)
		if !ok {
			continue
		}

		if stats.ID == "" {
			stats.ID = fmt.Sprintf("media-playout-%d", uint32(t.SSRC()))
		}

		if stats.Type == "" {
			stats.Type = StatsTypeMediaPlayout
		}

		if stats.Kind == "" {
			stats.Kind = string(MediaKindAudio)
		}

		if stats.Timestamp == 0 {
			stats.Timestamp = statsTimestampFrom(now)
		}

		allStats = append(allStats, stats)
	}

	return allStats
}

func (t *TrackRemote) setRtxSSRC(ssrc SSRC) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rtxSsrc = ssrc
}

type BundlePolicy int

const (
	BundlePolicyUnknown BundlePolicy = iota

	BundlePolicyBalanced

	BundlePolicyMaxCompat

	BundlePolicyMaxBundle
)

const (
	bundlePolicyBalancedStr  = "balanced"
	bundlePolicyMaxCompatStr = "max-compat"
	bundlePolicyMaxBundleStr = "max-bundle"
)

func newBundlePolicy(raw string) BundlePolicy {
	switch raw {
	case bundlePolicyBalancedStr:
		return BundlePolicyBalanced
	case bundlePolicyMaxCompatStr:
		return BundlePolicyMaxCompat
	case bundlePolicyMaxBundleStr:
		return BundlePolicyMaxBundle
	default:
		return BundlePolicyUnknown
	}
}

func (t BundlePolicy) String() string {
	switch t {
	case BundlePolicyBalanced:
		return bundlePolicyBalancedStr
	case BundlePolicyMaxCompat:
		return bundlePolicyMaxCompatStr
	case BundlePolicyMaxBundle:
		return bundlePolicyMaxBundleStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t *BundlePolicy) UnmarshalJSON(b []byte) error {
	var val string
	if err := json.Unmarshal(b, &val); err != nil {
		return err
	}

	*t = newBundlePolicy(val)

	return nil
}

func (t BundlePolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

type Certificate struct {
	privateKey crypto.PrivateKey
	x509Cert   *x509.Certificate
	statsID    string
}

func NewCertificate(key crypto.PrivateKey, tpl x509.Certificate) (*Certificate, error) {
	var err error
	var certDER []byte
	switch sk := key.(type) {
	case *rsa.PrivateKey:
		pk := sk.Public()
		tpl.SignatureAlgorithm = x509.SHA256WithRSA
		certDER, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, pk, sk)
		if err != nil {
			return nil, &UnknownError{Err: err}
		}
	case *ecdsa.PrivateKey:
		pk := sk.Public()
		tpl.SignatureAlgorithm = x509.ECDSAWithSHA256
		certDER, err = x509.CreateCertificate(rand.Reader, &tpl, &tpl, pk, sk)
		if err != nil {
			return nil, &UnknownError{Err: err}
		}
	default:
		return nil, &NotSupportedError{Err: ErrPrivateKeyType}
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, &UnknownError{Err: err}
	}

	return &Certificate{
		privateKey: key,
		x509Cert:   cert,
		statsID:    fmt.Sprintf("certificate-%d", time.Now().UnixNano()),
	}, nil
}

func (c Certificate) Equals(cert Certificate) bool {
	switch cSK := c.privateKey.(type) {
	case *rsa.PrivateKey:
		if oSK, ok := cert.privateKey.(*rsa.PrivateKey); ok {
			if cSK.N.Cmp(oSK.N) != 0 {
				return false
			}

			return c.x509Cert.Equal(cert.x509Cert)
		}

		return false
	case *ecdsa.PrivateKey:
		if oSK, ok := cert.privateKey.(*ecdsa.PrivateKey); ok {
			if cSK.X.Cmp(oSK.X) != 0 || cSK.Y.Cmp(oSK.Y) != 0 {
				return false
			}

			return c.x509Cert.Equal(cert.x509Cert)
		}

		return false
	default:
		return false
	}
}

func (c Certificate) Expires() time.Time {
	if c.x509Cert == nil {
		return time.Time{}
	}

	return c.x509Cert.NotAfter
}

func (c Certificate) GetFingerprints() ([]DTLSFingerprint, error) {
	fingerprintAlgorithms := []crypto.Hash{crypto.SHA256}
	res := make([]DTLSFingerprint, len(fingerprintAlgorithms))

	i := 0
	for _, algo := range fingerprintAlgorithms {
		name, err := dtls.StringFromHash(algo)
		if err != nil {

			return nil, fmt.Errorf("%w: %v", ErrFailedToGenerateCertificateFingerprint, err)
		}
		value, err := dtls.Fingerprint(c.x509Cert, algo)
		if err != nil {

			return nil, fmt.Errorf("%w: %v", ErrFailedToGenerateCertificateFingerprint, err)
		}
		res[i] = DTLSFingerprint{
			Algorithm: name,
			Value:     value,
		}
	}

	return res[:i+1], nil
}

func GenerateCertificate(secretKey crypto.PrivateKey) (*Certificate, error) {

	maxBigInt := new(big.Int)

	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))

	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		return nil, &UnknownError{Err: err}
	}

	return NewCertificate(secretKey, x509.Certificate{
		Issuer:       pkix.Name{CommonName: generatedCertificateOrigin},
		NotBefore:    time.Now().AddDate(0, 0, -1),
		NotAfter:     time.Now().AddDate(0, 1, -1),
		SerialNumber: serialNumber,
		Version:      2,
		Subject:      pkix.Name{CommonName: generatedCertificateOrigin},
	})
}

func (c Certificate) collectStats(report *statsReportCollector) error {
	report.Collecting()

	fingerPrintAlgo, err := c.GetFingerprints()
	if err != nil {
		return err
	}

	base64Certificate := base64.RawURLEncoding.EncodeToString(c.x509Cert.Raw)

	stats := CertificateStats{
		Timestamp:            statsTimestampFrom(time.Now()),
		Type:                 StatsTypeCertificate,
		ID:                   c.statsID,
		Fingerprint:          fingerPrintAlgo[0].Value,
		FingerprintAlgorithm: fingerPrintAlgo[0].Algorithm,
		Base64Certificate:    base64Certificate,
		IssuerCertificateID:  c.x509Cert.Issuer.String(),
	}

	report.Collect(stats.ID, stats)

	return nil
}

func (c Certificate) PEM() (string, error) {

	var builder strings.Builder
	err := pem.Encode(&builder, &pem.Block{Type: "CERTIFICATE", Bytes: c.x509Cert.Raw})
	if err != nil {
		return "", fmt.Errorf("failed to pem encode the X certificate: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(c.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	err = pem.Encode(&builder, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return "", fmt.Errorf("failed to encode private key: %w", err)
	}

	return builder.String(), nil
}

func (c Configuration) getICEServers() []ICEServer {
	iceServers := append([]ICEServer{}, c.ICEServers...)

	for iceServersIndex := range iceServers {
		iceServers[iceServersIndex].URLs = append([]string{}, iceServers[iceServersIndex].URLs...)

		for urlsIndex, rawURL := range iceServers[iceServersIndex].URLs {
			if strings.HasPrefix(rawURL, "stun") {

				parts := strings.Split(rawURL, "?")
				rawURL = parts[0]
			}
			iceServers[iceServersIndex].URLs[urlsIndex] = rawURL
		}
	}

	return iceServers
}

const (
	receiveMTU = 1500

	simulcastProbeCount = 10

	simulcastMaxProbeRoutines = 25

	defaultMaxSCTPMessageSize = 1073741823

	mediaSectionApplication = "application"

	sdpAttributeRid = "rid"

	sdpAttributeSimulcast = "simulcast"

	outboundMTU = 1200

	rtpPayloadTypeBitmask = 0x7F

	incomingUnhandledRTPSsrc = "Incoming unhandled RTP ssrc(%d), OnTrack will not be fired. %v"

	useReadSimulcast = "Use ReadSimulcast(rid) instead of Read() when multiple tracks are present"

	generatedCertificateOrigin = "WebRTC"

	AttributeRtxPayloadType = "rtx_payload_type"

	AttributeRtxSsrc = "rtx_ssrc"

	AttributeRtxSequenceNumber = "rtx_sequence_number"
)

func defaultSrtpProtectionProfiles() []dtls.SRTPProtectionProfile {
	return []dtls.SRTPProtectionProfile{
		dtls.SRTP_AEAD_AES_256_GCM,
		dtls.SRTP_AEAD_AES_128_GCM,
		dtls.SRTP_AES128_CM_HMAC_SHA1_80,
	}
}

type DataChannelInit struct {
	Ordered           *bool
	MaxPacketLifeTime *uint16
	MaxRetransmits    *uint16
	Protocol          *string
	Negotiated        *bool
	ID                *uint16
}

type DataChannelMessage struct {
	IsString bool
	Data     []byte
}

type DataChannelParameters struct {
	Label             string  `json:"label"`
	Protocol          string  `json:"protocol"`
	ID                *uint16 `json:"id"`
	Ordered           bool    `json:"ordered"`
	MaxPacketLifeTime *uint16 `json:"maxPacketLifeTime"`
	MaxRetransmits    *uint16 `json:"maxRetransmits"`
	Negotiated        bool    `json:"negotiated"`
}

type DataChannelState int

const (
	DataChannelStateUnknown DataChannelState = iota

	DataChannelStateConnecting

	DataChannelStateOpen

	DataChannelStateClosing

	DataChannelStateClosed
)

const (
	dataChannelStateConnectingStr = "connecting"
	dataChannelStateOpenStr       = "open"
	dataChannelStateClosingStr    = "closing"
	dataChannelStateClosedStr     = "closed"
)

func newDataChannelState(raw string) DataChannelState {
	switch raw {
	case dataChannelStateConnectingStr:
		return DataChannelStateConnecting
	case dataChannelStateOpenStr:
		return DataChannelStateOpen
	case dataChannelStateClosingStr:
		return DataChannelStateClosing
	case dataChannelStateClosedStr:
		return DataChannelStateClosed
	default:
		return DataChannelStateUnknown
	}
}

func (t DataChannelState) String() string {
	switch t {
	case DataChannelStateConnecting:
		return dataChannelStateConnectingStr
	case DataChannelStateOpen:
		return dataChannelStateOpenStr
	case DataChannelStateClosing:
		return dataChannelStateClosingStr
	case DataChannelStateClosed:
		return dataChannelStateClosedStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t DataChannelState) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t *DataChannelState) UnmarshalText(b []byte) error {
	*t = newDataChannelState(string(b))

	return nil
}

type DTLSFingerprint struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type DTLSParameters struct {
	Role         DTLSRole          `json:"role"`
	Fingerprints []DTLSFingerprint `json:"fingerprints"`
}

type DTLSRole byte

const (
	DTLSRoleUnknown DTLSRole = iota

	DTLSRoleAuto

	DTLSRoleClient

	DTLSRoleServer
)

const (
	defaultDtlsRoleAnswer = DTLSRoleClient

	defaultDtlsRoleOffer = DTLSRoleAuto
)

func (r DTLSRole) String() string {
	switch r {
	case DTLSRoleAuto:
		return "auto"
	case DTLSRoleClient:
		return "client"
	case DTLSRoleServer:
		return "server"
	default:
		return ErrUnknownType.Error()
	}
}

func dtlsRoleFromSDP(sessionDescription *sdp.SessionDescription) DTLSRole {
	if sessionDescription == nil {
		return DTLSRoleAuto
	}

	for _, mediaSection := range sessionDescription.MediaDescriptions {
		for _, attribute := range mediaSection.Attributes {
			if attribute.Key == "setup" {
				switch attribute.Value {
				case sdp.ConnectionRoleActive.String():
					return DTLSRoleClient
				case sdp.ConnectionRolePassive.String():
					return DTLSRoleServer
				default:
					return DTLSRoleAuto
				}
			}
		}
	}

	return DTLSRoleAuto
}

func connectionRoleFromDtlsRole(d DTLSRole) sdp.ConnectionRole {
	switch d {
	case DTLSRoleClient:
		return sdp.ConnectionRoleActive
	case DTLSRoleServer:
		return sdp.ConnectionRolePassive
	case DTLSRoleAuto:
		return sdp.ConnectionRoleActpass
	default:
		return sdp.ConnectionRole(0)
	}
}

type DTLSTransportState int

const (
	DTLSTransportStateUnknown DTLSTransportState = iota

	DTLSTransportStateNew

	DTLSTransportStateConnecting

	DTLSTransportStateConnected

	DTLSTransportStateClosed

	DTLSTransportStateFailed
)

const (
	dtlsTransportStateNewStr        = "new"
	dtlsTransportStateConnectingStr = "connecting"
	dtlsTransportStateConnectedStr  = "connected"
	dtlsTransportStateClosedStr     = "closed"
	dtlsTransportStateFailedStr     = "failed"
)

func newDTLSTransportState(raw string) DTLSTransportState {
	switch raw {
	case dtlsTransportStateNewStr:
		return DTLSTransportStateNew
	case dtlsTransportStateConnectingStr:
		return DTLSTransportStateConnecting
	case dtlsTransportStateConnectedStr:
		return DTLSTransportStateConnected
	case dtlsTransportStateClosedStr:
		return DTLSTransportStateClosed
	case dtlsTransportStateFailedStr:
		return DTLSTransportStateFailed
	default:
		return DTLSTransportStateUnknown
	}
}

func (t DTLSTransportState) String() string {
	switch t {
	case DTLSTransportStateNew:
		return dtlsTransportStateNewStr
	case DTLSTransportStateConnecting:
		return dtlsTransportStateConnectingStr
	case DTLSTransportStateConnected:
		return dtlsTransportStateConnectedStr
	case DTLSTransportStateClosed:
		return dtlsTransportStateClosedStr
	case DTLSTransportStateFailed:
		return dtlsTransportStateFailedStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t DTLSTransportState) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t *DTLSTransportState) UnmarshalText(b []byte) error {
	*t = newDTLSTransportState(string(b))

	return nil
}

var (
	ErrUnknownType = errors.New("unknown")

	ErrConnectionClosed = errors.New("connection closed")

	ErrDataChannelNotOpen = errors.New("data channel not open")

	ErrCertificateExpired = errors.New("x509Cert expired")

	ErrNoTurnCredentials = errors.New("turn server credentials required")

	ErrTurnCredentials = errors.New("invalid turn server credentials")

	ErrExistingTrack = errors.New("track already exists")

	ErrPrivateKeyType = errors.New("private key type not supported")

	ErrModifyingPeerIdentity = errors.New("peerIdentity cannot be modified")

	ErrModifyingCertificates = errors.New("certificates cannot be modified")

	ErrModifyingBundlePolicy = errors.New("bundle policy cannot be modified")

	ErrModifyingRTCPMuxPolicy = errors.New("rtcp mux policy cannot be modified")

	ErrModifyingICECandidatePoolSize = errors.New("ice candidate pool size cannot be modified")

	ErrStringSizeLimit = errors.New("data channel label exceeds size limit")

	ErrMaxDataChannelID = errors.New("maximum number ID for datachannel specified")

	ErrNegotiatedWithoutID = errors.New("negotiated set without channel id")

	ErrRetransmitsOrPacketLifeTime = errors.New("both MaxPacketLifeTime and MaxRetransmits was set")

	ErrCodecNotFound = errors.New("codec not found")

	ErrNoRemoteDescription = errors.New("remote description is not set")

	ErrIncorrectSDPSemantics = errors.New("remote SessionDescription semantics does not match configuration")

	ErrIncorrectSignalingState = errors.New("operation can not be run in current signaling state")

	ErrProtocolTooLarge = errors.New("protocol is larger then 65535 bytes")

	ErrSenderNotCreatedByConnection = errors.New("RtpSender not created by this PeerConnection")

	ErrSessionDescriptionNoFingerprint = errors.New("SetRemoteDescription called with no fingerprint")

	ErrSessionDescriptionInvalidFingerprint = errors.New("SetRemoteDescription called with an invalid fingerprint")

	ErrSessionDescriptionConflictingFingerprints = errors.New(
		"SetRemoteDescription called with multiple conflicting fingerprint",
	)

	ErrSessionDescriptionMissingIceUfrag = errors.New("SetRemoteDescription called with no ice-ufrag")

	ErrSessionDescriptionMissingIcePwd = errors.New("SetRemoteDescription called with no ice-pwd")

	ErrSessionDescriptionConflictingIceUfrag = errors.New(
		"SetRemoteDescription called with multiple conflicting ice-ufrag values",
	)

	ErrSessionDescriptionConflictingIcePwd = errors.New(
		"SetRemoteDescription called with multiple conflicting ice-pwd values",
	)

	ErrNoSRTPProtectionProfile = errors.New("DTLS Handshake completed and no SRTP Protection Profile was chosen")

	ErrFailedToGenerateCertificateFingerprint = errors.New("failed to generate certificate fingerprint")

	ErrNoCodecsAvailable = errors.New("operation failed no codecs are available")

	ErrUnsupportedCodec = errors.New("unable to start track, codec is not supported by remote")

	ErrSenderWithNoCodecs = errors.New("unable to populate media section, RTPSender created with no codecs")

	ErrCodecAlreadyRegistered = errors.New("codec already registered for same payload type")

	ErrRTPSenderNewTrackHasIncorrectKind = errors.New("new track must be of the same kind as previous")

	ErrRTPSenderNewTrackHasIncorrectEnvelope = errors.New("new track must have the same envelope as previous")

	ErrUnbindFailed = errors.New("failed to unbind TrackLocal from PeerConnection")

	ErrNoPayloaderForCodec = errors.New("the requested codec does not have a payloader")

	ErrRegisterHeaderExtensionInvalidDirection = errors.New(
		"a header extension must be registered as 'recvonly', 'sendonly' or both",
	)

	ErrSimulcastProbeOverflow = errors.New("simulcast probe limit has been reached, new SSRC has been discarded")

	ErrSDPUnmarshalling = errors.New("failed to unmarshal SDP")

	errDtlsTransportNotStarted          = errors.New("the DTLS transport has not started yet")
	errDtlsKeyExtractionFailed          = errors.New("failed extracting keys from DTLS for SRTP")
	errFailedToStartSRTP                = errors.New("failed to start SRTP")
	errFailedToStartSRTCP               = errors.New("failed to start SRTCP")
	errInvalidDTLSStart                 = errors.New("attempted to start DTLSTransport that is not in new state")
	errNoRemoteCertificate              = errors.New("peer didn't provide certificate via DTLS")
	errIdentityProviderNotImplemented   = errors.New("identity provider is not implemented")
	errNoMatchingCertificateFingerprint = errors.New("remote certificate does not match any fingerprint")

	errICEConnectionNotStarted        = errors.New("ICE connection not started")
	errICECandidateTypeUnknown        = errors.New("unknown candidate type")
	errICEInvalidConvertCandidateType = errors.New(
		"cannot convert ice.CandidateType into webrtc.ICECandidateType, invalid type",
	)
	errICEAgentNotExist            = errors.New("ICEAgent does not exist")
	errICECandiatesCoversionFailed = errors.New("unable to convert ICE candidates to ICECandidates")
	errICERoleUnknown              = errors.New("unknown ICE Role")
	errICEProtocolUnknown          = errors.New("unknown protocol")
	errICEGathererNotStarted       = errors.New("gatherer not started")
	errAddressRewriteWithNAT1To1   = errors.New("address rewrite rules cannot be combined with NAT1To1IPs")

	errNetworkTypeUnknown = errors.New("unknown network type")

	errSDPDoesNotMatchOffer        = errors.New("new sdp does not match previous offer")
	errSDPDoesNotMatchAnswer       = errors.New("new sdp does not match previous answer")
	errPeerConnSDPTypeInvalidValue = errors.New(
		"provided value is not a valid enum value of type SDPType",
	)
	errPeerConnStateChangeInvalid                     = errors.New("invalid state change op")
	errPeerConnStateChangeUnhandled                   = errors.New("unhandled state change op")
	errPeerConnSDPTypeInvalidValueSetLocalDescription = errors.New("invalid SDP type supplied to SetLocalDescription()")
	errPeerConnRemoteDescriptionWithoutMidValue       = errors.New(
		"remoteDescription contained media section without mid value",
	)
	errPeerConnRemoteDescriptionNil                  = errors.New("remoteDescription has not been set yet")
	errMediaSectionHasExplictSSRCAttribute           = errors.New("media section has an explicit SSRC")
	errPeerConnRemoteSSRCAddTransceiver              = errors.New("could not add transceiver for remote SSRC")
	errPeerConnSimulcastMidRTPExtensionRequired      = errors.New("mid RTP Extensions required for Simulcast")
	errPeerConnSimulcastStreamIDRTPExtensionRequired = errors.New("stream id RTP Extensions required for Simulcast")
	errPeerConnSimulcastIncomingSSRCFailed           = errors.New("incoming SSRC failed Simulcast probing")
	errPeerConnAddTransceiverFromKindOnlyAcceptsOne  = errors.New(
		"AddTransceiverFromKind only accepts one RTPTransceiverInit",
	)
	errPeerConnAddTransceiverFromTrackOnlyAcceptsOne = errors.New(
		"AddTransceiverFromTrack only accepts one RTPTransceiverInit",
	)
	errPeerConnAddTransceiverFromKindSupport = errors.New(
		"AddTransceiverFromKind currently only supports recvonly",
	)
	errPeerConnAddTransceiverFromTrackSupport = errors.New(
		"AddTransceiverFromTrack currently only supports sendonly and sendrecv",
	)
	errPeerConnSetIdentityProviderNotImplemented = errors.New("TODO SetIdentityProvider")
	errPeerConnWriteRTCPOpenWriteStream          = errors.New("WriteRTCP failed to open WriteStream")
	errPeerConnTranscieverMidNil                 = errors.New("cannot find transceiver with mid")
	errPeerConnEarlyMediaWithoutAnswer           = errors.New(
		"cannot process early media without SDP answer," +
			"use SettingEngine.SetHandleUndeclaredSSRCWithoutAnswer(true) to process without answer",
	)

	errRTPReceiverDTLSTransportNil            = errors.New("DTLSTransport must not be nil")
	errRTPReceiverReceiveAlreadyCalled        = errors.New("Receive has already been called")
	errRTPReceiverWithSSRCTrackStreamNotFound = errors.New("unable to find stream for Track with SSRC")
	errRTPReceiverForRIDTrackStreamNotFound   = errors.New("no trackStreams found for RID")

	errRTPSenderTrackNil             = errors.New("Track must not be nil")
	errRTPSenderDTLSTransportNil     = errors.New("DTLSTransport must not be nil")
	errRTPSenderSendAlreadyCalled    = errors.New("Send has already been called")
	errRTPSenderSendNotCalled        = errors.New("Send has not been called")
	errRTPSenderStopped              = errors.New("Sender has already been stopped")
	errRTPSenderTrackRemoved         = errors.New("Sender Track has been removed or replaced to nil")
	errRTPSenderRidNil               = errors.New("Sender cannot add encoding as rid is empty")
	errRTPSenderNoBaseEncoding       = errors.New("Sender cannot add encoding as there is no base track")
	errRTPSenderBaseEncodingMismatch = errors.New("Sender cannot add encoding as provided track does not match base track")
	errRTPSenderRIDCollision         = errors.New("Sender cannot encoding due to RID collision")
	errRTPSenderNoTrackForRID        = errors.New("Sender does not have track for RID")

	errRTPTransceiverCannotChangeMid        = errors.New("cannot change transceiver mid")
	errRTPTransceiverSetSendingInvalidState = errors.New("invalid state change in RTPTransceiver.setSending")
	errRTPTransceiverCodecUnsupported       = errors.New("unsupported codec type by this transceiver")

	errSDPZeroTransceivers                 = errors.New("addTransceiverSDP() called with 0 transceivers")
	errSDPMediaSectionMediaDataChanInvalid = errors.New("invalid Media Section. Media + DataChannel both enabled")
	errSDPMediaSectionMultipleTrackInvalid = errors.New(
		"invalid Media Section. Can not have multiple tracks in one MediaSection in UnifiedPlan",
	)

	errSettingEngineSetAnsweringDTLSRole = errors.New("SetAnsweringDTLSRole must DTLSRoleClient or DTLSRoleServer")

	errSignalingStateCannotRollback            = errors.New("can't rollback from stable state")
	errSignalingStateProposedTransitionInvalid = errors.New("invalid proposed signaling state transition")

	errStatsICECandidateStateInvalid = errors.New(
		"cannot convert to StatsICECandidatePairStateSucceeded invalid ice candidate state",
	)

	errICECandidatePoolSizeTooLarge = errors.New("ice candidate pool size greater than 1 is not supported")

	errInvalidICECredentialTypeString = errors.New("invalid ICECredentialType")
	errInvalidICEServer               = errors.New("invalid ICEServer")

	errICETransportNotInNew = errors.New("ICETransport can only be called in ICETransportStateNew")
	errICETransportClosed   = errors.New("ICETransport closed")

	errRTPTooShort = errors.New("not long enough to be a RTP Packet")

	errExcessiveRetries = errors.New("excessive retries in CreateOffer")
)

func GatheringCompletePromise(pc *PeerConnection) (gatherComplete <-chan struct{}) {
	gatheringComplete, done := context.WithCancel(context.Background())

	pc.setGatherCompleteHandler(func() { done() })
	if pc.ICEGatheringState() == ICEGatheringStateComplete {
		done()
	}

	return gatheringComplete.Done()
}

type ICECandidate struct {
	statsID        string
	Foundation     string           `json:"foundation"`
	Priority       uint32           `json:"priority"`
	Address        string           `json:"address"`
	Protocol       ICEProtocol      `json:"protocol"`
	Port           uint16           `json:"port"`
	Typ            ICECandidateType `json:"type"`
	Component      uint16           `json:"component"`
	RelatedAddress string           `json:"relatedAddress"`
	RelatedPort    uint16           `json:"relatedPort"`
	TCPType        string           `json:"tcpType"`
	SDPMid         string           `json:"sdpMid"`
	SDPMLineIndex  uint16           `json:"sdpMLineIndex"`
	extensions     string
}

func newICECandidatesFromICE(
	iceCandidates []ice.Candidate,
	sdpMid string,
	sdpMLineIndex uint16,
) ([]ICECandidate, error) {
	candidates := []ICECandidate{}

	for _, i := range iceCandidates {
		c, err := newICECandidateFromICE(i, sdpMid, sdpMLineIndex)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}

	return candidates, nil
}

func newICECandidateFromICE(candidate ice.Candidate, sdpMid string, sdpMLineIndex uint16) (ICECandidate, error) {
	typ, err := convertTypeFromICE(candidate.Type())
	if err != nil {
		return ICECandidate{}, err
	}
	protocol, err := NewICEProtocol(candidate.NetworkType().NetworkShort())
	if err != nil {
		return ICECandidate{}, err
	}

	newCandidate := ICECandidate{
		statsID:       candidate.ID(),
		Foundation:    candidate.Foundation(),
		Priority:      candidate.Priority(),
		Address:       candidate.Address(),
		Protocol:      protocol,
		Port:          uint16(candidate.Port()),
		Component:     candidate.Component(),
		Typ:           typ,
		TCPType:       candidate.TCPType().String(),
		SDPMid:        sdpMid,
		SDPMLineIndex: sdpMLineIndex,
	}

	newCandidate.setExtensions(candidate.Extensions())

	if candidate.RelatedAddress() != nil {
		newCandidate.RelatedAddress = candidate.RelatedAddress().Address
		newCandidate.RelatedPort = uint16(candidate.RelatedAddress().Port)
	}

	return newCandidate, nil
}

func (c ICECandidate) ToICE() (cand ice.Candidate, err error) {
	candidateID := c.statsID
	switch c.Typ {
	case ICECandidateTypeHost:
		config := ice.CandidateHostConfig{
			CandidateID: candidateID,
			Network:     c.Protocol.String(),
			Address:     c.Address,
			Port:        int(c.Port),
			Component:   c.Component,
			TCPType:     ice.NewTCPType(c.TCPType),
			Foundation:  c.Foundation,
			Priority:    c.Priority,
		}

		cand, err = ice.NewCandidateHost(&config)
	case ICECandidateTypeSrflx:
		config := ice.CandidateServerReflexiveConfig{
			CandidateID: candidateID,
			Network:     c.Protocol.String(),
			Address:     c.Address,
			Port:        int(c.Port),
			Component:   c.Component,
			Foundation:  c.Foundation,
			Priority:    c.Priority,
			RelAddr:     c.RelatedAddress,
			RelPort:     int(c.RelatedPort),
		}

		cand, err = ice.NewCandidateServerReflexive(&config)
	case ICECandidateTypePrflx:
		config := ice.CandidatePeerReflexiveConfig{
			CandidateID: candidateID,
			Network:     c.Protocol.String(),
			Address:     c.Address,
			Port:        int(c.Port),
			Component:   c.Component,
			Foundation:  c.Foundation,
			Priority:    c.Priority,
			RelAddr:     c.RelatedAddress,
			RelPort:     int(c.RelatedPort),
		}

		cand, err = ice.NewCandidatePeerReflexive(&config)
	case ICECandidateTypeRelay:
		config := ice.CandidateRelayConfig{
			CandidateID: candidateID,
			Network:     c.Protocol.String(),
			Address:     c.Address,
			Port:        int(c.Port),
			Component:   c.Component,
			Foundation:  c.Foundation,
			Priority:    c.Priority,
			RelAddr:     c.RelatedAddress,
			RelPort:     int(c.RelatedPort),
		}

		cand, err = ice.NewCandidateRelay(&config)
	default:
		return nil, fmt.Errorf("%w: %s", errICECandidateTypeUnknown, c.Typ)
	}

	if cand != nil && err == nil {
		err = c.exportExtensions(cand)
	}

	return cand, err
}

func (c *ICECandidate) setExtensions(ext []ice.CandidateExtension) {
	var extensions strings.Builder

	for i := range ext {
		if i > 0 {
			extensions.WriteString(" ")
		}

		extensions.WriteString(ext[i].Key + " " + ext[i].Value)
	}

	c.extensions = extensions.String()
}

func (c *ICECandidate) exportExtensions(cand ice.Candidate) error {
	extensions := c.extensions
	var ext ice.CandidateExtension
	var field string

	for i, start := 0, 0; i < len(extensions); i++ {
		switch {
		case extensions[i] == ' ':
			field = extensions[start:i]
			start = i + 1
		case i == len(extensions)-1:
			field = extensions[start:]
		default:
			continue
		}

		hasKey := ext.Key != ""
		if !hasKey {
			ext.Key = field
		} else {
			ext.Value = field
		}

		if hasKey || i == len(extensions)-1 {
			if err := cand.AddExtension(ext); err != nil {
				return err
			}

			ext = ice.CandidateExtension{}
		}
	}

	return nil
}

func convertTypeFromICE(t ice.CandidateType) (ICECandidateType, error) {
	switch t {
	case ice.CandidateTypeHost:
		return ICECandidateTypeHost, nil
	case ice.CandidateTypeServerReflexive:
		return ICECandidateTypeSrflx, nil
	case ice.CandidateTypePeerReflexive:
		return ICECandidateTypePrflx, nil
	case ice.CandidateTypeRelay:
		return ICECandidateTypeRelay, nil
	default:
		return ICECandidateType(t), fmt.Errorf("%w: %s", errICECandidateTypeUnknown, t)
	}
}

func (c ICECandidate) String() string {
	ic, err := c.ToICE()
	if err != nil {
		return fmt.Sprintf("%#v failed to convert to ICE: %s", c, err)
	}

	return ic.String()
}

func (c ICECandidate) ToJSON() ICECandidateInit {
	candidateStr := ""

	candidate, err := c.ToICE()
	if err == nil {
		candidateStr = candidate.Marshal()
	}

	return ICECandidateInit{
		Candidate:     fmt.Sprintf("candidate:%s", candidateStr),
		SDPMid:        &c.SDPMid,
		SDPMLineIndex: &c.SDPMLineIndex,
	}
}

type ICECandidateInit struct {
	Candidate        string  `json:"candidate"`
	SDPMid           *string `json:"sdpMid"`
	SDPMLineIndex    *uint16 `json:"sdpMLineIndex"`
	UsernameFragment *string `json:"usernameFragment"`
}

type ICECandidatePair struct {
	statsID string
	Local   *ICECandidate
	Remote  *ICECandidate
}

func newICECandidatePairStatsID(localID, remoteID string) string {
	return fmt.Sprintf("%s-%s", localID, remoteID)
}

func (p *ICECandidatePair) String() string {
	if p == nil {
		return "<nil>"
	}

	return fmt.Sprintf("(local) %s <-> (remote) %s", p.Local, p.Remote)
}

func NewICECandidatePair(local, remote *ICECandidate) *ICECandidatePair {
	statsID := newICECandidatePairStatsID(local.statsID, remote.statsID)

	return &ICECandidatePair{
		statsID: statsID,
		Local:   local,
		Remote:  remote,
	}
}

type ICECandidateType int

const (
	ICECandidateTypeUnknown ICECandidateType = iota

	ICECandidateTypeHost

	ICECandidateTypeSrflx

	ICECandidateTypePrflx

	ICECandidateTypeRelay
)

const (
	iceCandidateTypeHostStr  = "host"
	iceCandidateTypeSrflxStr = "srflx"
	iceCandidateTypePrflxStr = "prflx"
	iceCandidateTypeRelayStr = "relay"
)

func NewICECandidateType(raw string) (ICECandidateType, error) {
	switch raw {
	case iceCandidateTypeHostStr:
		return ICECandidateTypeHost, nil
	case iceCandidateTypeSrflxStr:
		return ICECandidateTypeSrflx, nil
	case iceCandidateTypePrflxStr:
		return ICECandidateTypePrflx, nil
	case iceCandidateTypeRelayStr:
		return ICECandidateTypeRelay, nil
	default:
		return ICECandidateTypeUnknown, fmt.Errorf("%w: %s", errICECandidateTypeUnknown, raw)
	}
}

func (t ICECandidateType) String() string {
	switch t {
	case ICECandidateTypeHost:
		return iceCandidateTypeHostStr
	case ICECandidateTypeSrflx:
		return iceCandidateTypeSrflxStr
	case ICECandidateTypePrflx:
		return iceCandidateTypePrflxStr
	case ICECandidateTypeRelay:
		return iceCandidateTypeRelayStr
	default:
		return ErrUnknownType.Error()
	}
}

func getCandidateType(candidateType ice.CandidateType) (ICECandidateType, error) {
	switch candidateType {
	case ice.CandidateTypeHost:
		return ICECandidateTypeHost, nil
	case ice.CandidateTypeServerReflexive:
		return ICECandidateTypeSrflx, nil
	case ice.CandidateTypePeerReflexive:
		return ICECandidateTypePrflx, nil
	case ice.CandidateTypeRelay:
		return ICECandidateTypeRelay, nil
	default:

		err := fmt.Errorf("%w: %s", errICEInvalidConvertCandidateType, candidateType.String())

		return ICECandidateTypeUnknown, err
	}
}

func (t ICECandidateType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t *ICECandidateType) UnmarshalText(b []byte) error {
	var err error
	*t, err = NewICECandidateType(string(b))

	return err
}

func (r ICECandidateType) toICE() ice.CandidateType {

	return ice.CandidateType(r)
}

type ICEConnectionState int

const (
	ICEConnectionStateUnknown ICEConnectionState = iota

	ICEConnectionStateNew

	ICEConnectionStateChecking

	ICEConnectionStateConnected

	ICEConnectionStateCompleted

	ICEConnectionStateDisconnected

	ICEConnectionStateFailed

	ICEConnectionStateClosed
)

const (
	iceConnectionStateNewStr          = "new"
	iceConnectionStateCheckingStr     = "checking"
	iceConnectionStateConnectedStr    = "connected"
	iceConnectionStateCompletedStr    = "completed"
	iceConnectionStateDisconnectedStr = "disconnected"
	iceConnectionStateFailedStr       = "failed"
	iceConnectionStateClosedStr       = "closed"
)

func (c ICEConnectionState) String() string {
	switch c {
	case ICEConnectionStateNew:
		return iceConnectionStateNewStr
	case ICEConnectionStateChecking:
		return iceConnectionStateCheckingStr
	case ICEConnectionStateConnected:
		return iceConnectionStateConnectedStr
	case ICEConnectionStateCompleted:
		return iceConnectionStateCompletedStr
	case ICEConnectionStateDisconnected:
		return iceConnectionStateDisconnectedStr
	case ICEConnectionStateFailed:
		return iceConnectionStateFailedStr
	case ICEConnectionStateClosed:
		return iceConnectionStateClosedStr
	default:
		return ErrUnknownType.Error()
	}
}

type ICECredentialType int

const (
	ICECredentialTypePassword ICECredentialType = iota

	ICECredentialTypeOauth
)

const (
	iceCredentialTypePasswordStr = "password"
	iceCredentialTypeOauthStr    = "oauth"
)

func newICECredentialType(raw string) (ICECredentialType, error) {
	switch raw {
	case iceCredentialTypePasswordStr:
		return ICECredentialTypePassword, nil
	case iceCredentialTypeOauthStr:
		return ICECredentialTypeOauth, nil
	default:
		return ICECredentialTypePassword, errInvalidICECredentialTypeString
	}
}

func (t ICECredentialType) String() string {
	switch t {
	case ICECredentialTypePassword:
		return iceCredentialTypePasswordStr
	case ICECredentialTypeOauth:
		return iceCredentialTypeOauthStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t *ICECredentialType) UnmarshalJSON(b []byte) error {
	var val string
	if err := json.Unmarshal(b, &val); err != nil {
		return err
	}

	tmp, err := newICECredentialType(val)
	if err != nil {
		return fmt.Errorf("%w: (%s)", err, val)
	}

	*t = tmp

	return nil
}

func (t ICECredentialType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

type ICEGathererState uint32

const (
	ICEGathererStateUnknown ICEGathererState = iota

	ICEGathererStateNew

	ICEGathererStateGathering

	ICEGathererStateComplete

	ICEGathererStateClosed
)

func (s ICEGathererState) String() string {
	switch s {
	case ICEGathererStateNew:
		return "new"
	case ICEGathererStateGathering:
		return "gathering"
	case ICEGathererStateComplete:
		return "complete"
	case ICEGathererStateClosed:
		return "closed"
	default:
		return ErrUnknownType.Error()
	}
}

func atomicStoreICEGathererState(state *ICEGathererState, newState ICEGathererState) {
	atomic.StoreUint32((*uint32)(state), uint32(newState))
}

func atomicLoadICEGathererState(state *ICEGathererState) ICEGathererState {
	return ICEGathererState(atomic.LoadUint32((*uint32)(state)))
}

type ICEGatheringState int

const (
	ICEGatheringStateUnknown ICEGatheringState = iota

	ICEGatheringStateNew

	ICEGatheringStateGathering

	ICEGatheringStateComplete
)

const (
	iceGatheringStateNewStr       = "new"
	iceGatheringStateGatheringStr = "gathering"
	iceGatheringStateCompleteStr  = "complete"
)

func (t ICEGatheringState) String() string {
	switch t {
	case ICEGatheringStateNew:
		return iceGatheringStateNewStr
	case ICEGatheringStateGathering:
		return iceGatheringStateGatheringStr
	case ICEGatheringStateComplete:
		return iceGatheringStateCompleteStr
	default:
		return ErrUnknownType.Error()
	}
}

type ICEGatherOptions struct {
	ICEServers           []ICEServer
	ICEGatherPolicy      ICETransportPolicy
	ICECandidatePoolSize uint8
}

type ICEParameters struct {
	UsernameFragment string `json:"usernameFragment"`
	Password         string `json:"password"`
	ICELite          bool   `json:"iceLite"`
}

type ICEProtocol int

const (
	ICEProtocolUnknown ICEProtocol = iota

	ICEProtocolUDP

	ICEProtocolTCP
)

const (
	iceProtocolUDPStr = "udp"
	iceProtocolTCPStr = "tcp"
)

func NewICEProtocol(raw string) (ICEProtocol, error) {
	switch {
	case strings.EqualFold(iceProtocolUDPStr, raw):
		return ICEProtocolUDP, nil
	case strings.EqualFold(iceProtocolTCPStr, raw):
		return ICEProtocolTCP, nil
	default:
		return ICEProtocolUnknown, fmt.Errorf("%w: %s", errICEProtocolUnknown, raw)
	}
}

func (t ICEProtocol) String() string {
	switch t {
	case ICEProtocolUDP:
		return iceProtocolUDPStr
	case ICEProtocolTCP:
		return iceProtocolTCPStr
	default:
		return ErrUnknownType.Error()
	}
}

type ICERole int

const (
	ICERoleUnknown ICERole = iota

	ICERoleControlling

	ICERoleControlled
)

const (
	iceRoleControllingStr = "controlling"
	iceRoleControlledStr  = "controlled"
)

func newICERole(raw string) ICERole {
	switch raw {
	case iceRoleControllingStr:
		return ICERoleControlling
	case iceRoleControlledStr:
		return ICERoleControlled
	default:
		return ICERoleUnknown
	}
}

func (t ICERole) String() string {
	switch t {
	case ICERoleControlling:
		return iceRoleControllingStr
	case ICERoleControlled:
		return iceRoleControlledStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t ICERole) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t *ICERole) UnmarshalText(b []byte) error {
	*t = newICERole(string(b))

	return nil
}

type ICETransportPolicy int

type ICEGatherPolicy = ICETransportPolicy

const (
	ICETransportPolicyAll ICETransportPolicy = iota

	ICETransportPolicyRelay

	ICETransportPolicyNoHost
)

const (
	iceTransportPolicyRelayStr  = "relay"
	iceTransportPolicyNoHostStr = "nohost"
	iceTransportPolicyAllStr    = "all"
)

func NewICETransportPolicy(raw string) ICETransportPolicy {
	switch raw {
	case iceTransportPolicyNoHostStr:
		return ICETransportPolicyNoHost
	case iceTransportPolicyRelayStr:
		return ICETransportPolicyRelay
	default:
		return ICETransportPolicyAll
	}
}

func (t ICETransportPolicy) String() string {
	switch t {
	case ICETransportPolicyNoHost:
		return iceTransportPolicyNoHostStr
	case ICETransportPolicyRelay:
		return iceTransportPolicyRelayStr
	case ICETransportPolicyAll:
		return iceTransportPolicyAllStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t *ICETransportPolicy) UnmarshalJSON(b []byte) error {
	var val string
	if err := json.Unmarshal(b, &val); err != nil {
		return err
	}
	*t = NewICETransportPolicy(val)

	return nil
}

func (t ICETransportPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

type ICETransportState int

const (
	ICETransportStateUnknown ICETransportState = iota

	ICETransportStateNew

	ICETransportStateChecking

	ICETransportStateConnected

	ICETransportStateCompleted

	ICETransportStateFailed

	ICETransportStateDisconnected

	ICETransportStateClosed
)

const (
	iceTransportStateNewStr          = "new"
	iceTransportStateCheckingStr     = "checking"
	iceTransportStateConnectedStr    = "connected"
	iceTransportStateCompletedStr    = "completed"
	iceTransportStateFailedStr       = "failed"
	iceTransportStateDisconnectedStr = "disconnected"
	iceTransportStateClosedStr       = "closed"
)

func newICETransportState(raw string) ICETransportState {
	switch raw {
	case iceTransportStateNewStr:
		return ICETransportStateNew
	case iceTransportStateCheckingStr:
		return ICETransportStateChecking
	case iceTransportStateConnectedStr:
		return ICETransportStateConnected
	case iceTransportStateCompletedStr:
		return ICETransportStateCompleted
	case iceTransportStateFailedStr:
		return ICETransportStateFailed
	case iceTransportStateDisconnectedStr:
		return ICETransportStateDisconnected
	case iceTransportStateClosedStr:
		return ICETransportStateClosed
	default:
		return ICETransportStateUnknown
	}
}

func (c ICETransportState) String() string {
	switch c {
	case ICETransportStateNew:
		return iceTransportStateNewStr
	case ICETransportStateChecking:
		return iceTransportStateCheckingStr
	case ICETransportStateConnected:
		return iceTransportStateConnectedStr
	case ICETransportStateCompleted:
		return iceTransportStateCompletedStr
	case ICETransportStateFailed:
		return iceTransportStateFailedStr
	case ICETransportStateDisconnected:
		return iceTransportStateDisconnectedStr
	case ICETransportStateClosed:
		return iceTransportStateClosedStr
	default:
		return ErrUnknownType.Error()
	}
}

func newICETransportStateFromICE(i ice.ConnectionState) ICETransportState {
	switch i {
	case ice.ConnectionStateNew:
		return ICETransportStateNew
	case ice.ConnectionStateChecking:
		return ICETransportStateChecking
	case ice.ConnectionStateConnected:
		return ICETransportStateConnected
	case ice.ConnectionStateCompleted:
		return ICETransportStateCompleted
	case ice.ConnectionStateFailed:
		return ICETransportStateFailed
	case ice.ConnectionStateDisconnected:
		return ICETransportStateDisconnected
	case ice.ConnectionStateClosed:
		return ICETransportStateClosed
	default:
		return ICETransportStateUnknown
	}
}

func (c ICETransportState) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

func (c *ICETransportState) UnmarshalText(b []byte) error {
	*c = newICETransportState(string(b))

	return nil
}

const (
	MimeTypeOpus = "audio/opus"

	MimeTypeVP8 = "video/VP8"

	MimeTypeRTX = "video/rtx"

	MimeTypeFlexFEC = "video/flexfec"
)

func supportedNetworkTypes() []NetworkType {
	return []NetworkType{
		NetworkTypeUDP4,
		NetworkTypeUDP6,
	}
}

type NetworkType int

const (
	NetworkTypeUnknown NetworkType = iota

	NetworkTypeUDP4

	NetworkTypeUDP6

	NetworkTypeTCP4

	NetworkTypeTCP6
)

const (
	networkTypeUDP4Str = "udp4"
	networkTypeUDP6Str = "udp6"
	networkTypeTCP4Str = "tcp4"
	networkTypeTCP6Str = "tcp6"
)

func (t NetworkType) String() string {
	switch t {
	case NetworkTypeUDP4:
		return networkTypeUDP4Str
	case NetworkTypeUDP6:
		return networkTypeUDP6Str
	case NetworkTypeTCP4:
		return networkTypeTCP4Str
	case NetworkTypeTCP6:
		return networkTypeTCP6Str
	default:
		return ErrUnknownType.Error()
	}
}

func (t NetworkType) Protocol() string {
	switch t {
	case NetworkTypeUDP4:
		return "udp"
	case NetworkTypeUDP6:
		return "udp"
	case NetworkTypeTCP4:
		return "tcp"
	case NetworkTypeTCP6:
		return "tcp"
	default:
		return ErrUnknownType.Error()
	}
}

func getNetworkType(iceNetworkType ice.NetworkType) (NetworkType, error) {
	switch iceNetworkType {
	case ice.NetworkTypeUDP4:
		return NetworkTypeUDP4, nil
	case ice.NetworkTypeUDP6:
		return NetworkTypeUDP6, nil
	case ice.NetworkTypeTCP4:
		return NetworkTypeTCP4, nil
	case ice.NetworkTypeTCP6:
		return NetworkTypeTCP6, nil
	default:
		return NetworkTypeUnknown, fmt.Errorf("%w: %s", errNetworkTypeUnknown, iceNetworkType.String())
	}
}

func toICENetworkTypes(networkTypes []NetworkType) []ice.NetworkType {
	if len(networkTypes) == 0 {
		return nil
	}

	converted := make([]ice.NetworkType, 0, len(networkTypes))
	for _, networkType := range networkTypes {
		converted = append(converted, networkType.toICE())
	}

	return converted
}

func (networkType NetworkType) toICE() ice.NetworkType {
	return ice.NetworkType(networkType)
}

type OAuthCredential struct {
	MACKey      string
	AccessToken string
}

type OfferAnswerOptions struct {
	VoiceActivityDetection bool
	ICETricklingSupported  bool
}

type AnswerOptions struct {
	OfferAnswerOptions
}

type OfferOptions struct {
	OfferAnswerOptions
	ICERestart bool
}

type operation func()

type operations struct {
	mu                                      sync.Mutex
	busyCh                                  chan struct{}
	ops                                     *list.List
	updateNegotiationNeededFlagOnEmptyChain *atomic.Bool
	onNegotiationNeeded                     func()
	isClosed                                bool
}

func newOperations(
	updateNegotiationNeededFlagOnEmptyChain *atomic.Bool,
	onNegotiationNeeded func(),
) *operations {
	return &operations{
		ops:                                     list.New(),
		updateNegotiationNeededFlagOnEmptyChain: updateNegotiationNeededFlagOnEmptyChain,
		onNegotiationNeeded:                     onNegotiationNeeded,
	}
}

func (o *operations) Enqueue(op operation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_ = o.tryEnqueue(op)
}

func (o *operations) tryEnqueue(op operation) bool {
	if op == nil {
		return false
	}

	if o.isClosed {
		return false
	}
	o.ops.PushBack(op)

	if o.busyCh == nil {
		o.busyCh = make(chan struct{})
		go o.start()
	}

	return true
}

func (o *operations) IsEmpty() bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.ops.Len() == 0
}

func (o *operations) Done() {
	var wg sync.WaitGroup
	wg.Add(1)
	o.mu.Lock()
	enqueued := o.tryEnqueue(func() {
		wg.Done()
	})
	o.mu.Unlock()
	if !enqueued {
		return
	}
	wg.Wait()
}

func (o *operations) GracefulClose() {
	o.mu.Lock()
	if o.isClosed {
		o.mu.Unlock()

		return
	}

	o.isClosed = true

	busyCh := o.busyCh
	o.mu.Unlock()
	if busyCh == nil {
		return
	}
	<-busyCh
}

func (o *operations) pop() func() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ops.Len() == 0 {
		return nil
	}

	e := o.ops.Front()
	o.ops.Remove(e)
	if op, ok := e.Value.(operation); ok {
		return op
	}

	return nil
}

func (o *operations) start() {
	defer func() {
		o.mu.Lock()
		defer o.mu.Unlock()

		close(o.busyCh)

		if o.ops.Len() == 0 || o.isClosed {
			o.busyCh = nil

			return
		}

		o.busyCh = make(chan struct{})
		go o.start()
	}()

	fn := o.pop()
	for fn != nil {
		fn()
		fn = o.pop()
	}
	if !o.updateNegotiationNeededFlagOnEmptyChain.Load() {
		return
	}
	o.updateNegotiationNeededFlagOnEmptyChain.Store(false)
	o.onNegotiationNeeded()
}

type PeerConnectionState int

const (
	PeerConnectionStateUnknown PeerConnectionState = iota

	PeerConnectionStateNew

	PeerConnectionStateConnecting

	PeerConnectionStateConnected

	PeerConnectionStateDisconnected

	PeerConnectionStateFailed

	PeerConnectionStateClosed
)

const (
	peerConnectionStateNewStr          = "new"
	peerConnectionStateConnectingStr   = "connecting"
	peerConnectionStateConnectedStr    = "connected"
	peerConnectionStateDisconnectedStr = "disconnected"
	peerConnectionStateFailedStr       = "failed"
	peerConnectionStateClosedStr       = "closed"
)

func (t PeerConnectionState) String() string {
	switch t {
	case PeerConnectionStateNew:
		return peerConnectionStateNewStr
	case PeerConnectionStateConnecting:
		return peerConnectionStateConnectingStr
	case PeerConnectionStateConnected:
		return peerConnectionStateConnectedStr
	case PeerConnectionStateDisconnected:
		return peerConnectionStateDisconnectedStr
	case PeerConnectionStateFailed:
		return peerConnectionStateFailedStr
	case PeerConnectionStateClosed:
		return peerConnectionStateClosedStr
	default:
		return ErrUnknownType.Error()
	}
}

const (
	TypeRTCPFBTransportCC = "transport-cc"

	TypeRTCPFBGoogREMB = "goog-remb"

	TypeRTCPFBACK = "ack"

	TypeRTCPFBCCM = "ccm"

	TypeRTCPFBNACK = "nack"
)

type RTCPFeedback struct {
	Type      string
	Parameter string
}

type RTCPMuxPolicy int

const (
	RTCPMuxPolicyUnknown RTCPMuxPolicy = iota

	RTCPMuxPolicyNegotiate

	RTCPMuxPolicyRequire
)

const (
	rtcpMuxPolicyNegotiateStr = "negotiate"
	rtcpMuxPolicyRequireStr   = "require"
)

func newRTCPMuxPolicy(raw string) RTCPMuxPolicy {
	switch raw {
	case rtcpMuxPolicyNegotiateStr:
		return RTCPMuxPolicyNegotiate
	case rtcpMuxPolicyRequireStr:
		return RTCPMuxPolicyRequire
	default:
		return RTCPMuxPolicyUnknown
	}
}

func (t RTCPMuxPolicy) String() string {
	switch t {
	case RTCPMuxPolicyNegotiate:
		return rtcpMuxPolicyNegotiateStr
	case RTCPMuxPolicyRequire:
		return rtcpMuxPolicyRequireStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t *RTCPMuxPolicy) UnmarshalJSON(b []byte) error {
	var val string
	if err := json.Unmarshal(b, &val); err != nil {
		return err
	}

	*t = newRTCPMuxPolicy(val)

	return nil
}

func (t RTCPMuxPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

type RTPCapabilities struct {
	Codecs           []RTPCodecCapability
	HeaderExtensions []RTPHeaderExtensionCapability
}

type RTPCodecType int

const (
	RTPCodecTypeUnknown RTPCodecType = iota

	RTPCodecTypeAudio

	RTPCodecTypeVideo
)

func (t RTPCodecType) String() string {
	switch t {
	case RTPCodecTypeAudio:
		return "audio"
	case RTPCodecTypeVideo:
		return "video"
	default:
		return ErrUnknownType.Error()
	}
}

func NewRTPCodecType(r string) RTPCodecType {
	switch {
	case strings.EqualFold(r, RTPCodecTypeAudio.String()):
		return RTPCodecTypeAudio
	case strings.EqualFold(r, RTPCodecTypeVideo.String()):
		return RTPCodecTypeVideo
	default:
		return RTPCodecType(0)
	}
}

type RTPCodecCapability struct {
	MimeType     string
	ClockRate    uint32
	Channels     uint16
	SDPFmtpLine  string
	RTCPFeedback []RTCPFeedback
}

type RTPHeaderExtensionCapability struct {
	URI string
}

type RTPHeaderExtensionParameter struct {
	URI string
	ID  int
}

type RTPCodecParameters struct {
	RTPCodecCapability
	PayloadType PayloadType
	statsID     string
}

type RTPParameters struct {
	HeaderExtensions []RTPHeaderExtensionParameter
	Codecs           []RTPCodecParameters
}

type codecMatchType int

const (
	codecMatchNone    codecMatchType = 0
	codecMatchPartial codecMatchType = 1
	codecMatchExact   codecMatchType = 2
)

func codecParametersFuzzySearch(
	needle RTPCodecParameters,
	haystack []RTPCodecParameters,
) (RTPCodecParameters, codecMatchType) {
	needleFmtp := wutil.ParseFMTP(
		needle.RTPCodecCapability.MimeType,
		needle.RTPCodecCapability.ClockRate,
		needle.RTPCodecCapability.Channels,
		needle.RTPCodecCapability.SDPFmtpLine)

	for _, c := range haystack {
		cfmtp := wutil.ParseFMTP(
			c.RTPCodecCapability.MimeType,
			c.RTPCodecCapability.ClockRate,
			c.RTPCodecCapability.Channels,
			c.RTPCodecCapability.SDPFmtpLine)

		if needleFmtp.Match(cfmtp) {
			return c, codecMatchExact
		}
	}

	for _, c := range haystack {
		if strings.EqualFold(c.RTPCodecCapability.MimeType, needle.RTPCodecCapability.MimeType) &&
			wutil.ClockRateEqual(c.RTPCodecCapability.MimeType,
				c.RTPCodecCapability.ClockRate,
				needle.RTPCodecCapability.ClockRate) &&
			wutil.ChannelsEqual(c.RTPCodecCapability.MimeType,
				c.RTPCodecCapability.Channels,
				needle.RTPCodecCapability.Channels) {
			return c, codecMatchPartial
		}
	}

	return RTPCodecParameters{}, codecMatchNone
}

func findRTXPayloadType(needle PayloadType, haystack []RTPCodecParameters) PayloadType {
	aptStr := fmt.Sprintf("apt=%d", needle)
	for _, c := range haystack {
		if aptStr == c.SDPFmtpLine {
			return c.PayloadType
		}
	}

	return PayloadType(0)
}

func primaryPayloadTypeForRTXExists(needle RTPCodecParameters, haystack []RTPCodecParameters) (
	isRTX bool, primaryExists bool,
) {
	if !strings.EqualFold(needle.MimeType, MimeTypeRTX) {
		return
	}

	isRTX = true
	parsed := wutil.ParseFMTP(needle.MimeType, needle.ClockRate, needle.Channels, needle.SDPFmtpLine)
	aptPayload, ok := parsed.Parameter("apt")
	if !ok {
		return
	}

	primaryPayloadType, err := strconv.Atoi(aptPayload)
	if err != nil || primaryPayloadType < 0 || primaryPayloadType > 255 {
		return
	}

	for _, c := range haystack {
		if c.PayloadType == PayloadType(primaryPayloadType) {
			primaryExists = true

			return
		}
	}

	return
}

func filterUnattachedRTX(codecs []RTPCodecParameters) []RTPCodecParameters {
	for i := len(codecs) - 1; i >= 0; i-- {
		c := codecs[i]
		if isRTX, primaryExists := primaryPayloadTypeForRTXExists(c, codecs); isRTX && !primaryExists {

			codecs = append(codecs[:i], codecs[i+1:]...)
		}
	}

	return codecs
}

func findFECPayloadType(haystack []RTPCodecParameters) PayloadType {
	for _, c := range haystack {
		if strings.Contains(c.RTPCodecCapability.MimeType, MimeTypeFlexFEC) {
			return c.PayloadType
		}
	}

	return PayloadType(0)
}

func rtcpFeedbackIntersection(a, b []RTCPFeedback) (out []RTCPFeedback) {
	for _, aFeedback := range a {
		for _, bFeeback := range b {
			if aFeedback.Type == bFeeback.Type && aFeedback.Parameter == bFeeback.Parameter {
				out = append(out, aFeedback)

				break
			}
		}
	}

	return
}

type RTPRtxParameters struct {
	SSRC SSRC `json:"ssrc"`
}

type RTPFecParameters struct {
	SSRC SSRC `json:"ssrc"`
}

type RTPCodingParameters struct {
	RID         string           `json:"rid"`
	SSRC        SSRC             `json:"ssrc"`
	PayloadType PayloadType      `json:"payloadType"`
	RTX         RTPRtxParameters `json:"rtx"`
	FEC         RTPFecParameters `json:"fec"`
}

type RTPDecodingParameters struct {
	RTPCodingParameters
}

type RTPEncodingParameters struct {
	RTPCodingParameters
}

type RTPReceiveParameters struct {
	Encodings []RTPDecodingParameters
}

type RTPSendParameters struct {
	RTPParameters
	Encodings []RTPEncodingParameters
}

type RTPTransceiverDirection int

const (
	RTPTransceiverDirectionUnknown RTPTransceiverDirection = iota

	RTPTransceiverDirectionSendrecv

	RTPTransceiverDirectionSendonly

	RTPTransceiverDirectionRecvonly

	RTPTransceiverDirectionInactive
)

const (
	rtpTransceiverDirectionSendrecvStr = "sendrecv"
	rtpTransceiverDirectionSendonlyStr = "sendonly"
	rtpTransceiverDirectionRecvonlyStr = "recvonly"
	rtpTransceiverDirectionInactiveStr = "inactive"
)

func NewRTPTransceiverDirection(raw string) RTPTransceiverDirection {
	switch raw {
	case rtpTransceiverDirectionSendrecvStr:
		return RTPTransceiverDirectionSendrecv
	case rtpTransceiverDirectionSendonlyStr:
		return RTPTransceiverDirectionSendonly
	case rtpTransceiverDirectionRecvonlyStr:
		return RTPTransceiverDirectionRecvonly
	case rtpTransceiverDirectionInactiveStr:
		return RTPTransceiverDirectionInactive
	default:
		return RTPTransceiverDirectionUnknown
	}
}

func (t RTPTransceiverDirection) String() string {
	switch t {
	case RTPTransceiverDirectionSendrecv:
		return rtpTransceiverDirectionSendrecvStr
	case RTPTransceiverDirectionSendonly:
		return rtpTransceiverDirectionSendonlyStr
	case RTPTransceiverDirectionRecvonly:
		return rtpTransceiverDirectionRecvonlyStr
	case RTPTransceiverDirectionInactive:
		return rtpTransceiverDirectionInactiveStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t RTPTransceiverDirection) Revers() RTPTransceiverDirection {
	switch t {
	case RTPTransceiverDirectionSendonly:
		return RTPTransceiverDirectionRecvonly
	case RTPTransceiverDirectionRecvonly:
		return RTPTransceiverDirectionSendonly
	default:
		return t
	}
}

func haveRTPTransceiverDirectionIntersection(
	haystack []RTPTransceiverDirection,
	needle []RTPTransceiverDirection,
) bool {
	for _, n := range needle {
		if slices.Contains(haystack, n) {
			return true
		}
	}

	return false
}

type RTPTransceiverInit struct {
	Direction     RTPTransceiverDirection
	SendEncodings []RTPEncodingParameters
}

type SCTPCapabilities struct {
	MaxMessageSize uint32 `json:"maxMessageSize"`
	sctpInit       string
}

type SCTPTransportState int

const (
	SCTPTransportStateUnknown SCTPTransportState = iota

	SCTPTransportStateConnecting

	SCTPTransportStateConnected

	SCTPTransportStateClosed
)

const (
	sctpTransportStateConnectingStr = "connecting"
	sctpTransportStateConnectedStr  = "connected"
	sctpTransportStateClosedStr     = "closed"
)

func (s SCTPTransportState) String() string {
	switch s {
	case SCTPTransportStateConnecting:
		return sctpTransportStateConnectingStr
	case SCTPTransportStateConnected:
		return sctpTransportStateConnectedStr
	case SCTPTransportStateClosed:
		return sctpTransportStateClosedStr
	default:
		return ErrUnknownType.Error()
	}
}

type SDPSemantics int

const (
	SDPSemanticsUnifiedPlan SDPSemantics = iota

	SDPSemanticsPlanB

	SDPSemanticsUnifiedPlanWithFallback
)

const (
	sdpSemanticsUnifiedPlanWithFallback = "unified-plan-with-fallback"
	sdpSemanticsUnifiedPlan             = "unified-plan"
	sdpSemanticsPlanB                   = "plan-b"
)

func newSDPSemantics(raw string) SDPSemantics {
	switch raw {
	case sdpSemanticsPlanB:
		return SDPSemanticsPlanB
	case sdpSemanticsUnifiedPlanWithFallback:
		return SDPSemanticsUnifiedPlanWithFallback
	default:
		return SDPSemanticsUnifiedPlan
	}
}

func (s SDPSemantics) String() string {
	switch s {
	case SDPSemanticsUnifiedPlanWithFallback:
		return sdpSemanticsUnifiedPlanWithFallback
	case SDPSemanticsUnifiedPlan:
		return sdpSemanticsUnifiedPlan
	case SDPSemanticsPlanB:
		return sdpSemanticsPlanB
	default:
		return ErrUnknownType.Error()
	}
}

func (s *SDPSemantics) UnmarshalJSON(b []byte) error {
	var val string
	if err := json.Unmarshal(b, &val); err != nil {
		return err
	}

	*s = newSDPSemantics(val)

	return nil
}

func (s SDPSemantics) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type SDPType int

const (
	SDPTypeUnknown SDPType = iota

	SDPTypeOffer

	SDPTypePranswer

	SDPTypeAnswer

	SDPTypeRollback
)

const (
	sdpTypeOfferStr    = "offer"
	sdpTypePranswerStr = "pranswer"
	sdpTypeAnswerStr   = "answer"
	sdpTypeRollbackStr = "rollback"
)

func NewSDPType(raw string) SDPType {
	switch raw {
	case sdpTypeOfferStr:
		return SDPTypeOffer
	case sdpTypePranswerStr:
		return SDPTypePranswer
	case sdpTypeAnswerStr:
		return SDPTypeAnswer
	case sdpTypeRollbackStr:
		return SDPTypeRollback
	default:
		return SDPTypeUnknown
	}
}

func (t SDPType) String() string {
	switch t {
	case SDPTypeOffer:
		return sdpTypeOfferStr
	case SDPTypePranswer:
		return sdpTypePranswerStr
	case SDPTypeAnswer:
		return sdpTypeAnswerStr
	case SDPTypeRollback:
		return sdpTypeRollbackStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t SDPType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *SDPType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	default:
		return ErrUnknownType
	case "offer":
		*t = SDPTypeOffer
	case "pranswer":
		*t = SDPTypePranswer
	case "answer":
		*t = SDPTypeAnswer
	case "rollback":
		*t = SDPTypeRollback
	}

	return nil
}

type ICETrickleCapability int

const (
	ICETrickleCapabilityUnknown ICETrickleCapability = iota

	ICETrickleCapabilitySupported

	ICETrickleCapabilityUnsupported
)

func (t ICETrickleCapability) String() string {
	switch t {
	case ICETrickleCapabilitySupported:
		return "supported"
	case ICETrickleCapabilityUnsupported:
		return "unsupported"
	default:
		return "unknown"
	}
}

type SessionDescription struct {
	Type   SDPType `json:"type"`
	SDP    string  `json:"sdp"`
	parsed *sdp.SessionDescription
}

func (sd *SessionDescription) Unmarshal() (*sdp.SessionDescription, error) {
	sd.parsed = &sdp.SessionDescription{}
	err := sd.parsed.UnmarshalString(sd.SDP)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSDPUnmarshalling, err)
	}

	return sd.parsed, nil
}

func hasICETrickleOption(desc *sdp.SessionDescription) bool {
	if value, ok := desc.Attribute(sdp.AttrKeyICEOptions); ok && hasTrickleOptionValue(value) {
		return true
	}

	for _, media := range desc.MediaDescriptions {
		if value, ok := media.Attribute(sdp.AttrKeyICEOptions); ok && hasTrickleOptionValue(value) {
			return true
		}
	}

	return false
}

func hasTrickleOptionValue(value string) bool {
	return slices.Contains(strings.Fields(value), "trickle")
}

type stateChangeOp int

const (
	stateChangeOpSetLocal stateChangeOp = iota + 1
	stateChangeOpSetRemote
)

func (op stateChangeOp) String() string {
	switch op {
	case stateChangeOpSetLocal:
		return "SetLocal"
	case stateChangeOpSetRemote:
		return "SetRemote"
	default:
		return "Unknown State Change Operation"
	}
}

type SignalingState int32

const (
	SignalingStateUnknown SignalingState = iota

	SignalingStateStable

	SignalingStateHaveLocalOffer

	SignalingStateHaveRemoteOffer

	SignalingStateHaveLocalPranswer

	SignalingStateHaveRemotePranswer

	SignalingStateClosed
)

const (
	signalingStateStableStr             = "stable"
	signalingStateHaveLocalOfferStr     = "have-local-offer"
	signalingStateHaveRemoteOfferStr    = "have-remote-offer"
	signalingStateHaveLocalPranswerStr  = "have-local-pranswer"
	signalingStateHaveRemotePranswerStr = "have-remote-pranswer"
	signalingStateClosedStr             = "closed"
)

func (t SignalingState) String() string {
	switch t {
	case SignalingStateStable:
		return signalingStateStableStr
	case SignalingStateHaveLocalOffer:
		return signalingStateHaveLocalOfferStr
	case SignalingStateHaveRemoteOffer:
		return signalingStateHaveRemoteOfferStr
	case SignalingStateHaveLocalPranswer:
		return signalingStateHaveLocalPranswerStr
	case SignalingStateHaveRemotePranswer:
		return signalingStateHaveRemotePranswerStr
	case SignalingStateClosed:
		return signalingStateClosedStr
	default:
		return ErrUnknownType.Error()
	}
}

func (t *SignalingState) Get() SignalingState {
	return SignalingState(atomic.LoadInt32((*int32)(t)))
}

func (t *SignalingState) Set(state SignalingState) {
	atomic.StoreInt32((*int32)(t), int32(state))
}

func checkNextSignalingState(cur, next SignalingState, op stateChangeOp, sdpType SDPType) (SignalingState, error) {

	if sdpType == SDPTypeRollback && cur == SignalingStateStable {
		return cur, &InvalidModificationError{
			Err: errSignalingStateCannotRollback,
		}
	}

	switch cur {
	case SignalingStateStable:
		switch op {
		case stateChangeOpSetLocal:

			if sdpType == SDPTypeOffer && next == SignalingStateHaveLocalOffer {
				return next, nil
			}
		case stateChangeOpSetRemote:

			if sdpType == SDPTypeOffer && next == SignalingStateHaveRemoteOffer {
				return next, nil
			}
		}
	case SignalingStateHaveLocalOffer:
		if op == stateChangeOpSetRemote {
			switch sdpType {

			case SDPTypeAnswer:
				if next == SignalingStateStable {
					return next, nil
				}

			case SDPTypePranswer:
				if next == SignalingStateHaveRemotePranswer {
					return next, nil
				}
			}
		}
	case SignalingStateHaveRemotePranswer:
		if op == stateChangeOpSetRemote && sdpType == SDPTypeAnswer {

			if next == SignalingStateStable {
				return next, nil
			}
		}
	case SignalingStateHaveRemoteOffer:
		if op == stateChangeOpSetLocal {
			switch sdpType {

			case SDPTypeAnswer:
				if next == SignalingStateStable {
					return next, nil
				}

			case SDPTypePranswer:
				if next == SignalingStateHaveLocalPranswer {
					return next, nil
				}
			}
		}
	case SignalingStateHaveLocalPranswer:
		if op == stateChangeOpSetLocal && sdpType == SDPTypeAnswer {

			if next == SignalingStateStable {
				return next, nil
			}
		}
	}

	return cur, &InvalidModificationError{
		Err: fmt.Errorf("%w: %s->%s(%s)->%s", errSignalingStateProposedTransitionInvalid, cur, op, sdpType, next),
	}
}

type Stats interface {
	statsMarker()
}

type StatsType string

const (
	StatsTypeCodec StatsType = "codec"

	StatsTypeInboundRTP StatsType = "inbound-rtp"

	StatsTypeOutboundRTP StatsType = "outbound-rtp"

	StatsTypeRemoteInboundRTP StatsType = "remote-inbound-rtp"

	StatsTypeRemoteOutboundRTP StatsType = "remote-outbound-rtp"

	StatsTypeCSRC StatsType = "csrc"

	StatsTypeMediaSource = "media-source"

	StatsTypeMediaPlayout StatsType = "media-playout"

	StatsTypePeerConnection StatsType = "peer-connection"

	StatsTypeDataChannel StatsType = "data-channel"

	StatsTypeStream StatsType = "stream"

	StatsTypeTrack StatsType = "track"

	StatsTypeSender StatsType = "sender"

	StatsTypeReceiver StatsType = "receiver"

	StatsTypeTransport StatsType = "transport"

	StatsTypeCandidatePair StatsType = "candidate-pair"

	StatsTypeLocalCandidate StatsType = "local-candidate"

	StatsTypeRemoteCandidate StatsType = "remote-candidate"

	StatsTypeCertificate StatsType = "certificate"

	StatsTypeSCTPTransport StatsType = "sctp-transport"
)

type MediaKind string

const (
	MediaKindAudio MediaKind = "audio"

	MediaKindVideo MediaKind = "video"
)

type StatsTimestamp float64

func (s StatsTimestamp) Time() time.Time {
	millis := float64(s)
	nanos := int64(millis * float64(time.Millisecond))

	return time.Unix(0, nanos).UTC()
}

func statsTimestampFrom(t time.Time) StatsTimestamp {
	return StatsTimestamp(t.UnixNano() / int64(time.Millisecond))
}

func statsTimestampNow() StatsTimestamp {
	return statsTimestampFrom(time.Now())
}

type StatsReport map[string]Stats

type statsReportCollector struct {
	collectingGroup sync.WaitGroup
	report          StatsReport
	mux             sync.Mutex
}

type SCTPTransportPartialReliabilityMode string

const (
	SCTPTransportPartialReliabilityModeNone        SCTPTransportPartialReliabilityMode = "none"
	SCTPTransportPartialReliabilityModeForwardTSN  SCTPTransportPartialReliabilityMode = "forward-tsn"
	SCTPTransportPartialReliabilityModeIForwardTSN SCTPTransportPartialReliabilityMode = "i-forward-tsn"
)

type SCTPTransportMetadata struct {
	MessageInterleavingEnabled   bool                                `json:"messageInterleavingEnabled"`
	PartialReliabilityMode       SCTPTransportPartialReliabilityMode `json:"partialReliabilityMode"`
	ZeroChecksumSendingEnabled   bool                                `json:"zeroChecksumSendingEnabled"`
	ZeroChecksumReceivingEnabled bool                                `json:"zeroChecksumReceivingEnabled"`
}

func newStatsReportCollector() *statsReportCollector {
	return &statsReportCollector{report: make(StatsReport)}
}

func (src *statsReportCollector) Collecting() {
	src.collectingGroup.Add(1)
}

func (src *statsReportCollector) Collect(id string, stats Stats) {
	src.mux.Lock()
	defer src.mux.Unlock()

	src.report[id] = stats
	src.collectingGroup.Done()
}

func (src *statsReportCollector) Done() {
	src.collectingGroup.Done()
}

func (src *statsReportCollector) Ready() StatsReport {
	src.collectingGroup.Wait()
	src.mux.Lock()
	defer src.mux.Unlock()

	return src.report
}

type CodecType string

const (
	CodecTypeEncode CodecType = "encode"

	CodecTypeDecode CodecType = "decode"
)

type CodecStats struct {
	Timestamp      StatsTimestamp `json:"timestamp"`
	Type           StatsType      `json:"type"`
	ID             string         `json:"id"`
	PayloadType    PayloadType    `json:"payloadType"`
	CodecType      CodecType      `json:"codecType"`
	TransportID    string         `json:"transportId"`
	MimeType       string         `json:"mimeType"`
	ClockRate      uint32         `json:"clockRate"`
	Channels       uint8          `json:"channels"`
	SDPFmtpLine    string         `json:"sdpFmtpLine"`
	Implementation string         `json:"implementation"`
}

func (s CodecStats) statsMarker() {}

type InboundRTPStreamStats struct {
	Mid                            string            `json:"mid"`
	Rid                            string            `json:"rid,omitempty"`
	Timestamp                      StatsTimestamp    `json:"timestamp"`
	Type                           StatsType         `json:"type"`
	ID                             string            `json:"id"`
	SSRC                           SSRC              `json:"ssrc"`
	Kind                           string            `json:"kind"`
	TransportID                    string            `json:"transportId"`
	CodecID                        string            `json:"codecId"`
	FIRCount                       uint32            `json:"firCount"`
	PLICount                       uint32            `json:"pliCount"`
	TotalProcessingDelay           float64           `json:"totalProcessingDelay"`
	NACKCount                      uint32            `json:"nackCount"`
	JitterBufferDelay              float64           `json:"jitterBufferDelay"`
	JitterBufferTargetDelay        float64           `json:"jitterBufferTargetDelay"`
	JitterBufferEmittedCount       uint64            `json:"jitterBufferEmittedCount"`
	JitterBufferMinimumDelay       float64           `json:"jitterBufferMinimumDelay"`
	TotalSamplesReceived           uint64            `json:"totalSamplesReceived"`
	ConcealedSamples               uint64            `json:"concealedSamples"`
	SilentConcealedSamples         uint64            `json:"silentConcealedSamples"`
	ConcealmentEvents              uint64            `json:"concealmentEvents"`
	InsertedSamplesForDeceleration uint64            `json:"insertedSamplesForDeceleration"`
	RemovedSamplesForAcceleration  uint64            `json:"removedSamplesForAcceleration"`
	AudioLevel                     float64           `json:"audioLevel"`
	TotalAudioEnergy               float64           `json:"totalAudioEnergy"`
	TotalSamplesDuration           float64           `json:"totalSamplesDuration"`
	SLICount                       uint32            `json:"sliCount"`
	QPSum                          uint64            `json:"qpSum"`
	TotalDecodeTime                float64           `json:"totalDecodeTime"`
	TotalInterFrameDelay           float64           `json:"totalInterFrameDelay"`
	TotalSquaredInterFrameDelay    float64           `json:"totalSquaredInterFrameDelay"`
	PacketsReceived                uint32            `json:"packetsReceived"`
	PacketsLost                    int32             `json:"packetsLost"`
	Jitter                         float64           `json:"jitter"`
	PacketsDiscarded               uint32            `json:"packetsDiscarded"`
	PacketsRepaired                uint32            `json:"packetsRepaired"`
	BurstPacketsLost               uint32            `json:"burstPacketsLost"`
	BurstPacketsDiscarded          uint32            `json:"burstPacketsDiscarded"`
	BurstLossCount                 uint32            `json:"burstLossCount"`
	BurstDiscardCount              uint32            `json:"burstDiscardCount"`
	BurstLossRate                  float64           `json:"burstLossRate"`
	BurstDiscardRate               float64           `json:"burstDiscardRate"`
	GapLossRate                    float64           `json:"gapLossRate"`
	GapDiscardRate                 float64           `json:"gapDiscardRate"`
	TrackID                        string            `json:"trackId"`
	ReceiverID                     string            `json:"receiverId"`
	RemoteID                       string            `json:"remoteId"`
	FramesDecoded                  uint32            `json:"framesDecoded"`
	KeyFramesDecoded               uint32            `json:"keyFramesDecoded"`
	FramesRendered                 uint32            `json:"framesRendered"`
	FramesDropped                  uint32            `json:"framesDropped"`
	FrameWidth                     uint32            `json:"frameWidth"`
	FrameHeight                    uint32            `json:"frameHeight"`
	LastPacketReceivedTimestamp    StatsTimestamp    `json:"lastPacketReceivedTimestamp"`
	HeaderBytesReceived            uint64            `json:"headerBytesReceived"`
	AverageRTCPInterval            float64           `json:"averageRtcpInterval"`
	FECPacketsReceived             uint32            `json:"fecPacketsReceived"`
	FECPacketsDiscarded            uint64            `json:"fecPacketsDiscarded"`
	BytesReceived                  uint64            `json:"bytesReceived"`
	FramesReceived                 uint32            `json:"framesReceived"`
	PacketsFailedDecryption        uint32            `json:"packetsFailedDecryption"`
	PacketsDuplicated              uint32            `json:"packetsDuplicated"`
	PerDSCPPacketsReceived         map[string]uint32 `json:"perDscpPacketsReceived"`
	DecoderImplementation          string            `json:"decoderImplementation"`
	PauseCount                     uint32            `json:"pauseCount"`
	TotalPausesDuration            float64           `json:"totalPausesDuration"`
	FreezeCount                    uint32            `json:"freezeCount"`
	TotalFreezesDuration           float64           `json:"totalFreezesDuration"`
	PowerEfficientDecoder          bool              `json:"powerEfficientDecoder"`
}

func (s InboundRTPStreamStats) statsMarker() {}

type QualityLimitationReason string

const (
	QualityLimitationReasonNone QualityLimitationReason = "none"

	QualityLimitationReasonCPU QualityLimitationReason = "cpu"

	QualityLimitationReasonBandwidth QualityLimitationReason = "bandwidth"

	QualityLimitationReasonOther QualityLimitationReason = "other"
)

type OutboundRTPStreamStats struct {
	Mid                                string                  `json:"mid"`
	Rid                                string                  `json:"rid"`
	MediaSourceID                      string                  `json:"mediaSourceId"`
	Timestamp                          StatsTimestamp          `json:"timestamp"`
	Type                               StatsType               `json:"type"`
	ID                                 string                  `json:"id"`
	SSRC                               SSRC                    `json:"ssrc"`
	Kind                               string                  `json:"kind"`
	TransportID                        string                  `json:"transportId"`
	CodecID                            string                  `json:"codecId"`
	HeaderBytesSent                    uint64                  `json:"headerBytesSent"`
	RetransmittedPacketsSent           uint64                  `json:"retransmittedPacketsSent"`
	RetransmittedBytesSent             uint64                  `json:"retransmittedBytesSent"`
	FIRCount                           uint32                  `json:"firCount"`
	PLICount                           uint32                  `json:"pliCount"`
	NACKCount                          uint32                  `json:"nackCount"`
	SLICount                           uint32                  `json:"sliCount"`
	QPSum                              uint64                  `json:"qpSum"`
	PacketsSent                        uint32                  `json:"packetsSent"`
	PacketsDiscardedOnSend             uint32                  `json:"packetsDiscardedOnSend"`
	FECPacketsSent                     uint32                  `json:"fecPacketsSent"`
	BytesSent                          uint64                  `json:"bytesSent"`
	BytesDiscardedOnSend               uint64                  `json:"bytesDiscardedOnSend"`
	TrackID                            string                  `json:"trackId"`
	SenderID                           string                  `json:"senderId"`
	RemoteID                           string                  `json:"remoteId"`
	LastPacketSentTimestamp            StatsTimestamp          `json:"lastPacketSentTimestamp"`
	TargetBitrate                      float64                 `json:"targetBitrate"`
	TotalEncodedBytesTarget            uint64                  `json:"totalEncodedBytesTarget"`
	FrameWidth                         uint32                  `json:"frameWidth"`
	FrameHeight                        uint32                  `json:"frameHeight"`
	FramesPerSecond                    float64                 `json:"framesPerSecond"`
	FramesSent                         uint32                  `json:"framesSent"`
	HugeFramesSent                     uint32                  `json:"hugeFramesSent"`
	FramesEncoded                      uint32                  `json:"framesEncoded"`
	KeyFramesEncoded                   uint32                  `json:"keyFramesEncoded"`
	TotalEncodeTime                    float64                 `json:"totalEncodeTime"`
	TotalPacketSendDelay               float64                 `json:"totalPacketSendDelay"`
	AverageRTCPInterval                float64                 `json:"averageRtcpInterval"`
	QualityLimitationReason            QualityLimitationReason `json:"qualityLimitationReason"`
	QualityLimitationDurations         map[string]float64      `json:"qualityLimitationDurations"`
	QualityLimitationResolutionChanges uint32                  `json:"qualityLimitationResolutionChanges"`
	PerDSCPPacketsSent                 map[string]uint32       `json:"perDscpPacketsSent"`
	Active                             bool                    `json:"active"`
	EncoderImplementation              string                  `json:"encoderImplementation"`
	PowerEfficientEncoder              bool                    `json:"powerEfficientEncoder"`
	ScalabilityMode                    string                  `json:"scalabilityMode"`
}

func (s OutboundRTPStreamStats) statsMarker() {}

type RemoteInboundRTPStreamStats struct {
	Timestamp                 StatsTimestamp `json:"timestamp"`
	Type                      StatsType      `json:"type"`
	ID                        string         `json:"id"`
	SSRC                      SSRC           `json:"ssrc"`
	Kind                      string         `json:"kind"`
	TransportID               string         `json:"transportId"`
	CodecID                   string         `json:"codecId"`
	FIRCount                  uint32         `json:"firCount"`
	PLICount                  uint32         `json:"pliCount"`
	NACKCount                 uint32         `json:"nackCount"`
	SLICount                  uint32         `json:"sliCount"`
	QPSum                     uint64         `json:"qpSum"`
	PacketsReceived           uint32         `json:"packetsReceived"`
	PacketsLost               int32          `json:"packetsLost"`
	Jitter                    float64        `json:"jitter"`
	PacketsDiscarded          uint32         `json:"packetsDiscarded"`
	PacketsRepaired           uint32         `json:"packetsRepaired"`
	BurstPacketsLost          uint32         `json:"burstPacketsLost"`
	BurstPacketsDiscarded     uint32         `json:"burstPacketsDiscarded"`
	BurstLossCount            uint32         `json:"burstLossCount"`
	BurstDiscardCount         uint32         `json:"burstDiscardCount"`
	BurstLossRate             float64        `json:"burstLossRate"`
	BurstDiscardRate          float64        `json:"burstDiscardRate"`
	GapLossRate               float64        `json:"gapLossRate"`
	GapDiscardRate            float64        `json:"gapDiscardRate"`
	LocalID                   string         `json:"localId"`
	RoundTripTime             float64        `json:"roundTripTime"`
	TotalRoundTripTime        float64        `json:"totalRoundTripTime"`
	FractionLost              float64        `json:"fractionLost"`
	RoundTripTimeMeasurements uint64         `json:"roundTripTimeMeasurements"`
}

func (s RemoteInboundRTPStreamStats) statsMarker() {}

type RemoteOutboundRTPStreamStats struct {
	Timestamp                 StatsTimestamp `json:"timestamp"`
	Type                      StatsType      `json:"type"`
	ID                        string         `json:"id"`
	SSRC                      SSRC           `json:"ssrc"`
	Kind                      string         `json:"kind"`
	TransportID               string         `json:"transportId"`
	CodecID                   string         `json:"codecId"`
	FIRCount                  uint32         `json:"firCount"`
	PLICount                  uint32         `json:"pliCount"`
	NACKCount                 uint32         `json:"nackCount"`
	SLICount                  uint32         `json:"sliCount"`
	QPSum                     uint64         `json:"qpSum"`
	PacketsSent               uint32         `json:"packetsSent"`
	PacketsDiscardedOnSend    uint32         `json:"packetsDiscardedOnSend"`
	FECPacketsSent            uint32         `json:"fecPacketsSent"`
	BytesSent                 uint64         `json:"bytesSent"`
	BytesDiscardedOnSend      uint64         `json:"bytesDiscardedOnSend"`
	LocalID                   string         `json:"localId"`
	RemoteTimestamp           StatsTimestamp `json:"remoteTimestamp"`
	ReportsSent               uint64         `json:"reportsSent"`
	RoundTripTime             float64        `json:"roundTripTime"`
	TotalRoundTripTime        float64        `json:"totalRoundTripTime"`
	RoundTripTimeMeasurements uint64         `json:"roundTripTimeMeasurements"`
}

func (s RemoteOutboundRTPStreamStats) statsMarker() {}

type RTPContributingSourceStats struct {
	Timestamp            StatsTimestamp `json:"timestamp"`
	Type                 StatsType      `json:"type"`
	ID                   string         `json:"id"`
	ContributorSSRC      SSRC           `json:"contributorSsrc"`
	InboundRTPStreamID   string         `json:"inboundRtpStreamId"`
	PacketsContributedTo uint32         `json:"packetsContributedTo"`
	AudioLevel           float64        `json:"audioLevel"`
}

func (s RTPContributingSourceStats) statsMarker() {}

type AudioSourceStats struct {
	Timestamp                 StatsTimestamp `json:"timestamp"`
	Type                      StatsType      `json:"type"`
	ID                        string         `json:"id"`
	TrackIdentifier           string         `json:"trackIdentifier"`
	Kind                      string         `json:"kind"`
	AudioLevel                float64        `json:"audioLevel"`
	TotalAudioEnergy          float64        `json:"totalAudioEnergy"`
	TotalSamplesDuration      float64        `json:"totalSamplesDuration"`
	EchoReturnLoss            float64        `json:"echoReturnLoss"`
	EchoReturnLossEnhancement float64        `json:"echoReturnLossEnhancement"`
	DroppedSamplesDuration    float64        `json:"droppedSamplesDuration"`
	DroppedSamplesEvents      uint64         `json:"droppedSamplesEvents"`
	TotalCaptureDelay         float64        `json:"totalCaptureDelay"`
	TotalSamplesCaptured      uint64         `json:"totalSamplesCaptured"`
}

func (s AudioSourceStats) statsMarker() {}

type VideoSourceStats struct {
	Timestamp       StatsTimestamp `json:"timestamp"`
	Type            StatsType      `json:"type"`
	ID              string         `json:"id"`
	TrackIdentifier string         `json:"trackIdentifier"`
	Kind            string         `json:"kind"`
	Width           uint32         `json:"width"`
	Height          uint32         `json:"height"`
	Frames          uint32         `json:"frames"`
	FramesPerSecond float64        `json:"framesPerSecond"`
}

func (s VideoSourceStats) statsMarker() {}

type AudioPlayoutStats struct {
	Timestamp                  StatsTimestamp `json:"timestamp"`
	Type                       StatsType      `json:"type"`
	ID                         string         `json:"id"`
	Kind                       string         `json:"kind"`
	SynthesizedSamplesDuration float64        `json:"synthesizedSamplesDuration"`
	SynthesizedSamplesEvents   uint64         `json:"synthesizedSamplesEvents"`
	TotalSamplesDuration       float64        `json:"totalSamplesDuration"`
	TotalPlayoutDelay          float64        `json:"totalPlayoutDelay"`
	TotalSamplesCount          uint64         `json:"totalSamplesCount"`
}

func (s AudioPlayoutStats) statsMarker() {}

type PeerConnectionStats struct {
	Timestamp             StatsTimestamp `json:"timestamp"`
	Type                  StatsType      `json:"type"`
	ID                    string         `json:"id"`
	DataChannelsOpened    uint32         `json:"dataChannelsOpened"`
	DataChannelsClosed    uint32         `json:"dataChannelsClosed"`
	DataChannelsRequested uint32         `json:"dataChannelsRequested"`
	DataChannelsAccepted  uint32         `json:"dataChannelsAccepted"`
}

func (s PeerConnectionStats) statsMarker() {}

type DataChannelStats struct {
	Timestamp             StatsTimestamp   `json:"timestamp"`
	Type                  StatsType        `json:"type"`
	ID                    string           `json:"id"`
	Label                 string           `json:"label"`
	Protocol              string           `json:"protocol"`
	DataChannelIdentifier int32            `json:"dataChannelIdentifier"`
	TransportID           string           `json:"transportId"`
	State                 DataChannelState `json:"state"`
	MessagesSent          uint32           `json:"messagesSent"`
	BytesSent             uint64           `json:"bytesSent"`
	MessagesReceived      uint32           `json:"messagesReceived"`
	BytesReceived         uint64           `json:"bytesReceived"`
}

func (s DataChannelStats) statsMarker() {}

type MediaStreamStats struct {
	Timestamp        StatsTimestamp `json:"timestamp"`
	Type             StatsType      `json:"type"`
	ID               string         `json:"id"`
	StreamIdentifier string         `json:"streamIdentifier"`
	TrackIDs         []string       `json:"trackIds"`
}

func (s MediaStreamStats) statsMarker() {}

type AudioSenderStats struct {
	Timestamp                 StatsTimestamp `json:"timestamp"`
	Type                      StatsType      `json:"type"`
	ID                        string         `json:"id"`
	TrackIdentifier           string         `json:"trackIdentifier"`
	RemoteSource              bool           `json:"remoteSource"`
	Ended                     bool           `json:"ended"`
	Kind                      string         `json:"kind"`
	AudioLevel                float64        `json:"audioLevel"`
	TotalAudioEnergy          float64        `json:"totalAudioEnergy"`
	VoiceActivityFlag         bool           `json:"voiceActivityFlag"`
	TotalSamplesDuration      float64        `json:"totalSamplesDuration"`
	EchoReturnLoss            float64        `json:"echoReturnLoss"`
	EchoReturnLossEnhancement float64        `json:"echoReturnLossEnhancement"`
	TotalSamplesSent          uint64         `json:"totalSamplesSent"`
}

func (s AudioSenderStats) statsMarker() {}

type SenderAudioTrackAttachmentStats AudioSenderStats

func (s SenderAudioTrackAttachmentStats) statsMarker() {}

type VideoSenderStats struct {
	Timestamp      StatsTimestamp `json:"timestamp"`
	Type           StatsType      `json:"type"`
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	FramesCaptured uint32         `json:"framesCaptured"`
	FramesSent     uint32         `json:"framesSent"`
	HugeFramesSent uint32         `json:"hugeFramesSent"`
	KeyFramesSent  uint32         `json:"keyFramesSent"`
}

func (s VideoSenderStats) statsMarker() {}

type SenderVideoTrackAttachmentStats VideoSenderStats

func (s SenderVideoTrackAttachmentStats) statsMarker() {}

type AudioReceiverStats struct {
	Timestamp                 StatsTimestamp `json:"timestamp"`
	Type                      StatsType      `json:"type"`
	ID                        string         `json:"id"`
	Kind                      string         `json:"kind"`
	AudioLevel                float64        `json:"audioLevel"`
	TotalAudioEnergy          float64        `json:"totalAudioEnergy"`
	VoiceActivityFlag         bool           `json:"voiceActivityFlag"`
	TotalSamplesDuration      float64        `json:"totalSamplesDuration"`
	EstimatedPlayoutTimestamp StatsTimestamp `json:"estimatedPlayoutTimestamp"`
	JitterBufferDelay         float64        `json:"jitterBufferDelay"`
	JitterBufferEmittedCount  uint64         `json:"jitterBufferEmittedCount"`
	TotalSamplesReceived      uint64         `json:"totalSamplesReceived"`
	ConcealedSamples          uint64         `json:"concealedSamples"`
	ConcealmentEvents         uint64         `json:"concealmentEvents"`
}

func (s AudioReceiverStats) statsMarker() {}

type VideoReceiverStats struct {
	Timestamp                 StatsTimestamp `json:"timestamp"`
	Type                      StatsType      `json:"type"`
	ID                        string         `json:"id"`
	Kind                      string         `json:"kind"`
	FrameWidth                uint32         `json:"frameWidth"`
	FrameHeight               uint32         `json:"frameHeight"`
	FramesPerSecond           float64        `json:"framesPerSecond"`
	EstimatedPlayoutTimestamp StatsTimestamp `json:"estimatedPlayoutTimestamp"`
	JitterBufferDelay         float64        `json:"jitterBufferDelay"`
	JitterBufferEmittedCount  uint64         `json:"jitterBufferEmittedCount"`
	FramesReceived            uint32         `json:"framesReceived"`
	KeyFramesReceived         uint32         `json:"keyFramesReceived"`
	FramesDecoded             uint32         `json:"framesDecoded"`
	FramesDropped             uint32         `json:"framesDropped"`
	PartialFramesLost         uint32         `json:"partialFramesLost"`
	FullFramesLost            uint32         `json:"fullFramesLost"`
}

func (s VideoReceiverStats) statsMarker() {}

type TransportStats struct {
	Timestamp               StatsTimestamp     `json:"timestamp"`
	Type                    StatsType          `json:"type"`
	ID                      string             `json:"id"`
	PacketsSent             uint32             `json:"packetsSent"`
	PacketsReceived         uint32             `json:"packetsReceived"`
	BytesSent               uint64             `json:"bytesSent"`
	BytesReceived           uint64             `json:"bytesReceived"`
	RTCPTransportStatsID    string             `json:"rtcpTransportStatsId"`
	ICERole                 ICERole            `json:"iceRole"`
	DTLSState               DTLSTransportState `json:"dtlsState"`
	ICEState                ICETransportState  `json:"iceState"`
	SelectedCandidatePairID string             `json:"selectedCandidatePairId"`
	LocalCertificateID      string             `json:"localCertificateId"`
	RemoteCertificateID     string             `json:"remoteCertificateId"`
	DTLSCipher              string             `json:"dtlsCipher"`
	SRTPCipher              string             `json:"srtpCipher"`
}

func (s TransportStats) statsMarker() {}

type StatsICECandidatePairState string

func toStatsICECandidatePairState(state ice.CandidatePairState) (StatsICECandidatePairState, error) {
	switch state {
	case ice.CandidatePairStateWaiting:
		return StatsICECandidatePairStateWaiting, nil
	case ice.CandidatePairStateInProgress:
		return StatsICECandidatePairStateInProgress, nil
	case ice.CandidatePairStateFailed:
		return StatsICECandidatePairStateFailed, nil
	case ice.CandidatePairStateSucceeded:
		return StatsICECandidatePairStateSucceeded, nil
	default:

		err := fmt.Errorf("%w: %s", errStatsICECandidateStateInvalid, state.String())

		return StatsICECandidatePairState("Unknown"), err
	}
}

func toICECandidatePairStats(candidatePairStats ice.CandidatePairStats) (ICECandidatePairStats, error) {
	state, err := toStatsICECandidatePairState(candidatePairStats.State)
	if err != nil {
		return ICECandidatePairStats{}, err
	}

	return ICECandidatePairStats{
		Timestamp: statsTimestampFrom(candidatePairStats.Timestamp),
		Type:      StatsTypeCandidatePair,
		ID:        newICECandidatePairStatsID(candidatePairStats.LocalCandidateID, candidatePairStats.RemoteCandidateID),

		LocalCandidateID:              candidatePairStats.LocalCandidateID,
		RemoteCandidateID:             candidatePairStats.RemoteCandidateID,
		State:                         state,
		Nominated:                     candidatePairStats.Nominated,
		PacketsSent:                   candidatePairStats.PacketsSent,
		PacketsReceived:               candidatePairStats.PacketsReceived,
		BytesSent:                     candidatePairStats.BytesSent,
		BytesReceived:                 candidatePairStats.BytesReceived,
		LastPacketSentTimestamp:       statsTimestampFrom(candidatePairStats.LastPacketSentTimestamp),
		LastPacketReceivedTimestamp:   statsTimestampFrom(candidatePairStats.LastPacketReceivedTimestamp),
		FirstRequestTimestamp:         statsTimestampFrom(candidatePairStats.FirstRequestTimestamp),
		LastRequestTimestamp:          statsTimestampFrom(candidatePairStats.LastRequestTimestamp),
		FirstResponseTimestamp:        statsTimestampFrom(candidatePairStats.FirstResponseTimestamp),
		LastResponseTimestamp:         statsTimestampFrom(candidatePairStats.LastResponseTimestamp),
		FirstRequestReceivedTimestamp: statsTimestampFrom(candidatePairStats.FirstRequestReceivedTimestamp),
		LastRequestReceivedTimestamp:  statsTimestampFrom(candidatePairStats.LastRequestReceivedTimestamp),
		TotalRoundTripTime:            candidatePairStats.TotalRoundTripTime,
		CurrentRoundTripTime:          candidatePairStats.CurrentRoundTripTime,
		AvailableOutgoingBitrate:      candidatePairStats.AvailableOutgoingBitrate,
		AvailableIncomingBitrate:      candidatePairStats.AvailableIncomingBitrate,
		CircuitBreakerTriggerCount:    candidatePairStats.CircuitBreakerTriggerCount,
		RequestsReceived:              candidatePairStats.RequestsReceived,
		RequestsSent:                  candidatePairStats.RequestsSent,
		ResponsesReceived:             candidatePairStats.ResponsesReceived,
		ResponsesSent:                 candidatePairStats.ResponsesSent,
		RetransmissionsReceived:       candidatePairStats.RetransmissionsReceived,
		RetransmissionsSent:           candidatePairStats.RetransmissionsSent,
		ConsentRequestsSent:           candidatePairStats.ConsentRequestsSent,
		ConsentExpiredTimestamp:       statsTimestampFrom(candidatePairStats.ConsentExpiredTimestamp),
	}, nil
}

const (
	StatsICECandidatePairStateFrozen StatsICECandidatePairState = "frozen"

	StatsICECandidatePairStateWaiting StatsICECandidatePairState = "waiting"

	StatsICECandidatePairStateInProgress StatsICECandidatePairState = "in-progress"

	StatsICECandidatePairStateFailed StatsICECandidatePairState = "failed"

	StatsICECandidatePairStateSucceeded StatsICECandidatePairState = "succeeded"
)

type ICECandidatePairStats struct {
	Timestamp                     StatsTimestamp             `json:"timestamp"`
	Type                          StatsType                  `json:"type"`
	ID                            string                     `json:"id"`
	TransportID                   string                     `json:"transportId"`
	LocalCandidateID              string                     `json:"localCandidateId"`
	RemoteCandidateID             string                     `json:"remoteCandidateId"`
	State                         StatsICECandidatePairState `json:"state"`
	Nominated                     bool                       `json:"nominated"`
	PacketsSent                   uint32                     `json:"packetsSent"`
	PacketsReceived               uint32                     `json:"packetsReceived"`
	BytesSent                     uint64                     `json:"bytesSent"`
	BytesReceived                 uint64                     `json:"bytesReceived"`
	LastPacketSentTimestamp       StatsTimestamp             `json:"lastPacketSentTimestamp"`
	LastPacketReceivedTimestamp   StatsTimestamp             `json:"lastPacketReceivedTimestamp"`
	FirstRequestTimestamp         StatsTimestamp             `json:"firstRequestTimestamp"`
	LastRequestTimestamp          StatsTimestamp             `json:"lastRequestTimestamp"`
	FirstResponseTimestamp        StatsTimestamp             `json:"firstResponseTimestamp"`
	LastResponseTimestamp         StatsTimestamp             `json:"lastResponseTimestamp"`
	FirstRequestReceivedTimestamp StatsTimestamp             `json:"firstRequestReceivedTimestamp"`
	LastRequestReceivedTimestamp  StatsTimestamp             `json:"lastRequestReceivedTimestamp"`
	TotalRoundTripTime            float64                    `json:"totalRoundTripTime"`
	CurrentRoundTripTime          float64                    `json:"currentRoundTripTime"`
	AvailableOutgoingBitrate      float64                    `json:"availableOutgoingBitrate"`
	AvailableIncomingBitrate      float64                    `json:"availableIncomingBitrate"`
	CircuitBreakerTriggerCount    uint32                     `json:"circuitBreakerTriggerCount"`
	RequestsReceived              uint64                     `json:"requestsReceived"`
	RequestsSent                  uint64                     `json:"requestsSent"`
	ResponsesReceived             uint64                     `json:"responsesReceived"`
	ResponsesSent                 uint64                     `json:"responsesSent"`
	RetransmissionsReceived       uint64                     `json:"retransmissionsReceived"`
	RetransmissionsSent           uint64                     `json:"retransmissionsSent"`
	ConsentRequestsSent           uint64                     `json:"consentRequestsSent"`
	ConsentExpiredTimestamp       StatsTimestamp             `json:"consentExpiredTimestamp"`
	PacketsDiscardedOnSend        uint32                     `json:"packetsDiscardedOnSend"`
	BytesDiscardedOnSend          uint32                     `json:"bytesDiscardedOnSend"`
}

func (s ICECandidatePairStats) statsMarker() {}

type ICECandidateStats struct {
	Timestamp     StatsTimestamp   `json:"timestamp"`
	Type          StatsType        `json:"type"`
	ID            string           `json:"id"`
	TransportID   string           `json:"transportId"`
	NetworkType   string           `json:"networkType,omitempty"`
	IP            string           `json:"ip"`
	Port          int32            `json:"port"`
	Protocol      string           `json:"protocol"`
	CandidateType ICECandidateType `json:"candidateType"`
	Priority      int32            `json:"priority"`
	URL           string           `json:"url"`
	RelayProtocol string           `json:"relayProtocol"`
	Deleted       bool             `json:"deleted"`
}

func (s ICECandidateStats) statsMarker() {}

type CertificateStats struct {
	Timestamp            StatsTimestamp `json:"timestamp"`
	Type                 StatsType      `json:"type"`
	ID                   string         `json:"id"`
	Fingerprint          string         `json:"fingerprint"`
	FingerprintAlgorithm string         `json:"fingerprintAlgorithm"`
	Base64Certificate    string         `json:"base64Certificate"`
	IssuerCertificateID  string         `json:"issuerCertificateId"`
}

func (s CertificateStats) statsMarker() {}

type SCTPTransportStats struct {
	Timestamp             StatsTimestamp         `json:"timestamp"`
	Type                  StatsType              `json:"type"`
	ID                    string                 `json:"id"`
	TransportID           string                 `json:"transportId"`
	SmoothedRoundTripTime float64                `json:"smoothedRoundTripTime"`
	CongestionWindow      uint32                 `json:"congestionWindow"`
	ReceiverWindow        uint32                 `json:"receiverWindow"`
	MTU                   uint32                 `json:"mtu"`
	UNACKData             uint32                 `json:"unackData"`
	Metadata              *SCTPTransportMetadata `json:"metadata,omitempty"`
	BytesSent             uint64                 `json:"bytesSent"`
	BytesReceived         uint64                 `json:"bytesReceived"`
}

func (s SCTPTransportStats) statsMarker() {}

type TrackLocalWriter interface {
	WriteRTP(header *rtp.Header, payload []byte) (int, error)
	Write(b []byte) (int, error)
}

type TrackLocalContext interface {
	CodecParameters() []RTPCodecParameters
	HeaderExtensions() []RTPHeaderExtensionParameter
	SSRC() SSRC
	SSRCRetransmission() SSRC
	SSRCForwardErrorCorrection() SSRC
	WriteStream() TrackLocalWriter
	ID() string
	RTCPReader() interceptor.RTCPReader
}

type baseTrackLocalContext struct {
	id                     string
	params                 RTPParameters
	ssrc, ssrcRTX, ssrcFEC SSRC
	writeStream            TrackLocalWriter
	rtcpInterceptor        interceptor.RTCPReader
}

func (t *baseTrackLocalContext) CodecParameters() []RTPCodecParameters {
	return t.params.Codecs
}

func (t *baseTrackLocalContext) HeaderExtensions() []RTPHeaderExtensionParameter {
	return t.params.HeaderExtensions
}

func (t *baseTrackLocalContext) SSRC() SSRC {
	return t.ssrc
}

func (t *baseTrackLocalContext) SSRCRetransmission() SSRC {
	return t.ssrcRTX
}

func (t *baseTrackLocalContext) SSRCForwardErrorCorrection() SSRC {
	return t.ssrcFEC
}

func (t *baseTrackLocalContext) WriteStream() TrackLocalWriter {
	return t.writeStream
}

func (t *baseTrackLocalContext) ID() string {
	return t.id
}

func (t *baseTrackLocalContext) RTCPReader() interceptor.RTCPReader {
	return t.rtcpInterceptor
}

type TrackLocal interface {
	Bind(TrackLocalContext) (RTPCodecParameters, error)
	Unbind(TrackLocalContext) error
	ID() string
	RID() string
	StreamID() string
	Kind() RTPCodecType
}

type SSRC uint32

type PayloadType uint8

// ---- merged from webrtc/internal/mux (package mux) ----

type Endpoint struct {
	mux     *Mux
	buffer  *transport.Buffer
	onClose func()
}

func (e *Endpoint) Close() (err error) {
	if e.onClose != nil {
		e.onClose()
	}

	if err = e.close(); err != nil {
		return err
	}

	e.mux.RemoveEndpoint(e)

	return nil
}

func (e *Endpoint) close() error {
	return e.buffer.Close()
}

func (e *Endpoint) Read(p []byte) (int, error) {
	return e.buffer.Read(p)
}

func (e *Endpoint) ReadFrom(p []byte) (int, net.Addr, error) {
	i, err := e.Read(p)

	return i, nil, err
}

func (e *Endpoint) Write(p []byte) (int, error) {
	n, err := e.mux.nextConn.Write(p)
	if errors.Is(err, ice.ErrNoCandidatePairs) {
		return 0, nil
	} else if errors.Is(err, ice.ErrClosed) {
		return 0, io.ErrClosedPipe
	}

	return n, err
}

func (e *Endpoint) WriteTo(p []byte, _ net.Addr) (int, error) {
	return e.Write(p)
}

func (e *Endpoint) LocalAddr() net.Addr {
	return e.mux.nextConn.LocalAddr()
}

func (e *Endpoint) RemoteAddr() net.Addr {
	return e.mux.nextConn.RemoteAddr()
}

func (e *Endpoint) SetDeadline(t time.Time) error {
	return e.mux.nextConn.SetDeadline(t)
}

func (e *Endpoint) SetReadDeadline(t time.Time) error {
	return e.buffer.SetReadDeadline(t)
}

func (e *Endpoint) SetWriteDeadline(t time.Time) error {
	return e.mux.nextConn.SetWriteDeadline(t)
}

func (e *Endpoint) SetOnClose(onClose func()) {
	e.onClose = onClose
}

const (
	maxBufferSize = 1000 * 1000

	maxPendingPackets = 15
)

type Config struct {
	Conn          net.Conn
	BufferSize    int
	LoggerFactory logging.LoggerFactory
}

type Mux struct {
	nextConn       net.Conn
	bufferSize     int
	lock           sync.Mutex
	endpoints      map[*Endpoint]MatchFunc
	isClosed       bool
	pendingPackets [][]byte
	closedCh       chan struct{}
	log            logging.LeveledLogger
}

func NewMux(config Config) *Mux {
	mux := &Mux{
		nextConn:   config.Conn,
		endpoints:  make(map[*Endpoint]MatchFunc),
		bufferSize: config.BufferSize,
		closedCh:   make(chan struct{}),
		log:        config.LoggerFactory.NewLogger("mux"),
	}

	go mux.readLoop()

	return mux
}

func (m *Mux) NewEndpoint(matchFunc MatchFunc) *Endpoint {
	endpoint := &Endpoint{
		mux:    m,
		buffer: transport.NewBuffer(),
	}

	endpoint.buffer.SetLimitSize(maxBufferSize)

	m.lock.Lock()
	m.endpoints[endpoint] = matchFunc
	m.lock.Unlock()

	go m.handlePendingPackets(endpoint, matchFunc)

	return endpoint
}

func (m *Mux) RemoveEndpoint(e *Endpoint) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.endpoints, e)
}

func (m *Mux) Close() error {
	m.lock.Lock()
	for e := range m.endpoints {
		if err := e.close(); err != nil {
			m.lock.Unlock()

			return err
		}

		delete(m.endpoints, e)
	}
	m.isClosed = true
	m.lock.Unlock()

	err := m.nextConn.Close()
	if err != nil {
		return err
	}

	<-m.closedCh

	return nil
}

func (m *Mux) readLoop() {
	defer func() {
		close(m.closedCh)
	}()

	buf := make([]byte, m.bufferSize)
	for {
		n, err := m.nextConn.Read(buf)
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, ice.ErrClosed):
			return
		case errors.Is(err, io.ErrShortBuffer), errors.Is(err, transport.ErrTimeout):
			m.log.Errorf("mux: failed to read from packetio.Buffer %s", err.Error())

			continue
		case err != nil:
			m.log.Errorf("mux: ending readLoop packetio.Buffer error %s", err.Error())

			return
		}

		if err = m.dispatch(buf[:n]); err != nil {
			if errors.Is(err, io.ErrClosedPipe) {

				return
			}
			m.log.Errorf("mux: ending readLoop dispatch error %s", err.Error())

			return
		}
	}
}

func (m *Mux) dispatch(buf []byte) error {
	if len(buf) == 0 {
		m.log.Warnf("Warning: mux: unable to dispatch zero length packet")

		return nil
	}

	var endpoint *Endpoint

	m.lock.Lock()
	for e, f := range m.endpoints {
		if f(buf) {
			endpoint = e

			break
		}
	}
	if endpoint == nil {
		defer m.lock.Unlock()

		if !m.isClosed {
			if len(m.pendingPackets) >= maxPendingPackets {
				m.log.Warnf(
					"Warning: mux: no endpoint for packet starting with %d, not adding to queue size(%d)",
					buf[0],
					len(m.pendingPackets),
				)
			} else {
				m.log.Warnf(
					"Warning: mux: no endpoint for packet starting with %d, adding to queue size(%d)",
					buf[0],
					len(m.pendingPackets),
				)
				m.pendingPackets = append(m.pendingPackets, append([]byte{}, buf...))
			}
		}

		return nil
	}

	m.lock.Unlock()
	_, err := endpoint.buffer.Write(buf)

	if errors.Is(err, transport.ErrFull) {
		m.log.Infof("mux: endpoint buffer is full, dropping packet")

		return nil
	}

	return err
}

func (m *Mux) handlePendingPackets(endpoint *Endpoint, matchFunc MatchFunc) {
	m.lock.Lock()
	defer m.lock.Unlock()

	pendingPackets := make([][]byte, 0, len(m.pendingPackets))
	for _, buf := range m.pendingPackets {
		if matchFunc(buf) {
			if _, err := endpoint.buffer.Write(buf); err != nil {
				m.log.Warnf("Warning: mux: error writing packet to endpoint from pending queue: %s", err)
			}
		} else {
			pendingPackets = append(pendingPackets, buf)
		}
	}
	m.pendingPackets = pendingPackets
}

type MatchFunc func([]byte) bool

func MatchRange(lower, upper byte, buf []byte) bool {
	if len(buf) < 1 {
		return false
	}
	b := buf[0]

	return b >= lower && b <= upper
}

func MatchDTLS(b []byte) bool {
	return MatchRange(20, 63, b)
}

func MatchSRTPOrSRTCP(b []byte) bool {
	return MatchRange(128, 191, b)
}

func isRTCP(buf []byte) bool {

	if len(buf) < 4 {
		return false
	}

	return buf[1] >= 192 && buf[1] <= 223
}

func MatchSRTP(buf []byte) bool {
	return MatchSRTPOrSRTCP(buf) && !isRTCP(buf)
}

func MatchSRTCP(buf []byte) bool {
	return MatchSRTPOrSRTCP(buf) && isRTCP(buf)
}

// ---- merged from webrtc/pkg/rtcerr (package rtcerr) ----

type UnknownError struct {
	Err error
}

func (e *UnknownError) Error() string {
	return fmt.Sprintf("UnknownError: %v", e.Err)
}

func (e *UnknownError) Unwrap() error {
	return e.Err
}

type InvalidStateError struct {
	Err error
}

func (e *InvalidStateError) Error() string {
	return fmt.Sprintf("InvalidStateError: %v", e.Err)
}

func (e *InvalidStateError) Unwrap() error {
	return e.Err
}

type InvalidAccessError struct {
	Err error
}

func (e *InvalidAccessError) Error() string {
	return fmt.Sprintf("InvalidAccessError: %v", e.Err)
}

func (e *InvalidAccessError) Unwrap() error {
	return e.Err
}

type NotSupportedError struct {
	Err error
}

func (e *NotSupportedError) Error() string {
	return fmt.Sprintf("NotSupportedError: %v", e.Err)
}

func (e *NotSupportedError) Unwrap() error {
	return e.Err
}

type InvalidModificationError struct {
	Err error
}

func (e *InvalidModificationError) Error() string {
	return fmt.Sprintf("InvalidModificationError: %v", e.Err)
}

func (e *InvalidModificationError) Unwrap() error {
	return e.Err
}

type TypeError struct {
	Err error
}

func (e *TypeError) Error() string {
	return fmt.Sprintf("TypeError: %v", e.Err)
}

func (e *TypeError) Unwrap() error {
	return e.Err
}

type OperationError struct {
	Err error
}

func (e *OperationError) Error() string {
	return fmt.Sprintf("OperationError: %v", e.Err)
}

func (e *OperationError) Unwrap() error {
	return e.Err
}

// ---- merged from webrtc/pkg/media (package media) ----

type Sample struct {
	Data               []byte
	Timestamp          time.Time
	Duration           time.Duration
	PacketTimestamp    uint32
	PrevDroppedPackets uint16
	Metadata           any
	RTPHeaders         []*rtp.Header
}
