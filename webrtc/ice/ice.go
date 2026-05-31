// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package ice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"github.com/amarnathcjd/gortc/webrtc"
	stunx "github.com/amarnathcjd/gortc/webrtc/ice/internal/stun"
	"github.com/amarnathcjd/gortc/webrtc/ice/internal/taskloop"
	"github.com/amarnathcjd/gortc/webrtc/logging"
	"github.com/amarnathcjd/gortc/webrtc/stun"
	"github.com/amarnathcjd/gortc/webrtc/transport"
	"math"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
)

func addrWithOptionalZone(addr netip.Addr, zone string) netip.Addr {
	if zone == "" {
		return addr
	}
	if addr.Is6() && (addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()) {
		return addr.WithZone(zone)
	}

	return addr
}

func parseAddrFromIface(in net.Addr, ifcName string) (netip.Addr, int, NetworkType, error) {
	addr, port, nt, err := parseAddr(in)
	if err != nil {
		return netip.Addr{}, 0, 0, err
	}
	if _, ok := in.(*net.IPNet); ok {

		addr = addrWithOptionalZone(addr, ifcName)
	}

	return addr, port, nt, nil
}

func parseAddr(in net.Addr) (netip.Addr, int, NetworkType, error) {
	host := func(ip net.IP, zone string) (netip.Addr, int, NetworkType, error) {
		a, err := ipAddrToNetIP(ip, zone)
		if err != nil {
			return netip.Addr{}, 0, 0, err
		}

		return a, 0, 0, nil
	}

	sock := func(ip net.IP, zone string, port int, v4, v6 NetworkType) (netip.Addr, int, NetworkType, error) {
		a, err := ipAddrToNetIP(ip, zone)
		if err != nil {
			return netip.Addr{}, 0, 0, err
		}

		nt := v6
		if a.Is4() {
			nt = v4
		}

		return a, port, nt, nil
	}

	switch a := in.(type) {
	case *net.IPNet:
		return host(a.IP, "")
	case *net.IPAddr:
		return host(a.IP, a.Zone)
	case *net.UDPAddr:
		return sock(a.IP, a.Zone, a.Port, NetworkTypeUDP4, NetworkTypeUDP6)
	case *net.TCPAddr:
		return sock(a.IP, a.Zone, a.Port, NetworkTypeTCP4, NetworkTypeTCP6)
	default:
		return netip.Addr{}, 0, 0, addrParseError{in}
	}
}

type addrParseError struct {
	addr net.Addr
}

func (e addrParseError) Error() string {
	return fmt.Sprintf("do not know how to parse address type %T", e.addr)
}

type ipConvertError struct {
	ip []byte
}

func (e ipConvertError) Error() string {
	return fmt.Sprintf("failed to convert IP '%s' to netip.Addr", e.ip)
}

func ipAddrToNetIP(ip []byte, zone string) (netip.Addr, error) {
	netIPAddr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, ipConvertError{ip}
	}

	netIPAddr = netIPAddr.Unmap()
	netIPAddr = addrWithOptionalZone(netIPAddr, zone)

	return netIPAddr, nil
}

func createAddr(network NetworkType, ip netip.Addr, port int) net.Addr {
	switch {
	case network.IsTCP():
		return &net.TCPAddr{IP: ip.AsSlice(), Port: port, Zone: ip.Zone()}
	default:
		return &net.UDPAddr{IP: ip.AsSlice(), Port: port, Zone: ip.Zone()}
	}
}

func addrEqual(a, b net.Addr) bool {
	aIP, aPort, aType, aErr := parseAddr(a)
	if aErr != nil {
		return false
	}

	bIP, bPort, bType, bErr := parseAddr(b)
	if bErr != nil {
		return false
	}

	return aType == bType && aIP.Compare(bIP) == 0 && aPort == bPort
}

type AddrPort [18]byte

func toAddrPort(addr net.Addr) AddrPort {
	var ap AddrPort
	switch addr := addr.(type) {
	case *net.UDPAddr:
		copy(ap[:16], addr.IP.To16())
		ap[16] = uint8(addr.Port >> 8)
		ap[17] = uint8(addr.Port)
	case *net.TCPAddr:
		copy(ap[:16], addr.IP.To16())
		ap[16] = uint8(addr.Port >> 8)
		ap[17] = uint8(addr.Port)
	}

	return ap
}

type bindingRequest struct {
	timestamp       time.Time
	transactionID   [stun.TransactionIDSize]byte
	destination     net.Addr
	isUseCandidate  bool
	nominationValue *uint32
}

type Agent struct {
	loop                              *taskloop.Loop
	constructed                       bool
	onConnectionStateChangeHdlr       atomic.Value
	onSelectedCandidatePairChangeHdlr atomic.Value
	onCandidateHdlr                   atomic.Value
	onConnected                       chan struct{}
	onConnectedOnce                   sync.Once
	forceCandidateContact             chan bool
	tieBreaker                        uint64
	lite                              bool
	connectionState                   ConnectionState
	gatheringState                    GatheringState
	mDNSMode                          MulticastDNSMode
	mDNSName                          string
	mDNSConn                          *mdnsConn
	muHaveStarted                     sync.Mutex
	startedCh                         <-chan struct{}
	startedFn                         func()
	isControlling                     atomic.Bool
	maxBindingRequests                uint16
	hostAcceptanceMinWait             time.Duration
	srflxAcceptanceMinWait            time.Duration
	prflxAcceptanceMinWait            time.Duration
	relayAcceptanceMinWait            time.Duration
	stunGatherTimeout                 time.Duration
	tcpPriorityOffset                 uint16
	disableActiveTCP                  bool
	portMin                           uint16
	portMax                           uint16
	candidateTypes                    []CandidateType
	disconnectedTimeout               time.Duration
	failedTimeout                     time.Duration
	keepaliveInterval                 time.Duration
	checkInterval                     time.Duration
	localUfrag                        string
	localPwd                          string
	localCandidates                   map[NetworkType][]Candidate
	remoteUfrag                       string
	remotePwd                         string
	remoteCandidates                  map[NetworkType][]Candidate
	checklist                         []*CandidatePair
	nextPairID                        uint64
	pairsByID                         map[uint64]*CandidatePair
	selectorLock                      sync.RWMutex
	selector                          pairCandidateSelector
	selectedPair                      atomic.Value
	urls                              []*stun.URI
	networkTypes                      []NetworkType
	turnTransportProtocols            []NetworkType
	addressRewriteRules               []AddressRewriteRule
	buf                               *transport.Buffer
	pendingBindingRequests            []bindingRequest
	addressRewriteMapper              *addressRewriteMapper
	userBindingRequestHandler         func(m *stun.Message, local, remote Candidate, pair *CandidatePair) bool
	gatherCandidateCancel             func()
	gatherCandidateDone               chan struct{}
	connectionStateNotifier           *handlerNotifier
	candidateNotifier                 *handlerNotifier
	selectedCandidatePairNotifier     *handlerNotifier
	loggerFactory                     logging.LoggerFactory
	log                               logging.LeveledLogger
	net                               transport.Net
	tcpMux                            TCPMux
	udpMux                            UDPMux
	udpMuxSrflx                       UniversalUDPMux
	interfaceFilter                   func(string) (keep bool)
	ipFilter                          func(net.IP) (keep bool)
	remoteIPFilter                    func(net.IP) (keep bool)
	includeLoopback                   bool
	insecureSkipVerify                bool
	proxyDialer                       proxy.Dialer
	enableUseCandidateCheckPriority   bool
	enableRenomination                bool
	nominationValueGenerator          func() uint32
	nominationAttribute               stun.AttrType
	continualGatheringPolicy          ContinualGatheringPolicy
	networkMonitorInterval            time.Duration
	lastKnownInterfaces               map[string]netip.Addr
	automaticRenomination             bool
	renominationInterval              time.Duration
	lastRenominationTime              time.Time
	turnClientFactory                 func(*TURNClientConfig) (turnClient, error)
}

func NewAgentWithOptions(opts ...AgentOption) (*Agent, error) {
	return newAgentFromConfig(&AgentConfig{}, opts...)
}

func newAgentFromConfig(config *AgentConfig, opts ...AgentOption) (*Agent, error) {
	if config == nil {
		config = &AgentConfig{}
	}

	agent, err := createAgentBase(config)
	if err != nil {
		return nil, err
	}

	agent.localUfrag = config.LocalUfrag
	agent.localPwd = config.LocalPwd
	if config.NAT1To1IPs != nil {
		if err := validateLegacyNAT1To1IPs(config.NAT1To1IPs); err != nil {
			return nil, err
		}

		typ := CandidateTypeHost
		if config.NAT1To1IPCandidateType != CandidateTypeUnspecified {
			typ = config.NAT1To1IPCandidateType
		}

		rules, err := legacyNAT1To1Rules(config.NAT1To1IPs, typ)
		if err != nil {
			return nil, err
		}
		agent.addressRewriteRules = rules
	}

	return newAgentWithConfig(agent, opts...)
}

func validateLegacyNAT1To1IPs(ips []string) error {
	var hasIPv4CatchAll, hasIPv6CatchAll bool

	for _, mapping := range ips {
		trimmed := strings.TrimSpace(mapping)
		var err error
		hasIPv4CatchAll, hasIPv6CatchAll, err = validateLegacyNAT1To1Entry(trimmed, hasIPv4CatchAll, hasIPv6CatchAll)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateLegacyNAT1To1Entry(mapping string, hasIPv4CatchAll, hasIPv6CatchAll bool) (bool, bool, error) {
	if mapping == "" {
		return hasIPv4CatchAll, hasIPv6CatchAll, nil
	}

	parts := strings.Split(mapping, "/")
	if len(parts) == 0 || len(parts) > 2 {
		return hasIPv4CatchAll, hasIPv6CatchAll, ErrInvalidNAT1To1IPMapping
	}

	_, isIPv4, err := validateIPString(parts[0])
	if err != nil {
		return hasIPv4CatchAll, hasIPv6CatchAll, err
	}

	if len(parts) == 2 {
		if _, _, err := validateIPString(strings.TrimSpace(parts[1])); err != nil {
			return hasIPv4CatchAll, hasIPv6CatchAll, err
		}

		return hasIPv4CatchAll, hasIPv6CatchAll, nil
	}

	if isIPv4 {
		if hasIPv4CatchAll {
			return hasIPv4CatchAll, hasIPv6CatchAll, ErrInvalidNAT1To1IPMapping
		}

		return true, hasIPv6CatchAll, nil
	}

	if hasIPv6CatchAll {
		return hasIPv4CatchAll, hasIPv6CatchAll, ErrInvalidNAT1To1IPMapping
	}

	return hasIPv4CatchAll, true, nil
}

func legacyNAT1To1Rules(ips []string, candidateType CandidateType) ([]AddressRewriteRule, error) {
	var rules []AddressRewriteRule

	for _, mapping := range ips {
		trimmed := strings.TrimSpace(mapping)
		if trimmed == "" {
			continue
		}

		parts := strings.Split(trimmed, "/")
		switch len(parts) {
		case 1:
			rules = append(rules, AddressRewriteRule{
				External:        []string{parts[0]},
				AsCandidateType: candidateType,
			})
		case 2:
			ext := strings.TrimSpace(parts[0])
			local := strings.TrimSpace(parts[1])
			if ext == "" || local == "" {
				return nil, ErrInvalidNAT1To1IPMapping
			}

			if _, _, err := validateIPString(ext); err != nil {
				return nil, err
			}
			if _, _, err := validateIPString(local); err != nil {
				return nil, err
			}

			rules = append(rules, AddressRewriteRule{
				External:        []string{ext},
				Local:           local,
				AsCandidateType: candidateType,
			})
		default:
			return nil, ErrInvalidNAT1To1IPMapping
		}
	}

	return rules, nil
}

func createAgentBase(config *AgentConfig) (*Agent, error) {
	if config.PortMax < config.PortMin {
		return nil, ErrPort
	}

	normalizedNetworkTypes, err := sanitizeTransportNetworkTypes(config.NetworkTypes)
	if err != nil {
		return nil, err
	}

	normalizedTURNTransportProtocols, err := sanitizeTransportNetworkTypes(config.turnTransportProtocols)
	if err != nil {
		return nil, err
	}

	mDNSName, mDNSMode, err := setupMDNSConfig(config)
	if err != nil {
		return nil, err
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}
	log := loggerFactory.NewLogger("ice")

	startedCtx, startedFn := context.WithCancel(context.Background())

	agent := &Agent{
		tieBreaker:                      globalMathRandomGenerator.Uint64(),
		lite:                            config.Lite,
		gatheringState:                  GatheringStateNew,
		connectionState:                 ConnectionStateNew,
		localCandidates:                 make(map[NetworkType][]Candidate),
		remoteCandidates:                make(map[NetworkType][]Candidate),
		pairsByID:                       make(map[uint64]*CandidatePair),
		urls:                            config.Urls,
		networkTypes:                    normalizedNetworkTypes,
		turnTransportProtocols:          normalizedTURNTransportProtocols,
		onConnected:                     make(chan struct{}),
		buf:                             transport.NewBuffer(),
		startedCh:                       startedCtx.Done(),
		startedFn:                       startedFn,
		portMin:                         config.PortMin,
		portMax:                         config.PortMax,
		loggerFactory:                   loggerFactory,
		log:                             log,
		net:                             config.Net,
		proxyDialer:                     config.ProxyDialer,
		tcpMux:                          config.TCPMux,
		udpMux:                          config.UDPMux,
		udpMuxSrflx:                     config.UDPMuxSrflx,
		mDNSMode:                        mDNSMode,
		mDNSName:                        mDNSName,
		gatherCandidateCancel:           func() {},
		forceCandidateContact:           make(chan bool, 1),
		interfaceFilter:                 config.InterfaceFilter,
		ipFilter:                        config.IPFilter,
		remoteIPFilter:                  config.RemoteIPFilter,
		insecureSkipVerify:              config.InsecureSkipVerify,
		includeLoopback:                 config.IncludeLoopback,
		disableActiveTCP:                config.DisableActiveTCP,
		userBindingRequestHandler:       config.BindingRequestHandler,
		enableUseCandidateCheckPriority: config.EnableUseCandidateCheckPriority,
		enableRenomination:              false,
		nominationValueGenerator:        nil,
		nominationAttribute:             DefaultNominationAttribute,
		continualGatheringPolicy:        GatherOnce,
		networkMonitorInterval:          2 * time.Second,
		lastKnownInterfaces:             make(map[string]netip.Addr),
		automaticRenomination:           false,
		renominationInterval:            3 * time.Second,
		turnClientFactory:               defaultTurnClient,
	}

	config.initWithDefaults(agent)

	return agent, nil
}

func applyAddressRewriteMapping(_ *Agent) error { return nil }

func setupMDNSConfig(config *AgentConfig) (string, MulticastDNSMode, error) {
	mDNSName := config.MulticastDNSHostName
	if mDNSName == "" {
		var err error
		if mDNSName, err = generateMulticastDNSName(); err != nil {
			return "", 0, err
		}
	}

	if !strings.HasSuffix(mDNSName, ".local") || len(strings.Split(mDNSName, ".")) != 2 {
		return "", 0, ErrInvalidMulticastDNSHostName
	}

	mDNSMode := config.MulticastDNSMode
	if mDNSMode == 0 {
		mDNSMode = MulticastDNSModeQueryOnly
	}

	return mDNSName, mDNSMode, nil
}

func newAgentWithConfig(agent *Agent, opts ...AgentOption) (*Agent, error) {
	var err error

	for _, opt := range opts {
		if err = opt(agent); err != nil {
			return nil, err
		}
	}

	agent.connectionStateNotifier = &handlerNotifier{
		connectionStateFunc: agent.onConnectionStateChange,
		done:                make(chan struct{}),
	}
	agent.candidateNotifier = &handlerNotifier{candidateFunc: agent.onCandidate, done: make(chan struct{})}
	agent.selectedCandidatePairNotifier = &handlerNotifier{
		candidatePairFunc: agent.onSelectedCandidatePairChange,
		done:              make(chan struct{}),
	}

	if agent.net == nil {
		agent.net, err = transport.NewNet()
		if err != nil {
			return nil, fmt.Errorf("failed to create network: %w", err)
		}
	}

	localIfcs, _, err := localInterfaces(
		agent.net,
		agent.interfaceFilter,
		agent.ipFilter,
		agent.networkTypes,
		agent.includeLoopback,
	)
	if err != nil {
		return nil, fmt.Errorf("error getting local interfaces: %w", err)
	}

	mDNSLocalAddress := mDNSLocalAddressFromTCPMux(agent.tcpMux, agent.networkTypes)

	if agent.mDNSConn, agent.mDNSMode, err = createMulticastDNS(
		agent.net,
		agent.networkTypes,
		localIfcs,
		agent.includeLoopback,
		mDNSLocalAddress,
		agent.mDNSMode,
		agent.mDNSName,
		agent.log,
		agent.loggerFactory,
	); err != nil {
		agent.log.Warnf("Failed to initialize mDNS %s: %v", agent.mDNSName, err)
	}

	agent.buf.SetLimitSize(maxBufferSize)

	if agent.lite && (len(agent.candidateTypes) != 1 || agent.candidateTypes[0] != CandidateTypeHost) {
		agent.closeMulticastConn()

		return nil, ErrLiteUsingNonHostCandidates
	}

	if len(agent.urls) > 0 &&
		!containsCandidateType(CandidateTypeServerReflexive, agent.candidateTypes) &&
		!containsCandidateType(CandidateTypeRelay, agent.candidateTypes) {
		agent.closeMulticastConn()

		return nil, ErrUselessUrlsProvided
	}

	if err = applyAddressRewriteMapping(agent); err != nil {
		agent.closeMulticastConn()

		return nil, err
	}

	agent.loop = taskloop.New(func() {
		agent.gatherCandidateCancel()
		if agent.gatherCandidateDone != nil {
			<-agent.gatherCandidateDone
		}

		agent.removeUfragFromMux()
		agent.deleteAllCandidates()
		agent.startedFn()

		if err := agent.buf.Close(); err != nil {
			agent.log.Warnf("Failed to close buffer: %v", err)
		}

		agent.closeMulticastConn()
		agent.updateConnectionState(ConnectionStateClosed)
	})

	if err := agent.Restart(agent.localUfrag, agent.localPwd); err != nil {
		agent.closeMulticastConn()
		_ = agent.Close()

		return nil, err
	}

	agent.constructed = true

	return agent, nil
}

func mDNSLocalAddressFromTCPMux(tcpMux TCPMux, networkTypes []NetworkType) net.IP {
	if tcpMux == nil || !allNetworkTypesTCP(networkTypes) {
		return nil
	}

	tcpAddr, ok := localTCPAddrFromMux(tcpMux)
	if !ok {
		return nil
	}

	localAddr, ok := mDNSLocalAddressFromIP(tcpAddr.IP)
	if !ok {
		return nil
	}

	return localAddr
}

func allNetworkTypesTCP(networkTypes []NetworkType) bool {
	if len(networkTypes) == 0 {
		return false
	}

	for _, networkType := range networkTypes {
		if !networkType.IsTCP() {
			return false
		}
	}

	return true
}

func localTCPAddrFromMux(tcpMux TCPMux) (*net.TCPAddr, bool) {
	addrProvider, ok := tcpMux.(interface{ LocalAddr() net.Addr })
	if !ok {
		return nil, false
	}

	tcpAddr, ok := addrProvider.LocalAddr().(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil || tcpAddr.IP.IsUnspecified() {
		return nil, false
	}

	return tcpAddr, true
}

func mDNSLocalAddressFromIP(ip net.IP) (net.IP, bool) {
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, false
	}

	parsed = parsed.Unmap()
	if parsed.Is6() && (parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast()) {

		return nil, false
	}

	return parsed.AsSlice(), true
}

func (a *Agent) startConnectivityChecks(isControlling bool, remoteUfrag, remotePwd string) error {
	a.muHaveStarted.Lock()
	defer a.muHaveStarted.Unlock()
	select {
	case <-a.startedCh:
		return ErrMultipleStart
	default:
	}
	if err := a.SetRemoteCredentials(remoteUfrag, remotePwd); err != nil {
		return err
	}

	a.log.Debugf("Started agent: isControlling? %t, remoteUfrag: %q, remotePwd: %q", isControlling, remoteUfrag, remotePwd)

	return a.loop.Run(a.loop, func(_ context.Context) {
		a.isControlling.Store(isControlling)
		a.remoteUfrag = remoteUfrag
		a.remotePwd = remotePwd
		a.setSelector()

		a.startedFn()

		a.updateConnectionState(ConnectionStateChecking)

		a.requestConnectivityCheck()
		go a.connectivityChecks()
	})
}

func (a *Agent) connectivityChecks() {
	lastConnectionState := ConnectionState(0)
	checkingDuration := time.Time{}

	contact := func() {
		if err := a.loop.Run(a.loop, func(_ context.Context) {
			defer func() {
				lastConnectionState = a.connectionState
			}()

			switch a.connectionState {
			case ConnectionStateFailed:

				return
			case ConnectionStateChecking:

				if lastConnectionState != a.connectionState {
					checkingDuration = time.Now()
				}

				if time.Since(checkingDuration) > a.disconnectedTimeout+a.failedTimeout {
					a.updateConnectionState(ConnectionStateFailed)

					return
				}
			default:
			}

			a.getSelector().ContactCandidates()
		}); err != nil {
			a.log.Warnf("Failed to start connectivity checks: %v", err)
		}
	}

	timer := time.NewTimer(math.MaxInt64)
	timer.Stop()

	for {
		interval := defaultKeepaliveInterval

		updateInterval := func(x time.Duration) {
			if x != 0 && (interval == 0 || interval > x) {
				interval = x
			}
		}

		switch lastConnectionState {
		case ConnectionStateNew, ConnectionStateChecking:
			updateInterval(a.checkInterval)
		case ConnectionStateConnected, ConnectionStateDisconnected:
			updateInterval(a.keepaliveInterval)
		default:
		}

		updateInterval(a.disconnectedTimeout)
		updateInterval(a.failedTimeout)

		timer.Reset(interval)

		select {
		case <-a.forceCandidateContact:
			if !timer.Stop() {
				<-timer.C
			}
			contact()
		case <-timer.C:
			contact()
		case <-a.loop.Done():
			timer.Stop()

			return
		}
	}
}

func (a *Agent) updateConnectionState(newState ConnectionState) {
	if a.connectionState != newState {

		if newState == ConnectionStateFailed {
			a.removeUfragFromMux()
			a.checklist = make([]*CandidatePair, 0)
			a.pairsByID = make(map[uint64]*CandidatePair)
			a.pendingBindingRequests = make([]bindingRequest, 0)
			a.setSelectedPair(nil)
			a.deleteAllCandidates()
		}

		a.log.Infof("Setting new connection state: %s", newState)
		a.connectionState = newState
		a.connectionStateNotifier.EnqueueConnectionState(newState)
	}
}

func (a *Agent) setSelectedPair(pair *CandidatePair) {
	if pair == nil {
		var nilPair *CandidatePair
		a.selectedPair.Store(nilPair)
		a.log.Tracef("Unset selected candidate pair")

		return
	}

	pair.nominated = true
	a.selectedPair.Store(pair)
	a.log.Tracef("Set selected candidate pair: %s", pair)

	a.onConnectedOnce.Do(func() { close(a.onConnected) })

	a.updateConnectionState(ConnectionStateConnected)

	a.selectedCandidatePairNotifier.EnqueueSelectedCandidatePair(pair)
}

func (a *Agent) pingAllCandidates() {
	a.log.Trace("Pinging all candidates")

	if len(a.checklist) == 0 {
		a.log.Warn("Failed to ping without candidate pairs. Connection is not possible yet.")
	}

	for _, p := range a.checklist {
		if p.state == CandidatePairStateWaiting {
			p.state = CandidatePairStateInProgress
		} else if p.state != CandidatePairStateInProgress {
			continue
		}

		if p.bindingRequestCount > a.maxBindingRequests {
			a.log.Tracef("Maximum requests reached for pair %s, marking it as failed", p)
			p.state = CandidatePairStateFailed
		} else {
			a.getSelector().PingCandidate(p.Local, p.Remote)
			p.bindingRequestCount++
		}
	}
}

func (a *Agent) keepAliveCandidatesForRenomination() {
	a.log.Trace("Keep alive candidates for automatic renomination")

	if len(a.checklist) == 0 {
		return
	}

	for _, pair := range a.checklist {
		switch pair.state {
		case CandidatePairStateFailed:

			continue
		case CandidatePairStateWaiting:

			pair.state = CandidatePairStateInProgress
		case CandidatePairStateInProgress, CandidatePairStateSucceeded:

		}

		a.getSelector().PingCandidate(pair.Local, pair.Remote)
	}
}

func (a *Agent) getBestAvailableCandidatePair() *CandidatePair {
	var best *CandidatePair
	for _, p := range a.checklist {
		if p.state == CandidatePairStateFailed {
			continue
		}

		if best == nil {
			best = p
		} else if best.priority() < p.priority() {
			best = p
		}
	}

	return best
}

func (a *Agent) getBestValidCandidatePair() *CandidatePair {
	var best *CandidatePair
	for _, p := range a.checklist {
		if p.state != CandidatePairStateSucceeded {
			continue
		}

		if best == nil {
			best = p
		} else if best.priority() < p.priority() {
			best = p
		}
	}

	return best
}

func (a *Agent) addPair(local, remote Candidate) *CandidatePair {
	a.nextPairID++
	p := newCandidatePair(local, remote, a.isControlling.Load())
	p.id = a.nextPairID
	a.checklist = append(a.checklist, p)
	a.pairsByID[p.id] = p

	return p
}

func (a *Agent) findPair(local, remote Candidate) *CandidatePair {
	for _, p := range a.checklist {
		if p.Local.Equal(local) && p.Remote.Equal(remote) {
			return p
		}
	}

	return nil
}

func (a *Agent) validateSelectedPair() bool {
	selectedPair := a.getSelectedPair()
	if selectedPair == nil {
		return false
	}

	disconnectedTime := time.Since(selectedPair.Remote.LastReceived())

	totalTimeToFailure := a.failedTimeout
	if totalTimeToFailure != 0 {
		totalTimeToFailure += a.disconnectedTimeout
	}

	a.updateConnectionState(a.connectionStateForDisconnection(disconnectedTime, totalTimeToFailure))

	return true
}

func (a *Agent) connectionStateForDisconnection(
	disconnectedTime time.Duration,
	totalTimeToFailure time.Duration,
) ConnectionState {
	disconnected := a.disconnectedTimeout != 0 && disconnectedTime > a.disconnectedTimeout
	failed := totalTimeToFailure != 0 && disconnectedTime > totalTimeToFailure

	switch {
	case failed:
		if disconnected && a.connectionState != ConnectionStateDisconnected && a.connectionState != ConnectionStateFailed {

			return ConnectionStateDisconnected
		}

		return ConnectionStateFailed
	case disconnected:
		return ConnectionStateDisconnected
	default:
		return ConnectionStateConnected
	}
}

func (a *Agent) checkKeepalive() {
	selectedPair := a.getSelectedPair()
	if selectedPair == nil {
		return
	}

	if a.keepaliveInterval != 0 {

		a.getSelector().PingCandidate(selectedPair.Local, selectedPair.Remote)
	}
}

func (a *Agent) AddRemoteCandidate(cand Candidate) error {
	if cand == nil {
		return nil
	}

	if cand.TCPType() == TCPTypeActive {
		a.log.Infof("Ignoring remote candidate with tcpType active: %s", cand)

		return nil
	}

	if cand.Type() == CandidateTypeHost && strings.HasSuffix(cand.Address(), ".local") {
		if a.mDNSMode == MulticastDNSModeDisabled {
			a.log.Warnf("Remote mDNS candidate added, but mDNS is disabled: (%s)", cand.Address())

			return nil
		}

		hostCandidate, ok := cand.(*CandidateHost)
		if !ok {
			return ErrAddressParseFailed
		}

		go a.resolveAndAddMulticastCandidate(hostCandidate)

		return nil
	}

	go func() {
		if err := a.loop.Run(a.loop, func(_ context.Context) {

			a.addRemoteCandidate(cand)
		}); err != nil {
			a.log.Warnf("Failed to add remote candidate %s: %v", cand.Address(), err)

			return
		}
	}()

	return nil
}

func (a *Agent) resolveAndAddMulticastCandidate(cand *CandidateHost) {
	if a.mDNSConn == nil {
		return
	}

	ctx, cancel := context.WithTimeout(a.loop, a.mDNSQueryTimeout())
	defer cancel()

	_, src, err := a.mDNSConn.QueryAddr(ctx, cand.Address())
	if err != nil {
		a.log.Warnf("Failed to discover mDNS candidate %s: %v", cand.Address(), err)

		return
	}

	if err = cand.setIPAddr(src); err != nil {
		a.log.Warnf("Failed to discover mDNS candidate %s: %v", cand.Address(), err)

		return
	}

	if err = a.loop.Run(a.loop, func(_ context.Context) {

		a.addRemoteCandidate(cand)
	}); err != nil {
		a.log.Warnf("Failed to add mDNS candidate %s: %v", cand.Address(), err)

		return
	}
}

func (a *Agent) mDNSQueryTimeout() time.Duration {
	if a.stunGatherTimeout > 0 {
		return a.stunGatherTimeout
	}

	return defaultSTUNGatherTimeout
}

func (a *Agent) requestConnectivityCheck() {
	select {
	case a.forceCandidateContact <- true:
	default:
	}
}

func (a *Agent) addRemotePassiveTCPCandidate(_ Candidate) {}

func copyAtomicValue(dst, src *atomic.Value) {
	if value := src.Load(); value != nil {
		dst.Store(value)
	}
}

type candidateActivitySetter interface {
	setLastReceived(time.Time)
	setLastSent(time.Time)
}

func copyCandidateActivity(dst, src Candidate) {
	setter, ok := dst.(candidateActivitySetter)
	if !ok {
		return
	}

	if lastReceived := src.LastReceived(); !lastReceived.IsZero() && dst.LastReceived().IsZero() {
		setter.setLastReceived(lastReceived)
	}

	if lastSent := src.LastSent(); !lastSent.IsZero() && dst.LastSent().IsZero() {
		setter.setLastSent(lastSent)
	}
}

func replacePairRemote(pair *CandidatePair, remote Candidate) *CandidatePair {
	replacement := newCandidatePair(pair.Local, remote, pair.iceRoleControlling)
	replacement.id = pair.id
	replacement.bindingRequestCount = pair.bindingRequestCount
	replacement.state = pair.state
	replacement.nominated = pair.nominated
	replacement.nominateOnBindingSuccess = pair.nominateOnBindingSuccess

	atomic.StoreInt64(&replacement.currentRoundTripTime, atomic.LoadInt64(&pair.currentRoundTripTime))
	atomic.StoreInt64(&replacement.totalRoundTripTime, atomic.LoadInt64(&pair.totalRoundTripTime))
	atomic.StoreUint32(&replacement.packetsSent, atomic.LoadUint32(&pair.packetsSent))
	atomic.StoreUint32(&replacement.packetsReceived, atomic.LoadUint32(&pair.packetsReceived))
	atomic.StoreUint64(&replacement.bytesSent, atomic.LoadUint64(&pair.bytesSent))
	atomic.StoreUint64(&replacement.bytesReceived, atomic.LoadUint64(&pair.bytesReceived))
	atomic.StoreUint64(&replacement.requestsReceived, atomic.LoadUint64(&pair.requestsReceived))
	atomic.StoreUint64(&replacement.requestsSent, atomic.LoadUint64(&pair.requestsSent))
	atomic.StoreUint64(&replacement.responsesReceived, atomic.LoadUint64(&pair.responsesReceived))
	atomic.StoreUint64(&replacement.responsesSent, atomic.LoadUint64(&pair.responsesSent))

	copyAtomicValue(&replacement.lastPacketSentAt, &pair.lastPacketSentAt)
	copyAtomicValue(&replacement.lastPacketReceivedAt, &pair.lastPacketReceivedAt)
	copyAtomicValue(&replacement.firstRequestSentAt, &pair.firstRequestSentAt)
	copyAtomicValue(&replacement.lastRequestSentAt, &pair.lastRequestSentAt)
	copyAtomicValue(&replacement.firstResponseReceivedAt, &pair.firstResponseReceivedAt)
	copyAtomicValue(&replacement.lastResponseReceivedAt, &pair.lastResponseReceivedAt)
	copyAtomicValue(&replacement.firstRequestReceivedAt, &pair.firstRequestReceivedAt)
	copyAtomicValue(&replacement.lastRequestReceivedAt, &pair.lastRequestReceivedAt)

	return replacement
}

func (a *Agent) retargetKnownPairHolders(oldPair, newPair *CandidatePair) {
	selector := a.getSelector()

	switch s := selector.(type) {
	case *controllingSelector:
		if s.nominatedPair == oldPair {
			s.nominatedPair = newPair
		}
	case *liteSelector:
		if cs, ok := s.pairCandidateSelector.(*controllingSelector); ok && cs.nominatedPair == oldPair {
			cs.nominatedPair = newPair
		}
	}
}

func removeRedundantPrflxFromSet(set []Candidate, cand Candidate) ([]Candidate, []Candidate) {
	var replacedPrflx []Candidate

	for i := 0; i < len(set); i++ {
		existing := set[i]
		if existing.Type() == CandidateTypePeerReflexive && existing.transportAddressEqual(cand) {
			replacedPrflx = append(replacedPrflx, existing)
			set = append(set[:i], set[i+1:]...)
			i--
		}
	}

	return set, replacedPrflx
}

func (a *Agent) replaceRemoteInPairs(oldRemote, newRemote Candidate) {
	for i, pair := range a.checklist {
		if pair.Remote == oldRemote {
			oldPriority := pair.priority()
			replacement := replacePairRemote(pair, newRemote)
			replacement.setPriorityOverride(oldPriority)
			a.checklist[i] = replacement
			a.pairsByID[replacement.id] = replacement
			a.retargetKnownPairHolders(pair, replacement)

			if a.getSelectedPair() == pair {
				a.setSelectedPair(replacement)
			}
		}
	}
}

func (a *Agent) replaceRemoteInLocalCaches(oldRemote, newRemote Candidate) {
	for _, locals := range a.localCandidates {
		for _, local := range locals {
			local.replaceRemoteCandidateCacheValues(oldRemote, newRemote)
		}
	}
}

func (a *Agent) replaceRedundantPeerReflexiveCandidates(set []Candidate, cand Candidate) []Candidate {
	if cand.Type() == CandidateTypePeerReflexive {
		return set
	}

	updatedSet, replacedPrflx := removeRedundantPrflxFromSet(set, cand)
	for _, oldRemote := range replacedPrflx {
		copyCandidateActivity(cand, oldRemote)
		a.replaceRemoteInPairs(oldRemote, cand)
		a.replaceRemoteInLocalCaches(oldRemote, cand)
	}

	return updatedSet
}

func (a *Agent) addRemoteCandidate(cand Candidate) bool {
	if !a.shouldAcceptRemoteCandidate(cand) {
		return false
	}

	set := a.remoteCandidates[cand.NetworkType()]

	for _, candidate := range set {
		if candidate.Equal(cand) {
			return true
		}
	}

	set = a.replaceRedundantPeerReflexiveCandidates(set, cand)

	acceptRemotePassiveTCPCandidate := false

	if !a.disableActiveTCP && cand.TCPType() == TCPTypePassive {
		if slices.Contains(configuredNetworkTypes(a.networkTypes), cand.NetworkType()) {
			acceptRemotePassiveTCPCandidate = true
		}
	}

	if acceptRemotePassiveTCPCandidate {
		a.addRemotePassiveTCPCandidate(cand)
	}

	set = append(set, cand)
	a.remoteCandidates[cand.NetworkType()] = set

	if cand.TCPType() != TCPTypePassive {
		if localCandidates, ok := a.localCandidates[cand.NetworkType()]; ok {
			for _, localCandidate := range localCandidates {
				if a.findPair(localCandidate, cand) == nil {
					a.addPair(localCandidate, cand)
				}
			}
		}
	}

	a.requestConnectivityCheck()

	return true
}

func (a *Agent) shouldAcceptRemoteCandidate(cand Candidate) bool {
	if a.remoteIPFilter == nil {
		return true
	}

	ipAddr, _, _, err := parseAddr(cand.addr())
	if err != nil {
		a.log.Warnf("Ignoring remote candidate with unparsable address %q: %v", cand.addr(), err)

		return false
	}

	if !a.remoteIPFilter(ipAddr.AsSlice()) {
		a.log.Warnf("Ignoring remote candidate filtered by remote IP policy: %s", cand)

		return false
	}

	return true
}

func (a *Agent) addCandidate(ctx context.Context, cand Candidate, candidateConn net.PacketConn) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return a.loop.Run(ctx, func(context.Context) {
		set := a.localCandidates[cand.NetworkType()]
		for _, candidate := range set {
			if candidate.Equal(cand) {
				a.log.Debugf("Ignore duplicate candidate: %s", cand)
				if err := cand.close(); err != nil {
					a.log.Warnf("Failed to close duplicate candidate: %v", err)
				}
				if err := candidateConn.Close(); err != nil {
					a.log.Warnf("Failed to close duplicate candidate connection: %v", err)
				}

				return
			}
		}

		a.setCandidateExtensions(cand)
		cand.start(a, candidateConn, a.startedCh)

		set = append(set, cand)
		a.localCandidates[cand.NetworkType()] = set

		if remoteCandidates, ok := a.remoteCandidates[cand.NetworkType()]; ok {
			for _, remoteCandidate := range remoteCandidates {
				a.addPair(cand, remoteCandidate)
			}
		}

		a.requestConnectivityCheck()

		if !cand.filterForLocationTracking() {
			a.candidateNotifier.EnqueueCandidate(cand)
		}
	})
}

func (a *Agent) setCandidateExtensions(cand Candidate) {
	err := cand.AddExtension(CandidateExtension{
		Key:   "ufrag",
		Value: a.localUfrag,
	})
	if err != nil {
		a.log.Errorf("Failed to add ufrag extension to candidate: %v", err)
	}
}

func (a *Agent) GetRemoteCandidates() ([]Candidate, error) {
	var res []Candidate

	err := a.loop.Run(a.loop, func(_ context.Context) {
		var candidates []Candidate
		for _, set := range a.remoteCandidates {
			candidates = append(candidates, set...)
		}
		res = candidates
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (a *Agent) GetLocalCandidates() ([]Candidate, error) {
	var res []Candidate

	err := a.loop.Run(a.loop, func(_ context.Context) {
		var candidates []Candidate
		for _, set := range a.localCandidates {
			for _, c := range set {
				if c.filterForLocationTracking() {
					continue
				}
				candidates = append(candidates, c)
			}
		}
		res = candidates
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (a *Agent) GetGatheringState() (GatheringState, error) {
	var state GatheringState
	err := a.loop.Run(a.loop, func(_ context.Context) {
		state = a.gatheringState
	})
	if err != nil {
		return GatheringStateUnknown, err
	}

	return state, nil
}

func (a *Agent) GetLocalUserCredentials() (frag string, pwd string, err error) {
	valSet := make(chan struct{})
	err = a.loop.Run(a.loop, func(_ context.Context) {
		frag = a.localUfrag
		pwd = a.localPwd
		close(valSet)
	})

	if err == nil {
		<-valSet
	}

	return
}

func (a *Agent) GetRemoteUserCredentials() (frag string, pwd string, err error) {
	valSet := make(chan struct{})
	err = a.loop.Run(a.loop, func(_ context.Context) {
		frag = a.remoteUfrag
		pwd = a.remotePwd
		close(valSet)
	})

	if err == nil {
		<-valSet
	}

	return
}

func (a *Agent) removeUfragFromMux() {
	if a.tcpMux != nil {
		a.tcpMux.RemoveConnByUfrag(a.localUfrag)
	}
	if a.udpMux != nil {
		a.udpMux.RemoveConnByUfrag(a.localUfrag)
	}
	if a.udpMuxSrflx != nil {
		a.udpMuxSrflx.RemoveConnByUfrag(a.localUfrag)
	}
}

func (a *Agent) Close() error {
	return a.close(false)
}

func (a *Agent) GracefulClose() error {
	return a.close(true)
}

func (a *Agent) close(graceful bool) error {

	a.loop.Close()

	a.connectionStateNotifier.Close(graceful)
	a.candidateNotifier.Close(graceful)
	a.selectedCandidatePairNotifier.Close(graceful)

	return nil
}

func (a *Agent) deleteAllCandidates() {
	for net, cs := range a.localCandidates {
		for _, c := range cs {
			if err := c.close(); err != nil {
				a.log.Warnf("Failed to close candidate %s: %v", c, err)
			}
		}
		delete(a.localCandidates, net)
	}
	for net, cs := range a.remoteCandidates {
		for _, c := range cs {
			if err := c.close(); err != nil {
				a.log.Warnf("Failed to close candidate %s: %v", c, err)
			}
		}
		delete(a.remoteCandidates, net)
	}
}

func (a *Agent) findRemoteCandidate(networkType NetworkType, addr net.Addr) Candidate {
	ip, port, _, err := parseAddr(addr)
	if err != nil {
		a.log.Warnf("Failed to parse address: %s; error: %s", addr, err)

		return nil
	}

	set := a.remoteCandidates[networkType]
	for _, c := range set {
		if c.Address() == ip.String() && c.Port() == port {
			return c
		}
	}

	return nil
}

func (a *Agent) sendBindingRequest(msg *stun.Message, local, remote Candidate) {
	a.log.Tracef("Ping STUN from %s to %s", local, remote)

	var nominationValue *uint32
	var nomination NominationAttribute
	if err := nomination.GetFromWithType(msg, a.nominationAttribute); err == nil {
		nominationValue = &nomination.Value
	}

	a.invalidatePendingBindingRequests(time.Now())
	a.pendingBindingRequests = append(a.pendingBindingRequests, bindingRequest{
		timestamp:       time.Now(),
		transactionID:   msg.TransactionID,
		destination:     remote.addr(),
		isUseCandidate:  msg.Contains(stun.AttrUseCandidate),
		nominationValue: nominationValue,
	})

	if pair := a.findPair(local, remote); pair != nil {
		pair.UpdateRequestSent()
	} else {
		a.log.Warnf("Failed to find pair for add binding request from %s to %s", local, remote)
	}
	a.sendSTUN(msg, local, remote)
}

func (a *Agent) sendBindingSuccess(m *stun.Message, local, remote Candidate) {
	base := remote

	ip, port, _, err := parseAddr(base.addr())
	if err != nil {
		a.log.Warnf("Failed to parse address: %s; error: %s", base.addr(), err)

		return
	}

	if out, err := stun.Build(m, stun.BindingSuccess,
		&stun.XORMappedAddress{
			IP:   ip.AsSlice(),
			Port: port,
		},
		stun.NewShortTermIntegrity(a.localPwd),
		stun.Fingerprint,
	); err != nil {
		a.log.Warnf("Failed to handle inbound ICE from: %s to: %s error: %s", local, remote, err)
	} else {
		if pair := a.findPair(local, remote); pair != nil {
			pair.UpdateResponseSent()
		} else {
			a.log.Warnf("Failed to find pair for add binding response from %s to %s", local, remote)
		}
		a.sendSTUN(out, local, remote)
	}
}

func (a *Agent) invalidatePendingBindingRequests(filterTime time.Time) {
	initialSize := len(a.pendingBindingRequests)

	temp := a.pendingBindingRequests[:0]
	for _, bindingRequest := range a.pendingBindingRequests {
		if filterTime.Sub(bindingRequest.timestamp) < maxBindingRequestTimeout {
			temp = append(temp, bindingRequest)
		}
	}

	a.pendingBindingRequests = temp
	if bindRequestsRemoved := initialSize - len(a.pendingBindingRequests); bindRequestsRemoved > 0 {
		a.log.Tracef("Discarded %d binding requests because they expired", bindRequestsRemoved)
	}
}

func (a *Agent) handleInboundBindingSuccess(id [stun.TransactionIDSize]byte) (bool, *bindingRequest, time.Duration) {
	a.invalidatePendingBindingRequests(time.Now())
	for i := range a.pendingBindingRequests {
		if a.pendingBindingRequests[i].transactionID == id {
			validBindingRequest := a.pendingBindingRequests[i]
			a.pendingBindingRequests = append(a.pendingBindingRequests[:i], a.pendingBindingRequests[i+1:]...)

			return true, &validBindingRequest, time.Since(validBindingRequest.timestamp)
		}
	}

	return false, nil, 0
}

func (a *Agent) handleRoleConflict(msg *stun.Message, local, remote Candidate, remoteTieBreaker *AttrControl) {
	localIsGreaterOrEqual := a.tieBreaker >= remoteTieBreaker.Tiebreaker
	a.log.Warnf("Role conflict local and remote same role(%s), localIsGreaterOrEqual(%t)", a.role(), localIsGreaterOrEqual)

	if (a.isControlling.Load() && localIsGreaterOrEqual) || (!a.isControlling.Load() && !localIsGreaterOrEqual) {
		if roleConflictMsg, err := stun.Build(msg, stun.BindingError,
			stun.ErrorCodeAttribute{
				Code:   stun.CodeRoleConflict,
				Reason: []byte("Role Conflict"),
			},
			stun.NewShortTermIntegrity(a.localPwd),
			stun.Fingerprint,
		); err != nil {
			a.log.Warnf("Failed to generate Role Conflict message from: %s to: %s error: %s", local, remote, err)
		} else {
			a.sendSTUN(roleConflictMsg, local, remote)
		}
	} else {
		a.isControlling.Store(!a.isControlling.Load())
		a.setSelector()
	}
}

func (a *Agent) handleInbound(msg *stun.Message, local Candidate, remote net.Addr) {
	if msg == nil || local == nil {
		return
	}

	if !canHandleInbound(msg) {
		a.log.Tracef("Unhandled STUN from %s to %s class(%s) method(%s)", remote, local, msg.Type.Class, msg.Type.Method)

		return
	}

	remoteCandidate := a.findRemoteCandidate(local.NetworkType(), remote)

	switch msg.Type.Class {
	case stun.ClassSuccessResponse:
		if !a.handleInboundResponse(remoteCandidate, local, remote, msg) {
			return
		}
	case stun.ClassRequest:
		var ok bool
		if remoteCandidate, ok = a.handleInboundRequest(remoteCandidate, local, remote, msg); !ok {
			return
		}
	default:
	}

	if remoteCandidate != nil {
		remoteCandidate.seen(false)
	}
}

func canHandleInbound(msg *stun.Message) bool {
	return msg.Type.Method == stun.MethodBinding &&
		(msg.Type.Class == stun.ClassSuccessResponse ||
			msg.Type.Class == stun.ClassRequest ||
			msg.Type.Class == stun.ClassIndication)
}

func (a *Agent) handleInboundResponse(
	remoteCandidate, local Candidate, remote net.Addr, msg *stun.Message,
) bool {
	if err := stun.MessageIntegrity([]byte(a.remotePwd)).Check(msg); err != nil {
		a.log.Warnf("Discard success response with broken integrity from (%s), %v", remote, err)

		return false
	}

	if remoteCandidate == nil {
		a.log.Warnf("Discard success message from (%s), no such remote", remote)

		return false
	}

	a.getSelector().HandleSuccessResponse(msg, local, remoteCandidate, remote)

	return true
}

func (a *Agent) handleInboundRequest(
	remoteCandidate, local Candidate, remote net.Addr, msg *stun.Message,
) (remoteCand Candidate, ok bool) {
	a.log.Tracef(
		"Inbound STUN (Request) from %s to %s, useCandidate: %v",
		remote,
		local,
		msg.Contains(stun.AttrUseCandidate),
	)

	if err := stunx.AssertUsername(msg, a.localUfrag+":"+a.remoteUfrag); err != nil {
		a.log.Warnf("Discard request with wrong username from (%s), %v", remote, err)

		return nil, false
	} else if err := stun.MessageIntegrity([]byte(a.localPwd)).Check(msg); err != nil {
		a.log.Warnf("Discard request with broken integrity from (%s), %v", remote, err)

		return nil, false
	}

	if remoteCandidate == nil {
		ip, port, networkType, err := parseAddr(remote)
		if err != nil {
			a.log.Errorf("Failed to create parse remote net.Addr when creating remote prflx candidate: %s", err)

			return nil, false
		}

		prflxCandidateConfig := CandidatePeerReflexiveConfig{
			Network:   networkType.String(),
			Address:   ip.String(),
			Port:      port,
			Component: local.Component(),
			RelAddr:   "",
			RelPort:   0,
		}

		var prio PriorityAttr
		err = prio.GetFrom(msg)
		if err == nil {
			prflxCandidateConfig.Priority = uint32(prio)
		}

		prflxCandidate, err := NewCandidatePeerReflexive(&prflxCandidateConfig)
		if err != nil {
			a.log.Errorf("Failed to create new remote prflx candidate (%s)", err)

			return nil, false
		}
		remoteCandidate = prflxCandidate

		a.log.Debugf("Adding a new peer-reflexive candidate: %s ", remote)
		if !a.addRemoteCandidate(remoteCandidate) {
			return nil, false
		}
	}

	remoteTieBreaker := &AttrControl{}
	if err := remoteTieBreaker.GetFrom(msg); err == nil && remoteTieBreaker.Role == a.role() {
		a.handleRoleConflict(msg, local, remoteCandidate, remoteTieBreaker)

		return nil, false
	}

	a.getSelector().HandleBindingRequest(msg, local, remoteCandidate)

	return remoteCandidate, true
}

func (a *Agent) validateNonSTUNTraffic(local Candidate, remote net.Addr) (Candidate, bool) {
	var remoteCandidate Candidate
	if err := a.loop.Run(local.context(), func(context.Context) {
		remoteCandidate = a.findRemoteCandidate(local.NetworkType(), remote)
		if remoteCandidate != nil {
			remoteCandidate.seen(false)
		}
	}); err != nil {
		a.log.Warnf("Failed to validate remote candidate: %v", err)
	}

	return remoteCandidate, remoteCandidate != nil
}

func (a *Agent) GetSelectedCandidatePair() (*CandidatePair, error) {
	selectedPair := a.getSelectedPair()
	if selectedPair == nil {
		return nil, nil
	}

	local, err := selectedPair.Local.copy()
	if err != nil {
		return nil, err
	}

	remote, err := selectedPair.Remote.copy()
	if err != nil {
		return nil, err
	}

	return &CandidatePair{Local: local, Remote: remote}, nil
}

func (a *Agent) getSelectedPair() *CandidatePair {
	if selectedPair, ok := a.selectedPair.Load().(*CandidatePair); ok {
		return selectedPair
	}

	return nil
}

func (a *Agent) closeMulticastConn() {
	if a.mDNSConn != nil {
		if err := a.mDNSConn.Close(); err != nil {
			a.log.Warnf("Failed to close mDNS Conn: %v", err)
		}
	}
}

func (a *Agent) SetRemoteCredentials(remoteUfrag, remotePwd string) error {
	switch {
	case remoteUfrag == "":
		return ErrRemoteUfragEmpty
	case remotePwd == "":
		return ErrRemotePwdEmpty
	}

	return a.loop.Run(a.loop, func(_ context.Context) {
		a.remoteUfrag = remoteUfrag
		a.remotePwd = remotePwd
	})
}

func (a *Agent) UpdateOptions(opts ...AgentOption) error {
	var optErr error

	err := a.loop.Run(a.loop, func(_ context.Context) {
		for _, opt := range opts {
			if optErr = opt(a); optErr != nil {
				return
			}
		}
	})
	if err != nil {
		return err
	}

	return optErr
}

func (a *Agent) Restart(ufrag, pwd string) error {
	if ufrag == "" {
		var err error
		ufrag, err = generateUFrag()
		if err != nil {
			return err
		}
	}
	if pwd == "" {
		var err error
		pwd, err = generatePwd()
		if err != nil {
			return err
		}
	}

	if len([]rune(ufrag))*8 < 24 {
		return ErrLocalUfragInsufficientBits
	}
	if len([]rune(pwd))*8 < 128 {
		return ErrLocalPwdInsufficientBits
	}

	var err error
	if runErr := a.loop.Run(a.loop, func(_ context.Context) {
		if a.gatheringState == GatheringStateGathering {
			a.gatherCandidateCancel()
		}

		a.removeUfragFromMux()
		a.localUfrag = ufrag
		a.localPwd = pwd
		a.remoteUfrag = ""
		a.remotePwd = ""
		a.gatheringState = GatheringStateNew
		a.checklist = make([]*CandidatePair, 0)
		a.pairsByID = make(map[uint64]*CandidatePair)
		a.pendingBindingRequests = make([]bindingRequest, 0)
		a.setSelectedPair(nil)
		a.deleteAllCandidates()
		a.setSelector()

		if a.connectionState != ConnectionStateNew {
			a.updateConnectionState(ConnectionStateChecking)
		}
	}); runErr != nil {
		return runErr
	}

	return err
}

func (a *Agent) setGatheringState(newState GatheringState) error {
	done := make(chan struct{})
	if err := a.loop.Run(a.loop, func(context.Context) {
		if a.gatheringState != newState && newState == GatheringStateComplete {
			a.candidateNotifier.EnqueueCandidate(nil)
		}

		a.gatheringState = newState
		close(done)
	}); err != nil {
		return err
	}

	<-done

	return nil
}

func (a *Agent) needsToCheckPriorityOnNominated() bool {
	return !a.lite || a.enableUseCandidateCheckPriority
}

func (a *Agent) role() Role {
	if a.isControlling.Load() {
		return Controlling
	}

	return Controlled
}

func (a *Agent) setSelector() {
	a.selectorLock.Lock()
	defer a.selectorLock.Unlock()

	var s pairCandidateSelector
	if a.isControlling.Load() {
		s = &controllingSelector{agent: a, log: a.log}
	} else {
		s = &controlledSelector{agent: a, log: a.log}
	}
	if a.lite {
		s = &liteSelector{pairCandidateSelector: s}
	}

	s.Start()
	a.selector = s
}

func (a *Agent) getSelector() pairCandidateSelector {
	a.selectorLock.Lock()
	defer a.selectorLock.Unlock()

	return a.selector
}

func (a *Agent) getNominationValue() uint32 {
	if a.nominationValueGenerator != nil {
		return a.nominationValueGenerator()
	}

	return 0
}

func (a *Agent) RenominateCandidate(local, remote Candidate) error {
	if !a.isControlling.Load() {
		return ErrOnlyControllingAgentCanRenominate
	}

	if !a.enableRenomination {
		return ErrRenominationNotEnabled
	}

	pair := a.findPair(local, remote)
	if pair == nil {
		return ErrCandidatePairNotFound
	}

	return a.sendNominationRequest(pair, a.getNominationValue())
}

func (a *Agent) sendNominationRequest(pair *CandidatePair, nominationValue uint32) error {
	attributes := []stun.Setter{
		stun.TransactionID,
		stun.NewUsername(a.remoteUfrag + ":" + a.localUfrag),
		UseCandidate(),
		AttrControlling(a.tieBreaker),
		PriorityAttr(pair.Local.Priority()),
		stun.NewShortTermIntegrity(a.remotePwd),
		stun.Fingerprint,
	}

	if a.enableRenomination && nominationValue > 0 {
		attributes = append(attributes, NominationSetter{
			Value:    nominationValue,
			AttrType: a.nominationAttribute,
		})
		a.log.Tracef("Sending renomination request from %s to %s with nomination value %d",
			pair.Local, pair.Remote, nominationValue)
	}

	msg, err := stun.Build(append([]stun.Setter{stun.BindingRequest}, attributes...)...)
	if err != nil {
		return fmt.Errorf("failed to build nomination request: %w", err)
	}

	a.sendBindingRequest(msg, pair.Local, pair.Remote)

	return nil
}

func (a *Agent) evaluateCandidatePairQuality(pair *CandidatePair) float64 {
	if pair == nil || pair.state != CandidatePairStateSucceeded {
		return 0
	}

	score := float64(0)

	localTypeScore := float64(0)
	switch pair.Local.Type() {
	case CandidateTypeHost:
		localTypeScore = 100
	case CandidateTypeServerReflexive:
		localTypeScore = 50
	case CandidateTypePeerReflexive:
		localTypeScore = 30
	case CandidateTypeRelay:
		localTypeScore = 10
	case CandidateTypeUnspecified:
		localTypeScore = 0
	}

	remoteTypeScore := float64(0)
	switch pair.Remote.Type() {
	case CandidateTypeHost:
		remoteTypeScore = 100
	case CandidateTypeServerReflexive:
		remoteTypeScore = 50
	case CandidateTypePeerReflexive:
		remoteTypeScore = 30
	case CandidateTypeRelay:
		remoteTypeScore = 10
	case CandidateTypeUnspecified:
		remoteTypeScore = 0
	}

	score += (localTypeScore + remoteTypeScore) / 2

	rtt := pair.CurrentRoundTripTime()
	if rtt > 0 {

		rttDuration := time.Duration(rtt * float64(time.Second))
		rttMs := float64(rttDuration / time.Millisecond)
		if rttMs < 1 {
			rttMs = 1
		}

		score -= math.Log10(rttMs) * 10
	} else {

		score -= 30
	}

	if pair.ResponsesReceived() > 0 {
		lastResponse := pair.LastResponseReceivedAt()
		if !lastResponse.IsZero() && time.Since(lastResponse) < 5*time.Second {
			score += 20
		}
	}

	return score
}

func (a *Agent) shouldRenominate(current, candidate *CandidatePair) bool {
	if current == nil || candidate == nil || current.equal(candidate) || candidate.state != CandidatePairStateSucceeded {
		return false
	}

	currentIsRelay := current.Local.Type() == CandidateTypeRelay ||
		current.Remote.Type() == CandidateTypeRelay
	candidateIsDirect := candidate.Local.Type() == CandidateTypeHost &&
		candidate.Remote.Type() == CandidateTypeHost

	if currentIsRelay && candidateIsDirect {
		a.log.Debugf("Should renominate: relay -> direct connection available")

		return true
	}

	currentRTT := current.CurrentRoundTripTime()
	candidateRTT := candidate.CurrentRoundTripTime()

	if currentRTT > 0 && candidateRTT > 0 {
		currentRTTDuration := time.Duration(currentRTT * float64(time.Second))
		candidateRTTDuration := time.Duration(candidateRTT * float64(time.Second))
		rttImprovement := currentRTTDuration - candidateRTTDuration

		if rttImprovement > 10*time.Millisecond {
			a.log.Debugf("Should renominate: RTT improvement of %v", rttImprovement)

			return true
		}
	}

	currentScore := a.evaluateCandidatePairQuality(current)
	candidateScore := a.evaluateCandidatePairQuality(candidate)

	if candidateScore > currentScore*1.15 {
		a.log.Debugf("Should renominate: quality score improved from %.2f to %.2f",
			currentScore, candidateScore)

		return true
	}

	return false
}

func (a *Agent) findBestCandidatePair() *CandidatePair {
	var best *CandidatePair
	bestScore := float64(-math.MaxFloat64)

	for _, pair := range a.checklist {
		if pair.state != CandidatePairStateSucceeded {
			continue
		}

		score := a.evaluateCandidatePairQuality(pair)
		if score > bestScore {
			bestScore = score
			best = pair
		}
	}

	return best
}

const (
	defaultCheckInterval = 200 * time.Millisecond

	defaultKeepaliveInterval = 2 * time.Second

	defaultDisconnectedTimeout = 5 * time.Second

	defaultFailedTimeout = 25 * time.Second

	defaultHostAcceptanceMinWait = 0

	defaultSrflxAcceptanceMinWait = 500 * time.Millisecond

	defaultPrflxAcceptanceMinWait = 1000 * time.Millisecond

	defaultRelayAcceptanceMinWait = 2000 * time.Millisecond

	defaultRelayOnlyAcceptanceMinWait = time.Duration(0)

	defaultSTUNGatherTimeout = 5 * time.Second

	defaultMaxBindingRequests = 7

	defaultTCPPriorityOffset = 27

	maxBufferSize = 1000 * 1000

	maxBindingRequestTimeout = 4000 * time.Millisecond
)

func defaultCandidateTypes() []CandidateType {
	return []CandidateType{CandidateTypeHost, CandidateTypeServerReflexive, CandidateTypeRelay}
}

func defaultRelayAcceptanceMinWaitFor(candidateTypes []CandidateType) time.Duration {
	if len(candidateTypes) == 1 && candidateTypes[0] == CandidateTypeRelay {
		return defaultRelayOnlyAcceptanceMinWait
	}

	return defaultRelayAcceptanceMinWait
}

type AgentConfig struct {
	Urls                            []*stun.URI
	PortMin                         uint16
	PortMax                         uint16
	LocalUfrag                      string
	LocalPwd                        string
	MulticastDNSMode                MulticastDNSMode
	MulticastDNSHostName            string
	DisconnectedTimeout             *time.Duration
	FailedTimeout                   *time.Duration
	KeepaliveInterval               *time.Duration
	CheckInterval                   *time.Duration
	NetworkTypes                    []NetworkType
	turnTransportProtocols          []NetworkType
	CandidateTypes                  []CandidateType
	LoggerFactory                   logging.LoggerFactory
	MaxBindingRequests              *uint16
	Lite                            bool
	NAT1To1IPCandidateType          CandidateType
	NAT1To1IPs                      []string
	HostAcceptanceMinWait           *time.Duration
	SrflxAcceptanceMinWait          *time.Duration
	PrflxAcceptanceMinWait          *time.Duration
	RelayAcceptanceMinWait          *time.Duration
	STUNGatherTimeout               *time.Duration
	Net                             transport.Net
	InterfaceFilter                 func(string) (keep bool)
	IPFilter                        func(net.IP) (keep bool)
	RemoteIPFilter                  func(net.IP) (keep bool)
	InsecureSkipVerify              bool
	TCPMux                          TCPMux
	UDPMux                          UDPMux
	UDPMuxSrflx                     UniversalUDPMux
	ProxyDialer                     proxy.Dialer
	AcceptAggressiveNomination      bool
	IncludeLoopback                 bool
	TCPPriorityOffset               *uint16
	DisableActiveTCP                bool
	BindingRequestHandler           func(m *stun.Message, local, remote Candidate, pair *CandidatePair) bool
	EnableUseCandidateCheckPriority bool
}

func (config *AgentConfig) initWithDefaults(agent *Agent) {
	if config.MaxBindingRequests == nil {
		agent.maxBindingRequests = defaultMaxBindingRequests
	} else {
		agent.maxBindingRequests = *config.MaxBindingRequests
	}

	if config.HostAcceptanceMinWait == nil {
		agent.hostAcceptanceMinWait = defaultHostAcceptanceMinWait
	} else {
		agent.hostAcceptanceMinWait = *config.HostAcceptanceMinWait
	}

	if config.SrflxAcceptanceMinWait == nil {
		agent.srflxAcceptanceMinWait = defaultSrflxAcceptanceMinWait
	} else {
		agent.srflxAcceptanceMinWait = *config.SrflxAcceptanceMinWait
	}

	if config.PrflxAcceptanceMinWait == nil {
		agent.prflxAcceptanceMinWait = defaultPrflxAcceptanceMinWait
	} else {
		agent.prflxAcceptanceMinWait = *config.PrflxAcceptanceMinWait
	}

	if config.RelayAcceptanceMinWait == nil {
		agent.relayAcceptanceMinWait = defaultRelayAcceptanceMinWaitFor(config.CandidateTypes)
	} else {
		agent.relayAcceptanceMinWait = *config.RelayAcceptanceMinWait
	}

	if config.STUNGatherTimeout == nil {
		agent.stunGatherTimeout = defaultSTUNGatherTimeout
	} else {
		agent.stunGatherTimeout = *config.STUNGatherTimeout
	}

	if config.TCPPriorityOffset == nil {
		agent.tcpPriorityOffset = defaultTCPPriorityOffset
	} else {
		agent.tcpPriorityOffset = *config.TCPPriorityOffset
	}

	if config.DisconnectedTimeout == nil {
		agent.disconnectedTimeout = defaultDisconnectedTimeout
	} else {
		agent.disconnectedTimeout = *config.DisconnectedTimeout
	}

	if config.FailedTimeout == nil {
		agent.failedTimeout = defaultFailedTimeout
	} else {
		agent.failedTimeout = *config.FailedTimeout
	}

	if config.KeepaliveInterval == nil {
		agent.keepaliveInterval = defaultKeepaliveInterval
	} else {
		agent.keepaliveInterval = *config.KeepaliveInterval
	}

	if config.CheckInterval == nil {
		agent.checkInterval = defaultCheckInterval
	} else {
		agent.checkInterval = *config.CheckInterval
	}

	if len(config.CandidateTypes) == 0 {
		agent.candidateTypes = defaultCandidateTypes()
	} else {
		agent.candidateTypes = config.CandidateTypes
	}
}

func (a *Agent) OnConnectionStateChange(f func(ConnectionState)) error {
	a.onConnectionStateChangeHdlr.Store(f)

	return nil
}

func (a *Agent) OnSelectedCandidatePairChange(f func(Candidate, Candidate)) error {
	a.onSelectedCandidatePairChangeHdlr.Store(f)

	return nil
}

func (a *Agent) OnCandidate(f func(Candidate)) error {
	a.onCandidateHdlr.Store(f)

	return nil
}

func (a *Agent) onSelectedCandidatePairChange(p *CandidatePair) {
	if h, ok := a.onSelectedCandidatePairChangeHdlr.Load().(func(Candidate, Candidate)); ok && h != nil {
		h(p.Local, p.Remote)
	}
}

func (a *Agent) onCandidate(c Candidate) {
	if onCandidateHdlr, ok := a.onCandidateHdlr.Load().(func(Candidate)); ok && onCandidateHdlr != nil {
		onCandidateHdlr(c)
	}
}

func (a *Agent) onConnectionStateChange(s ConnectionState) {
	if hdlr, ok := a.onConnectionStateChangeHdlr.Load().(func(ConnectionState)); ok && hdlr != nil {
		hdlr(s)
	}
}

type handlerNotifier struct {
	sync.Mutex
	runningConnectionStates bool
	runningCandidates       bool
	runningCandidatePairs   bool
	notifiers               sync.WaitGroup
	connectionStates        []ConnectionState
	connectionStateFunc     func(ConnectionState)
	candidates              []Candidate
	candidateFunc           func(Candidate)
	selectedCandidatePairs  []*CandidatePair
	candidatePairFunc       func(*CandidatePair)
	done                    chan struct{}
}

func (h *handlerNotifier) Close(graceful bool) {
	if graceful {

		defer h.notifiers.Wait()
	}

	h.Lock()

	select {
	case <-h.done:
		h.Unlock()

		return
	default:
	}
	close(h.done)
	h.Unlock()
}

func (h *handlerNotifier) EnqueueConnectionState(state ConnectionState) {
	h.Lock()
	defer h.Unlock()

	select {
	case <-h.done:
		return
	default:
	}

	notify := func() {
		defer h.notifiers.Done()
		for {
			h.Lock()
			if len(h.connectionStates) == 0 {
				h.runningConnectionStates = false
				h.Unlock()

				return
			}
			notification := h.connectionStates[0]
			h.connectionStates = h.connectionStates[1:]
			h.Unlock()
			h.connectionStateFunc(notification)
		}
	}

	h.connectionStates = append(h.connectionStates, state)
	if !h.runningConnectionStates {
		h.runningConnectionStates = true
		h.notifiers.Add(1)
		go notify()
	}
}

func (h *handlerNotifier) EnqueueCandidate(cand Candidate) {
	h.Lock()
	defer h.Unlock()

	select {
	case <-h.done:
		return
	default:
	}

	notify := func() {
		defer h.notifiers.Done()
		for {
			h.Lock()
			if len(h.candidates) == 0 {
				h.runningCandidates = false
				h.Unlock()

				return
			}
			notification := h.candidates[0]
			h.candidates = h.candidates[1:]
			h.Unlock()
			h.candidateFunc(notification)
		}
	}

	h.candidates = append(h.candidates, cand)
	if !h.runningCandidates {
		h.runningCandidates = true
		h.notifiers.Add(1)
		go notify()
	}
}

func (h *handlerNotifier) EnqueueSelectedCandidatePair(pair *CandidatePair) {
	h.Lock()
	defer h.Unlock()

	select {
	case <-h.done:
		return
	default:
	}

	notify := func() {
		defer h.notifiers.Done()
		for {
			h.Lock()
			if len(h.selectedCandidatePairs) == 0 {
				h.runningCandidatePairs = false
				h.Unlock()

				return
			}
			notification := h.selectedCandidatePairs[0]
			h.selectedCandidatePairs = h.selectedCandidatePairs[1:]
			h.Unlock()
			h.candidatePairFunc(notification)
		}
	}

	h.selectedCandidatePairs = append(h.selectedCandidatePairs, pair)
	if !h.runningCandidatePairs {
		h.runningCandidatePairs = true
		h.notifiers.Add(1)
		go notify()
	}
}

type AgentOption func(*Agent) error

type NominationValueGenerator func() uint32

func DefaultNominationValueGenerator() NominationValueGenerator {
	var counter atomic.Uint32

	return func() uint32 {
		return counter.Add(1)
	}
}

func WithAddressRewriteRules(rules ...AddressRewriteRule) AgentOption {
	return func(agent *Agent) error {
		if agent.constructed {
			return ErrAgentOptionNotUpdatable
		}

		return appendAddressRewriteRules(agent, rules...)
	}
}

func warnOnAddressRewriteConflicts(agent *Agent) {
	if agent == nil || agent.log == nil {
		return
	}

	for _, conflict := range findAddressRewriteRuleConflicts(agent.addressRewriteRules) {
		scope := conflict.scope
		scopeSummary := fmt.Sprintf(
			"candidate=%s iface=%s cidr=%s networks=%s local=%s",
			scope.candidateType.String(),
			emptyScopeValue(scope.iface),
			emptyScopeValue(scope.cidr),
			emptyScopeValue(scope.networksKey),
			scope.localKey,
		)

		message := fmt.Sprintf(
			"detected overlapping address rewrite rule (%s): existing external IPs [%s], additional external IP %s",
			scopeSummary,
			strings.Join(conflict.existingExternalIPs, ", "),
			conflict.conflictingExternal,
		)

		agent.log.Warn(message)
	}
}

func emptyScopeValue(v string) string {
	if v == "" {
		return "*"
	}

	return v
}

func appendAddressRewriteRules(agent *Agent, rules ...AddressRewriteRule) error {
	if len(rules) == 0 {
		return nil
	}

	sanitized := make([]AddressRewriteRule, 0, len(rules))
	for _, rule := range rules {
		normalized, err := sanitizeAddressRewriteRule(rule)
		if err != nil {
			return err
		}

		sanitized = append(sanitized, normalized)
	}

	agent.addressRewriteRules = append(agent.addressRewriteRules, sanitized...)
	warnOnAddressRewriteConflicts(agent)

	return nil
}

func sanitizeAddressRewriteRule(rule AddressRewriteRule) (AddressRewriteRule, error) {
	cleaned, err := sanitizeExternalIPs(rule.External)
	if err != nil {
		return AddressRewriteRule{}, err
	}

	normalized := rule
	normalized.External = cleaned
	normalized.Local = strings.TrimSpace(rule.Local)
	if normalized.Local != "" {
		if _, _, err := validateIPString(normalized.Local); err != nil {
			return AddressRewriteRule{}, err
		}
	}
	switch normalized.Mode {
	case addressRewriteModeUnspecified:
		normalized.Mode = defaultAddressRewriteMode(normalized.AsCandidateType)
	case AddressRewriteReplace, AddressRewriteAppend:
	default:
		return AddressRewriteRule{}, ErrInvalidNAT1To1IPMapping
	}
	if len(rule.Networks) > 0 {
		normalized.Networks = append([]NetworkType(nil), rule.Networks...)
	}

	return normalized, nil
}

func defaultAddressRewriteMode(candidateType CandidateType) AddressRewriteMode {
	if candidateType == CandidateTypeUnspecified || candidateType == CandidateTypeHost {
		return AddressRewriteReplace
	}

	return AddressRewriteAppend
}

func sanitizeExternalIPs(ips []string) ([]string, error) {
	seen := make(map[string]struct{}, len(ips))
	sanitized := make([]string, 0, len(ips))

	for _, raw := range ips {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		if _, ok := seen[trimmed]; ok {
			continue
		}

		if strings.Contains(trimmed, "/") {
			return nil, ErrInvalidNAT1To1IPMapping
		}

		if _, _, err := validateIPString(trimmed); err != nil {
			return nil, err
		}

		seen[trimmed] = struct{}{}
		sanitized = append(sanitized, trimmed)
	}

	if len(sanitized) == 0 {
		return nil, ErrInvalidNAT1To1IPMapping
	}

	return sanitized, nil
}

type addressRewriteScopeKey struct {
	candidateType CandidateType
	iface         string
	cidr          string
	networksKey   string
	localKey      string
}

type addressRewriteConflict struct {
	scope               addressRewriteScopeKey
	existingExternalIPs []string
	conflictingExternal string
}

func findAddressRewriteRuleConflicts(rules []AddressRewriteRule) []addressRewriteConflict {
	conflicts := make([]addressRewriteConflict, 0)
	scopeState := make(map[addressRewriteScopeKey]map[string]struct{})

	for _, rule := range rules {
		candidateType := rule.AsCandidateType
		if candidateType == CandidateTypeUnspecified {
			candidateType = CandidateTypeHost
		}

		networksKey := "*"
		if len(rule.Networks) > 0 {
			names := make([]string, len(rule.Networks))
			for i, network := range rule.Networks {
				names[i] = network.String()
			}
			sort.Strings(names)
			networksKey = strings.Join(names, ",")
		}

		externalEntries := enumerateAddressRewriteExternalEntries(rule)
		for _, entry := range externalEntries {
			key := addressRewriteScopeKey{
				candidateType: candidateType,
				iface:         rule.Iface,
				cidr:          rule.CIDR,
				networksKey:   networksKey,
				localKey:      entry.localScopeKey,
			}

			existing := scopeState[key]
			if existing == nil {
				existing = make(map[string]struct{})
				scopeState[key] = existing
			}

			if len(existing) > 0 {
				if _, ok := existing[entry.externalIP]; !ok {
					conflicts = append(conflicts, addressRewriteConflict{
						scope:               key,
						existingExternalIPs: mapKeys(existing),
						conflictingExternal: entry.externalIP,
					})
				}
			}

			existing[entry.externalIP] = struct{}{}
		}
	}

	return conflicts
}

type addressRewriteExternalEntry struct {
	externalIP    string
	localScopeKey string
}

func enumerateAddressRewriteExternalEntries(rule AddressRewriteRule) []addressRewriteExternalEntry {
	if len(rule.External) == 0 {
		return nil
	}

	entries := make([]addressRewriteExternalEntry, 0, len(rule.External))
	localScope := deriveAddressRewriteLocalScopeKey(rule.Local)

	for _, mapping := range rule.External {
		if mapping == "" {
			continue
		}

		external := strings.TrimSpace(mapping)
		if external == "" {
			continue
		}

		scopeKey := localScope
		if scopeKey == "" {
			scopeKey = deriveAddressRewriteFamilyScopeKey(external)
		}

		entries = append(entries, addressRewriteExternalEntry{
			externalIP:    external,
			localScopeKey: scopeKey,
		})
	}

	return entries
}

func deriveAddressRewriteLocalScopeKey(local string) string {
	local = strings.TrimSpace(local)
	if local == "" {
		return ""
	}

	ip, _, err := validateIPString(local)
	if err != nil {
		return "family:unknown"
	}

	if ip.To4() != nil {
		return "family:ipv4"
	}

	return "family:ipv6"
}

func deriveAddressRewriteFamilyScopeKey(ipStr string) string {
	ip, _, err := validateIPString(ipStr)
	if err != nil {
		return "family:unknown"
	}

	if ip.To4() != nil {
		return "family:ipv4"
	}

	return "family:ipv6"
}

func mapKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

func WithICELite(lite bool) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.lite = lite

		return nil
	}
}

func WithUrls(urls []*stun.URI) AgentOption {
	return func(a *Agent) error {
		if len(urls) == 0 {
			a.urls = nil

			return nil
		}

		cloned := make([]*stun.URI, len(urls))
		copy(cloned, urls)
		a.urls = cloned

		return nil
	}
}

func WithPortRange(portMin, portMax uint16) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.portMin = portMin
		a.portMax = portMax

		return nil
	}
}

func WithDisconnectedTimeout(timeout time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.disconnectedTimeout = timeout

		return nil
	}
}

func WithFailedTimeout(timeout time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.failedTimeout = timeout

		return nil
	}
}

func WithKeepaliveInterval(interval time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.keepaliveInterval = interval

		return nil
	}
}

func WithHostAcceptanceMinWait(wait time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.hostAcceptanceMinWait = wait

		return nil
	}
}

func WithSrflxAcceptanceMinWait(wait time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.srflxAcceptanceMinWait = wait

		return nil
	}
}

func WithPrflxAcceptanceMinWait(wait time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.prflxAcceptanceMinWait = wait

		return nil
	}
}

func WithRelayAcceptanceMinWait(wait time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.relayAcceptanceMinWait = wait

		return nil
	}
}

func WithSTUNGatherTimeout(timeout time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.stunGatherTimeout = timeout

		return nil
	}
}

func WithIPFilter(filter func(net.IP) bool) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.ipFilter = filter

		return nil
	}
}

func WithRemoteIPFilter(filter func(net.IP) bool) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.remoteIPFilter = filter

		return nil
	}
}

func WithNet(net transport.Net) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.net = net

		return nil
	}
}

func WithMulticastDNSMode(mode MulticastDNSMode) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.mDNSMode = mode

		return nil
	}
}

func WithMulticastDNSHostName(hostName string) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		if !strings.HasSuffix(hostName, ".local") || len(strings.Split(hostName, ".")) != 2 {
			return ErrInvalidMulticastDNSHostName
		}

		a.mDNSName = hostName

		return nil
	}
}

func WithLocalCredentials(ufrag, pwd string) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		if ufrag != "" && len([]rune(ufrag))*8 < 24 {
			return ErrLocalUfragInsufficientBits
		}
		if pwd != "" && len([]rune(pwd))*8 < 128 {
			return ErrLocalPwdInsufficientBits
		}

		a.localUfrag = ufrag
		a.localPwd = pwd

		return nil
	}
}

func WithTCPMux(tcpMux TCPMux) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.tcpMux = tcpMux

		return nil
	}
}

func WithUDPMux(udpMux UDPMux) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.udpMux = udpMux

		return nil
	}
}

func WithProxyDialer(dialer proxy.Dialer) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.proxyDialer = dialer

		return nil
	}
}

func WithMaxBindingRequests(limit uint16) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.maxBindingRequests = limit

		return nil
	}
}

func WithRenomination(generator NominationValueGenerator) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		if generator == nil {
			return ErrInvalidNominationValueGenerator
		}
		a.enableRenomination = true
		a.nominationValueGenerator = generator

		return nil
	}
}

func WithNominationAttribute(attrType uint16) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		if attrType == 0x0000 {
			return ErrInvalidNominationAttribute
		}

		a.nominationAttribute = stun.AttrType(attrType)

		return nil
	}
}

func WithIncludeLoopback() AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.includeLoopback = true

		return nil
	}
}

func WithDisableActiveTCP() AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.disableActiveTCP = true

		return nil
	}
}

func WithBindingRequestHandler(
	handler func(m *stun.Message, local, remote Candidate, pair *CandidatePair) bool,
) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.userBindingRequestHandler = handler

		return nil
	}
}

func WithNetworkTypes(networkTypes []NetworkType) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		normalized, err := sanitizeTransportNetworkTypes(networkTypes)
		if err != nil {
			return err
		}

		a.networkTypes = normalized

		return nil
	}
}

func sanitizeTransportNetworkTypes(types []NetworkType) ([]NetworkType, error) {
	if len(types) == 0 {
		return nil, nil
	}

	seen := map[NetworkType]struct{}{}
	out := make([]NetworkType, 0, len(types))
	for _, networkType := range types {
		if !networkType.IsUDP() && !networkType.IsTCP() {
			return nil, ErrProtoType
		}

		if _, ok := seen[networkType]; ok {
			continue
		}

		seen[networkType] = struct{}{}
		out = append(out, networkType)
	}

	return out, nil
}

func WithCandidateTypes(candidateTypes []CandidateType) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.candidateTypes = candidateTypes

		return nil
	}
}

func WithAutomaticRenomination(interval time.Duration) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.automaticRenomination = true
		if interval > 0 {
			a.renominationInterval = interval
		}

		return nil
	}
}

func WithInterfaceFilter(filter func(string) bool) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.interfaceFilter = filter

		return nil
	}
}

func WithLoggerFactory(loggerFactory logging.LoggerFactory) AgentOption {
	return func(a *Agent) error {
		if a.constructed {
			return ErrAgentOptionNotUpdatable
		}

		a.log = loggerFactory.NewLogger("ice")

		return nil
	}
}

func (a *Agent) GetCandidatePairsStats() []CandidatePairStats {
	var res []CandidatePairStats
	err := a.loop.Run(a.loop, func(_ context.Context) {
		result := make([]CandidatePairStats, 0, len(a.checklist))
		for _, cp := range a.checklist {
			stat := CandidatePairStats{
				Timestamp:                     time.Now(),
				LocalCandidateID:              cp.Local.ID(),
				RemoteCandidateID:             cp.Remote.ID(),
				State:                         cp.state,
				Nominated:                     cp.nominated,
				PacketsSent:                   cp.PacketsSent(),
				PacketsReceived:               cp.PacketsReceived(),
				BytesSent:                     cp.BytesSent(),
				BytesReceived:                 cp.BytesReceived(),
				LastPacketSentTimestamp:       cp.LastPacketSentAt(),
				LastPacketReceivedTimestamp:   cp.LastPacketReceivedAt(),
				FirstRequestTimestamp:         cp.FirstRequestSentAt(),
				LastRequestTimestamp:          cp.LastRequestSentAt(),
				FirstResponseTimestamp:        cp.FirstResponseReceivedAt(),
				LastResponseTimestamp:         cp.LastResponseReceivedAt(),
				FirstRequestReceivedTimestamp: cp.FirstRequestReceivedAt(),
				LastRequestReceivedTimestamp:  cp.LastRequestReceivedAt(),

				TotalRoundTripTime:   cp.TotalRoundTripTime(),
				CurrentRoundTripTime: cp.CurrentRoundTripTime(),

				RequestsReceived:  cp.RequestsReceived(),
				RequestsSent:      cp.RequestsSent(),
				ResponsesReceived: cp.ResponsesReceived(),
				ResponsesSent:     cp.ResponsesSent(),
			}
			result = append(result, stat)
		}
		res = result
	})
	if err != nil {
		a.log.Errorf("Failed to get candidate pairs stats: %v", err)

		return []CandidatePairStats{}
	}

	return res
}

func (a *Agent) GetSelectedCandidatePairStats() (CandidatePairStats, bool) {
	isAvailable := false
	var res CandidatePairStats
	err := a.loop.Run(a.loop, func(_ context.Context) {
		sp := a.getSelectedPair()
		if sp == nil {
			return
		}

		isAvailable = true
		res = CandidatePairStats{
			Timestamp:                   time.Now(),
			LocalCandidateID:            sp.Local.ID(),
			RemoteCandidateID:           sp.Remote.ID(),
			State:                       sp.state,
			Nominated:                   sp.nominated,
			PacketsSent:                 sp.PacketsSent(),
			PacketsReceived:             sp.PacketsReceived(),
			BytesSent:                   sp.BytesSent(),
			BytesReceived:               sp.BytesReceived(),
			LastPacketSentTimestamp:     sp.LastPacketSentAt(),
			LastPacketReceivedTimestamp: sp.LastPacketReceivedAt(),

			TotalRoundTripTime:   sp.TotalRoundTripTime(),
			CurrentRoundTripTime: sp.CurrentRoundTripTime(),

			ResponsesReceived: sp.ResponsesReceived(),
		}
	})
	if err != nil {
		a.log.Errorf("Failed to get selected candidate pair stats: %v", err)

		return CandidatePairStats{}, false
	}

	return res, isAvailable
}

func (a *Agent) GetLocalCandidatesStats() []CandidateStats {
	return a.getCandidatesStats(true)
}

func (a *Agent) GetRemoteCandidatesStats() []CandidateStats {
	return a.getCandidatesStats(false)
}

func (a *Agent) getCandidatesStats(isLocal bool) []CandidateStats {
	var res []CandidateStats
	err := a.loop.Run(a.loop, func(_ context.Context) {
		var candidateMap map[NetworkType][]Candidate
		if isLocal {
			candidateMap = a.localCandidates
		} else {
			candidateMap = a.remoteCandidates
		}

		result := make([]CandidateStats, 0, len(candidateMap))
		for networkType, candidate := range candidateMap {
			for _, cand := range candidate {
				relayProtocol := ""

				if isLocal && cand.Type() == CandidateTypeRelay {
					if cRelay, ok := cand.(*CandidateRelay); ok {
						relayProtocol = cRelay.RelayProtocol()
					}
				}

				stat := CandidateStats{
					Timestamp:     time.Now(),
					ID:            cand.ID(),
					NetworkType:   networkType,
					IP:            cand.Address(),
					Port:          cand.Port(),
					CandidateType: cand.Type(),
					Priority:      cand.Priority(),

					RelayProtocol: relayProtocol,
				}
				result = append(result, stat)
			}
		}
		res = result
	})
	if err != nil {
		a.log.Errorf("Failed to get candidate pair stats: %v", err)

		return []CandidateStats{}
	}

	return res
}

const (
	receiveMTU             = 8192
	defaultLocalPreference = 65535

	ComponentRTP uint16 = 1

	ComponentRTCP
)

type Candidate interface {
	Foundation() string
	ID() string
	Component() uint16
	SetComponent(uint16)
	LastReceived() time.Time
	LastSent() time.Time
	NetworkType() NetworkType
	Address() string
	Port() int
	Priority() uint32
	RelatedAddress() *CandidateRelatedAddress
	Extensions() []CandidateExtension
	GetExtension(key string) (value CandidateExtension, ok bool)
	AddExtension(extension CandidateExtension) error
	RemoveExtension(key string) (ok bool)
	String() string
	Type() CandidateType
	TCPType() TCPType
	Equal(other Candidate) bool
	DeepEqual(other Candidate) bool
	Marshal() string
	transportAddressEqual(other Candidate) bool
	addr() net.Addr
	filterForLocationTracking() bool
	agent() *Agent
	context() context.Context
	close() error
	copy() (Candidate, error)
	seen(outbound bool)
	start(a *Agent, conn net.PacketConn, initializedCh <-chan struct{})
	writeTo(raw []byte, dst Candidate) (int, error)
	replaceRemoteCandidateCacheValues(oldRemote, newRemote Candidate)
}

type candidateBase struct {
	id                    string
	networkType           NetworkType
	candidateType         CandidateType
	component             uint16
	address               string
	port                  int
	relatedAddress        *CandidateRelatedAddress
	tcpType               TCPType
	resolvedAddr          net.Addr
	lastSent              atomic.Int64
	lastReceived          atomic.Int64
	conn                  net.PacketConn
	currAgent             *Agent
	closeCh               chan struct{}
	closedCh              chan struct{}
	foundationOverride    string
	priorityOverride      uint32
	relayLocalPreference  uint16
	remoteCandidateCaches sync.Map
	isLocationTracked     bool
	extensions            []CandidateExtension
}

var timeRef = time.Now()

func getMonoNanos(t time.Time) int64 {
	return t.Sub(timeRef).Nanoseconds()
}

func getMonoTime(nanos int64) time.Time {
	return timeRef.Add(time.Duration(nanos))
}

func (c *candidateBase) Done() <-chan struct{} {
	return c.closeCh
}

func (c *candidateBase) Err() error {
	select {
	case <-c.closedCh:
		return ErrRunCanceled
	default:
		return nil
	}
}

func (c *candidateBase) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

func (c *candidateBase) Value(any) any {
	return nil
}

func (c *candidateBase) setWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return nil
	}

	return c.conn.SetWriteDeadline(t)
}

func (c *candidateBase) ID() string {
	return c.id
}

func (c *candidateBase) Foundation() string {
	if c.foundationOverride != "" {
		return c.foundationOverride
	}

	return fmt.Sprintf("%d", crc32.ChecksumIEEE([]byte(c.Type().String()+c.address+c.networkType.String())))
}

func (c *candidateBase) Address() string {
	return c.address
}

func (c *candidateBase) Port() int {
	return c.port
}

func (c *candidateBase) Type() CandidateType {
	return c.candidateType
}

func (c *candidateBase) NetworkType() NetworkType {
	return c.networkType
}

func (c *candidateBase) Component() uint16 {
	return c.component
}

func (c *candidateBase) SetComponent(component uint16) {
	c.component = component
}

func (c *candidateBase) LocalPreference() uint16 {
	if c.candidateType == CandidateTypeRelay {
		return c.relayLocalPreference
	}

	if c.NetworkType().IsTCP() {

		var otherPref uint16 = 8191

		directionPref := func() uint16 {
			switch c.Type() {
			case CandidateTypeHost, CandidateTypeRelay:
				switch c.tcpType {
				case TCPTypeActive:
					return 6
				case TCPTypePassive:
					return 4
				case TCPTypeSimultaneousOpen:
					return 2
				case TCPTypeUnspecified:
					return 0
				}
			case CandidateTypePeerReflexive, CandidateTypeServerReflexive:
				switch c.tcpType {
				case TCPTypeSimultaneousOpen:
					return 6
				case TCPTypeActive:
					return 4
				case TCPTypePassive:
					return 2
				case TCPTypeUnspecified:
					return 0
				}
			case CandidateTypeUnspecified:
				return 0
			}

			return 0
		}()

		return (1<<13)*directionPref + otherPref
	}

	return defaultLocalPreference
}

func (c *candidateBase) RelatedAddress() *CandidateRelatedAddress {
	return c.relatedAddress
}

func (c *candidateBase) TCPType() TCPType {
	return c.tcpType
}

func (c *candidateBase) start(a *Agent, conn net.PacketConn, initializedCh <-chan struct{}) {
	if c.conn != nil {
		c.agent().log.Warn("Can't start already started candidateBase")

		return
	}
	c.currAgent = a
	c.conn = conn
	c.closeCh = make(chan struct{})
	c.closedCh = make(chan struct{})

	go c.recvLoop(initializedCh)
}

var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, receiveMTU)

		return &buf
	},
}

func (c *candidateBase) recvLoop(initializedCh <-chan struct{}) {
	agent := c.agent()

	defer close(c.closedCh)

	select {
	case <-initializedCh:
	case <-c.closeCh:
		return
	}

	bufPtr, ok := bufferPool.Get().(*[]byte)
	if !ok {
		return
	}
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, srcAddr, err := c.conn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				agent.log.Warnf("Failed to read from candidate %s: %v", c, err)
			}

			return
		}

		c.handleInboundPacket(buf[:n], srcAddr)
	}
}

func (c *candidateBase) validateSTUNTrafficCache(addr net.Addr) bool {
	if candidate, ok := c.remoteCandidateCaches.Load(toAddrPort(addr)); ok {
		remoteCandidate, ok := candidate.(Candidate)
		if !ok {
			return false
		}

		remoteCandidate.seen(false)

		return true
	}

	return false
}

func (c *candidateBase) addRemoteCandidateCache(candidate Candidate, srcAddr net.Addr) {
	if c.validateSTUNTrafficCache(srcAddr) {
		return
	}
	c.remoteCandidateCaches.Store(toAddrPort(srcAddr), candidate)
}

func (c *candidateBase) replaceRemoteCandidateCacheValues(oldRemote, newRemote Candidate) {
	c.remoteCandidateCaches.Range(func(key, value any) bool {
		candidate, ok := value.(Candidate)
		if ok && candidate == oldRemote {
			c.remoteCandidateCaches.Store(key, newRemote)
		}

		return true
	})
}

func (c *candidateBase) handleInboundPacket(buf []byte, srcAddr net.Addr) {
	agent := c.agent()

	if stun.IsMessage(buf) {
		msg := &stun.Message{
			Raw: make([]byte, len(buf)),
		}

		copy(msg.Raw, buf)

		if err := msg.Decode(); err != nil {
			agent.log.Warnf("Failed to handle decode ICE from %s to %s: %v", c.addr(), srcAddr, err)

			return
		}

		if err := agent.loop.Run(c, func(_ context.Context) {

			agent.handleInbound(msg, c, srcAddr)
		}); err != nil {
			agent.log.Warnf("Failed to handle message: %v", err)
		}

		return
	}

	if !c.validateSTUNTrafficCache(srcAddr) {
		remoteCandidate, valid := agent.validateNonSTUNTraffic(c, srcAddr)
		if !valid {
			agent.log.Warnf("Discarded message from %s, not a valid remote candidate", c.addr())

			return
		}
		c.addRemoteCandidateCache(remoteCandidate, srcAddr)
	}

	n, err := agent.buf.Write(buf)
	if err != nil {
		agent.log.Warnf("Failed to write packet: %s", err)

		return
	}

	if n > 0 {
		if sp := agent.getSelectedPair(); sp != nil {
			sp.UpdatePacketReceived(n)
		}
	}
}

func (c *candidateBase) close() error {

	if c.Done() == nil {
		return nil
	}

	select {
	case <-c.Done():
		return nil
	default:
	}

	var firstErr error

	close(c.closeCh)
	if err := c.conn.SetDeadline(time.Now()); err != nil {
		firstErr = err
	}

	if err := c.conn.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	if firstErr != nil {
		return firstErr
	}

	<-c.closedCh

	return nil
}

func (c *candidateBase) writeTo(raw []byte, dst Candidate) (int, error) {
	n, err := c.conn.WriteTo(raw, dst.addr())
	if err != nil {

		if errors.Is(err, io.ErrClosedPipe) {
			return n, err
		}
		c.agent().log.Infof("Failed to send packet: %v", err)

		return n, nil
	}
	c.seen(true)

	return n, nil
}

func (c *candidateBase) TypePreference() uint16 {
	pref := c.Type().Preference()
	if pref == 0 {
		return 0
	}

	if c.NetworkType().IsTCP() {
		var tcpPriorityOffset uint16 = defaultTCPPriorityOffset
		if c.agent() != nil {
			tcpPriorityOffset = c.agent().tcpPriorityOffset
		}

		pref -= tcpPriorityOffset
	}

	return pref
}

func (c *candidateBase) Priority() uint32 {
	if c.priorityOverride != 0 {
		return c.priorityOverride
	}

	return (1<<24)*uint32(c.TypePreference()) +
		(1<<8)*uint32(c.LocalPreference()) +
		(1<<0)*uint32(256-c.Component())
}

func (c *candidateBase) transportAddressEqual(other Candidate) bool {
	if c.addr() != other.addr() {
		if c.addr() == nil || other.addr() == nil {
			return false
		}
		if !addrEqual(c.addr(), other.addr()) {
			return false
		}
	}

	return c.NetworkType() == other.NetworkType() &&
		c.Address() == other.Address() &&
		c.Port() == other.Port() &&
		c.TCPType() == other.TCPType()
}

func (c *candidateBase) Equal(other Candidate) bool {
	return c.transportAddressEqual(other) &&
		c.Type() == other.Type() &&
		c.RelatedAddress().Equal(other.RelatedAddress())
}

func (c *candidateBase) DeepEqual(other Candidate) bool {
	return c.Equal(other) && c.extensionsEqual(other.Extensions())
}

func (c *candidateBase) String() string {
	return fmt.Sprintf(
		"%s %s %s%s (resolved: %v)",
		c.NetworkType(),
		c.Type(),
		net.JoinHostPort(c.Address(), strconv.Itoa(c.Port())),
		c.relatedAddress,
		c.resolvedAddr,
	)
}

func (c *candidateBase) LastReceived() time.Time {
	if lastReceived := c.lastReceived.Load(); lastReceived != 0 {
		return getMonoTime(lastReceived)
	}

	return time.Time{}
}

func (c *candidateBase) setLastReceived(t time.Time) {
	c.lastReceived.Store(getMonoNanos(t))
}

func (c *candidateBase) LastSent() time.Time {
	if lastSent := c.lastSent.Load(); lastSent != 0 {
		return getMonoTime(lastSent)
	}

	return time.Time{}
}

func (c *candidateBase) setLastSent(t time.Time) {
	c.lastSent.Store(getMonoNanos(t))
}

func (c *candidateBase) seen(outbound bool) {
	if outbound {
		c.setLastSent(time.Now())
	} else {
		c.setLastReceived(time.Now())
	}
}

func (c *candidateBase) addr() net.Addr {
	return c.resolvedAddr
}

func (c *candidateBase) filterForLocationTracking() bool {
	return c.isLocationTracked
}

func (c *candidateBase) agent() *Agent {
	return c.currAgent
}

func (c *candidateBase) context() context.Context {
	return c
}

func (c *candidateBase) copy() (Candidate, error) {
	return UnmarshalCandidate(c.Marshal())
}

func removeZoneIDFromAddress(addr string) string {
	if before, _, ok := strings.Cut(addr, "%"); ok {
		return before
	}

	return addr
}

func (c *candidateBase) Marshal() string {
	val := c.Foundation()
	if val == " " {
		val = ""
	}

	val = fmt.Sprintf("%s %d %s %d %s %d typ %s",
		val,
		c.Component(),
		c.NetworkType().NetworkShort(),
		c.Priority(),
		removeZoneIDFromAddress(c.Address()),
		c.Port(),
		c.Type())

	if r := c.RelatedAddress(); r != nil && r.Address != "" && r.Port != 0 {
		val = fmt.Sprintf("%s raddr %s rport %d",
			val,
			r.Address,
			r.Port)
	}

	extensions := c.marshalExtensions()

	if extensions != "" {
		val = fmt.Sprintf("%s %s", val, extensions)
	}

	return val
}

type CandidateExtension struct {
	Key   string
	Value string
}

func (c *candidateBase) Extensions() []CandidateExtension {
	tcpType := c.TCPType()
	hasTCPType := 0
	if tcpType != TCPTypeUnspecified {
		hasTCPType = 1
	}

	extensions := make([]CandidateExtension, len(c.extensions)+hasTCPType)

	if hasTCPType == 1 {
		extensions[0] = CandidateExtension{
			Key:   "tcptype",
			Value: tcpType.String(),
		}
	}

	copy(extensions[hasTCPType:], c.extensions)

	return extensions
}

func (c *candidateBase) GetExtension(key string) (CandidateExtension, bool) {
	extension := CandidateExtension{Key: key}

	for i := range c.extensions {
		if c.extensions[i].Key == key {
			extension.Value = c.extensions[i].Value

			return extension, true
		}
	}

	if key == "tcptype" && c.TCPType() != TCPTypeUnspecified {
		extension.Value = c.TCPType().String()

		return extension, true
	}

	return extension, false
}

func (c *candidateBase) AddExtension(ext CandidateExtension) error {
	if ext.Key == "tcptype" {
		tcpType := NewTCPType(ext.Value)
		if tcpType == TCPTypeUnspecified {
			return fmt.Errorf("%w: invalid or unsupported TCPtype %s", errParseTCPType, ext.Value)
		}

		c.tcpType = tcpType

		return nil
	}

	if ext.Key == "" {
		return fmt.Errorf("%w: key is empty", errParseExtension)
	}

	for i := range c.extensions {
		if c.extensions[i].Key == ext.Key {
			c.extensions[i] = ext

			return nil
		}
	}

	c.extensions = append(c.extensions, ext)

	return nil
}

func (c *candidateBase) RemoveExtension(key string) (ok bool) {
	if key == "tcptype" {
		c.tcpType = TCPTypeUnspecified
		ok = true
	}

	for i := range c.extensions {
		if c.extensions[i].Key == key {
			c.extensions = append(c.extensions[:i], c.extensions[i+1:]...)
			ok = true

			break
		}
	}

	return ok
}

func (c *candidateBase) marshalExtensions() string {
	value := ""
	exts := c.Extensions()

	for i := range exts {
		if value != "" {
			value += " "
		}

		value += exts[i].Key + " " + exts[i].Value
	}

	return value
}

func (c *candidateBase) extensionsEqual(other []CandidateExtension) bool {
	freq1 := make(map[CandidateExtension]int)
	freq2 := make(map[CandidateExtension]int)

	if len(c.extensions) != len(other) {
		return false
	}

	if len(c.extensions) == 0 {
		return true
	}

	if len(c.extensions) == 1 {
		return c.extensions[0] == other[0]
	}

	for i := range c.extensions {
		freq1[c.extensions[i]]++
		freq2[other[i]]++
	}

	for k, v := range freq1 {
		if freq2[k] != v {
			return false
		}
	}

	return true
}

func (c *candidateBase) setExtensions(extensions []CandidateExtension) {
	c.extensions = extensions
}

func UnmarshalCandidate(raw string) (Candidate, error) {

	raw = strings.TrimPrefix(raw, "candidate:")

	pos := 0

	foundation, pos, err := readCandidateCharToken(raw, pos, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: %v in %s", errParseFoundation, err, raw)
	}

	if foundation == "" {
		foundation = " "
	}

	if pos >= len(raw) {
		return nil, fmt.Errorf("%w: expected component in %s", errAttributeTooShortICECandidate, raw)
	}

	component, pos, err := readCandidateDigitToken(raw, pos, 5)
	if err != nil {
		return nil, fmt.Errorf("%w: %v in %s", errParseComponent, err, raw)
	}

	if pos >= len(raw) {
		return nil, fmt.Errorf("%w: expected transport in %s", errAttributeTooShortICECandidate, raw)
	}

	protocol, pos := readCandidateStringToken(raw, pos)

	if pos >= len(raw) {
		return nil, fmt.Errorf("%w: expected priority in %s", errAttributeTooShortICECandidate, raw)
	}

	priority, pos, err := readCandidateDigitToken(raw, pos, 10)
	if err != nil {
		return nil, fmt.Errorf("%w: %v in %s", errParsePriority, err, raw)
	}

	if pos >= len(raw) {
		return nil, fmt.Errorf("%w: expected address in %s", errAttributeTooShortICECandidate, raw)
	}

	address, pos := readCandidateStringToken(raw, pos)

	address = removeZoneIDFromAddress(address)

	if pos >= len(raw) {
		return nil, fmt.Errorf("%w: expected port in %s", errAttributeTooShortICECandidate, raw)
	}

	port, pos, err := readCandidatePort(raw, pos)
	if err != nil {
		return nil, fmt.Errorf("%w: %v in %s", errParsePort, err, raw)
	}

	typeKey, pos := readCandidateStringToken(raw, pos)
	if typeKey != "typ" {
		return nil, fmt.Errorf("%w (%s)", ErrUnknownCandidateTyp, typeKey)
	}

	if pos >= len(raw) {
		return nil, fmt.Errorf("%w: expected candidate type in %s", errAttributeTooShortICECandidate, raw)
	}

	typ, pos := readCandidateStringToken(raw, pos)

	raddr, rport, pos, err := tryReadRelativeAddrs(raw, pos)
	if err != nil {
		return nil, err
	}

	tcpType := TCPTypeUnspecified
	var extensions []CandidateExtension
	var tcpTypeRaw string

	if pos < len(raw) {
		extensions, tcpTypeRaw, err = unmarshalCandidateExtensions(raw[pos:])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errParseExtension, err)
		}

		if tcpTypeRaw != "" {
			tcpType = NewTCPType(tcpTypeRaw)
			if tcpType == TCPTypeUnspecified {
				return nil, fmt.Errorf("%w: invalid or unsupported TCPtype %s", errParseTCPType, tcpTypeRaw)
			}
		}
	}

	switch typ {
	case "host":
		candidate, err := NewCandidateHost(&CandidateHostConfig{
			"",
			protocol,
			address,
			port,
			uint16(component),
			uint32(priority),
			foundation,
			tcpType,
			false,
		})
		if err != nil {
			return nil, err
		}

		candidate.setExtensions(extensions)

		return candidate, nil
	case "srflx":
		candidate, err := NewCandidateServerReflexive(&CandidateServerReflexiveConfig{
			"",
			protocol,
			address,
			port,
			uint16(component),
			uint32(priority),
			foundation,
			raddr,
			rport,
		})
		if err != nil {
			return nil, err
		}

		candidate.setExtensions(extensions)

		return candidate, nil
	case "prflx":
		candidate, err := NewCandidatePeerReflexive(&CandidatePeerReflexiveConfig{
			"",
			protocol,
			address,
			port,
			uint16(component),
			uint32(priority),
			foundation,
			raddr,
			rport,
		})
		if err != nil {
			return nil, err
		}

		candidate.setExtensions(extensions)

		return candidate, nil
	case "relay":
		candidate, err := NewCandidateRelay(&CandidateRelayConfig{
			"",
			protocol,
			address,
			port,
			uint16(component),
			uint32(priority),
			foundation,
			raddr,
			rport,
			"",
			nil,
		})
		if err != nil {
			return nil, err
		}

		candidate.setExtensions(extensions)

		return candidate, nil
	default:
		return nil, fmt.Errorf("%w (%s)", ErrUnknownCandidateTyp, typ)
	}
}

func readCandidateCharToken(raw string, start int, limit int) (string, int, error) {
	for i, char := range raw[start:] {
		if char == 0x20 {
			return raw[start : start+i], start + i + 1, nil
		}

		if i == limit {

			return "", 0, fmt.Errorf("token too long: %s expected 1x%d", raw[start:start+i], limit)
		}

		if (char < 'A' || char > 'Z') &&
			(char < 'a' || char > 'z') &&
			(char < '0' || char > '9') &&
			char != '+' && char != '/' {
			return "", 0, fmt.Errorf("invalid ice-char token: %c", char)
		}
	}

	return raw[start:], len(raw), nil
}

func readCandidateStringToken(raw string, start int) (string, int) {
	for i, char := range raw[start:] {
		if char == 0x20 {
			return raw[start : start+i], start + i + 1
		}
	}

	return raw[start:], len(raw)
}

func readCandidateDigitToken(raw string, start, limit int) (int, int, error) {
	var val int
	for i, char := range raw[start:] {
		if char == 0x20 {
			return val, start + i + 1, nil
		}

		if i == limit {

			return 0, 0, fmt.Errorf("token too long: %s expected 1x%d", raw[start:start+i], limit)
		}

		if char < '0' || char > '9' {
			return 0, 0, fmt.Errorf("invalid digit token: %c", char)
		}

		val = val*10 + int(char-'0')
	}

	return val, len(raw), nil
}

func readCandidatePort(raw string, start int) (int, int, error) {
	port, pos, err := readCandidateDigitToken(raw, start, 5)
	if err != nil {
		return 0, 0, err
	}

	if port > 65535 {
		return 0, 0, fmt.Errorf("invalid RFC 4566 port %d", port)
	}

	return port, pos, nil
}

func readCandidateByteString(raw string, start int) (string, int, error) {
	for i, char := range raw[start:] {
		if char == 0x20 {
			return raw[start : start+i], start + i + 1, nil
		}

		if (char < 0x01 || char > 0x09) &&
			(char < 0x0B || char > 0x0C) &&
			(char < 0x0E || char > 0xFF) {
			return "", 0, fmt.Errorf("invalid byte-string character: %c", char)
		}
	}

	return raw[start:], len(raw), nil
}

func tryReadRelativeAddrs(raw string, start int) (raddr string, rport, pos int, err error) {
	key, pos := readCandidateStringToken(raw, start)

	if key != "raddr" {
		return "", 0, start, nil
	}

	if pos >= len(raw) {
		return "", 0, 0, fmt.Errorf("%w: expected raddr value in %s", errParseRelatedAddr, raw)
	}

	raddr, pos = readCandidateStringToken(raw, pos)

	if pos >= len(raw) {
		return "", 0, 0, fmt.Errorf("%w: expected rport in %s", errParseRelatedAddr, raw)
	}

	key, pos = readCandidateStringToken(raw, pos)
	if key != "rport" {
		return "", 0, 0, fmt.Errorf("%w: expected rport in %s", errParseRelatedAddr, raw)
	}

	if pos >= len(raw) {
		return "", 0, 0, fmt.Errorf("%w: expected rport value in %s", errParseRelatedAddr, raw)
	}

	rport, pos, err = readCandidatePort(raw, pos)
	if err != nil {
		return "", 0, 0, fmt.Errorf("%w: %v", errParseRelatedAddr, err)
	}

	return raddr, rport, pos, nil
}

func unmarshalCandidateExtensions(raw string) (extensions []CandidateExtension, rawTCPTypeRaw string, err error) {
	extensions = make([]CandidateExtension, 0)

	if raw == "" {
		return extensions, "", nil
	}

	if raw[0] == 0x20 {
		return extensions, "", fmt.Errorf("%w: unexpected space %s", errParseExtension, raw)
	}

	for i := 0; i < len(raw); {
		key, next, err := readCandidateByteString(raw, i)
		if err != nil {
			return extensions, "", fmt.Errorf(
				"%w: failed to read key %v", errParseExtension, err,
			)
		}
		i = next

		var value string
		if i < len(raw) {
			value, next, err = readCandidateByteString(raw, i)
			if err != nil {
				return extensions, "", fmt.Errorf(
					"%w: failed to read value %v", errParseExtension, err,
				)
			}
			i = next
		}

		if key == "tcptype" {
			rawTCPTypeRaw = value

			continue
		}

		extensions = append(extensions, CandidateExtension{key, value})
	}

	return extensions, rawTCPTypeRaw, nil
}

type CandidateHost struct {
	candidateBase
	network string
}

type CandidateHostConfig struct {
	CandidateID       string
	Network           string
	Address           string
	Port              int
	Component         uint16
	Priority          uint32
	Foundation        string
	TCPType           TCPType
	IsLocationTracked bool
}

func NewCandidateHost(config *CandidateHostConfig) (*CandidateHost, error) {
	candidateID := config.CandidateID

	if candidateID == "" {
		candidateID = globalCandidateIDGenerator.Generate()
	}

	candidateHost := &CandidateHost{
		candidateBase: candidateBase{
			id:                 candidateID,
			address:            config.Address,
			candidateType:      CandidateTypeHost,
			component:          config.Component,
			port:               config.Port,
			tcpType:            config.TCPType,
			foundationOverride: config.Foundation,
			priorityOverride:   config.Priority,
			isLocationTracked:  config.IsLocationTracked,
		},
		network: config.Network,
	}

	if !strings.HasSuffix(config.Address, ".local") && !strings.HasSuffix(config.Address, ".invalid") {
		ipAddr, err := netip.ParseAddr(config.Address)
		if err != nil {
			return nil, err
		}

		if err := candidateHost.setIPAddr(ipAddr); err != nil {
			return nil, err
		}
	} else {

		candidateHost.candidateBase.networkType = NetworkTypeUDP4
	}

	return candidateHost, nil
}

func (c *CandidateHost) setIPAddr(addr netip.Addr) error {
	networkType, err := determineNetworkType(c.network, addr)
	if err != nil {
		return err
	}

	c.candidateBase.networkType = networkType
	c.candidateBase.resolvedAddr = createAddr(networkType, addr, c.port)

	return nil
}

type CandidatePeerReflexive struct {
	candidateBase
}

type CandidatePeerReflexiveConfig struct {
	CandidateID string
	Network     string
	Address     string
	Port        int
	Component   uint16
	Priority    uint32
	Foundation  string
	RelAddr     string
	RelPort     int
}

func NewCandidatePeerReflexive(config *CandidatePeerReflexiveConfig) (*CandidatePeerReflexive, error) {
	ipAddr, err := netip.ParseAddr(config.Address)
	if err != nil {
		return nil, err
	}

	networkType, err := determineNetworkType(config.Network, ipAddr)
	if err != nil {
		return nil, err
	}

	candidateID := config.CandidateID
	if candidateID == "" {
		candidateID = globalCandidateIDGenerator.Generate()
	}

	return &CandidatePeerReflexive{
		candidateBase: candidateBase{
			id:                 candidateID,
			networkType:        networkType,
			candidateType:      CandidateTypePeerReflexive,
			address:            config.Address,
			port:               config.Port,
			resolvedAddr:       createAddr(networkType, ipAddr, config.Port),
			component:          config.Component,
			foundationOverride: config.Foundation,
			priorityOverride:   config.Priority,
			relatedAddress: &CandidateRelatedAddress{
				Address: config.RelAddr,
				Port:    config.RelPort,
			},
		},
	}, nil
}

const (
	preferenceRelayTLS  = 0
	preferenceRelayTCP  = 1
	preferenceRelayDTLS = 2
	preferenceRelayUDP  = 3
)

type CandidateRelay struct {
	candidateBase
	relayProtocol string
	onClose       func() error
}

type CandidateRelayConfig struct {
	CandidateID   string
	Network       string
	Address       string
	Port          int
	Component     uint16
	Priority      uint32
	Foundation    string
	RelAddr       string
	RelPort       int
	RelayProtocol string
	OnClose       func() error
}

func NewCandidateRelay(config *CandidateRelayConfig) (*CandidateRelay, error) {
	candidateID := config.CandidateID

	if candidateID == "" {
		candidateID = globalCandidateIDGenerator.Generate()
	}

	ipAddr, err := netip.ParseAddr(config.Address)
	if err != nil {
		return nil, err
	}

	networkType, err := determineNetworkType(config.Network, ipAddr)
	if err != nil {
		return nil, err
	}

	return &CandidateRelay{
		candidateBase: candidateBase{
			id:            candidateID,
			networkType:   networkType,
			candidateType: CandidateTypeRelay,
			address:       config.Address,
			port:          config.Port,
			resolvedAddr: &net.UDPAddr{
				IP:   ipAddr.AsSlice(),
				Port: config.Port,
				Zone: ipAddr.Zone(),
			},
			component:          config.Component,
			foundationOverride: config.Foundation,
			priorityOverride:   config.Priority,
			relatedAddress: &CandidateRelatedAddress{
				Address: config.RelAddr,
				Port:    config.RelPort,
			},
			relayLocalPreference: relayProtocolPreference(config.RelayProtocol),
		},
		relayProtocol: config.RelayProtocol,
		onClose:       config.OnClose,
	}, nil
}

func (c *CandidateRelay) RelayProtocol() string {
	return c.relayProtocol
}

func (c *CandidateRelay) close() error {
	err := c.candidateBase.close()
	if c.onClose != nil {
		err = c.onClose()
		c.onClose = nil
	}

	return err
}

func (c *CandidateRelay) copy() (Candidate, error) {
	cc, err := c.candidateBase.copy()
	if err != nil {
		return nil, err
	}

	if ccr, ok := cc.(*CandidateRelay); ok {
		ccr.relayProtocol = c.relayProtocol
	}

	return cc, nil
}

func relayProtocolPreference(relayProtocol string) uint16 {
	switch relayProtocol {
	case relayProtocolTLS:
		return preferenceRelayTLS
	case tcp:
		return preferenceRelayTCP
	case relayProtocolDTLS:
		return preferenceRelayDTLS
	default:
		return preferenceRelayUDP
	}
}

type CandidateServerReflexive struct {
	candidateBase
}

type CandidateServerReflexiveConfig struct {
	CandidateID string
	Network     string
	Address     string
	Port        int
	Component   uint16
	Priority    uint32
	Foundation  string
	RelAddr     string
	RelPort     int
}

func NewCandidateServerReflexive(config *CandidateServerReflexiveConfig) (*CandidateServerReflexive, error) {
	ipAddr, err := netip.ParseAddr(config.Address)
	if err != nil {
		return nil, err
	}

	networkType, err := determineNetworkType(config.Network, ipAddr)
	if err != nil {
		return nil, err
	}

	candidateID := config.CandidateID
	if candidateID == "" {
		candidateID = globalCandidateIDGenerator.Generate()
	}

	return &CandidateServerReflexive{
		candidateBase: candidateBase{
			id:            candidateID,
			networkType:   networkType,
			candidateType: CandidateTypeServerReflexive,
			address:       config.Address,
			port:          config.Port,
			resolvedAddr: &net.UDPAddr{
				IP:   ipAddr.AsSlice(),
				Port: config.Port,
				Zone: ipAddr.Zone(),
			},
			component:          config.Component,
			foundationOverride: config.Foundation,
			priorityOverride:   config.Priority,
			relatedAddress: &CandidateRelatedAddress{
				Address: config.RelAddr,
				Port:    config.RelPort,
			},
		},
	}, nil
}

func newCandidatePair(local, remote Candidate, controlling bool) *CandidatePair {
	return &CandidatePair{
		iceRoleControlling: controlling,
		Remote:             remote,
		Local:              local,
		state:              CandidatePairStateWaiting,
	}
}

type CandidatePair struct {
	id                       uint64
	iceRoleControlling       bool
	Remote                   Candidate
	Local                    Candidate
	priorityOverride         uint64
	hasPriorityOverride      bool
	bindingRequestCount      uint16
	state                    CandidatePairState
	nominated                bool
	nominateOnBindingSuccess bool
	currentRoundTripTime     int64
	totalRoundTripTime       int64
	packetsSent              uint32
	packetsReceived          uint32
	bytesSent                uint64
	bytesReceived            uint64
	lastPacketSentAt         atomic.Value
	lastPacketReceivedAt     atomic.Value
	requestsReceived         uint64
	requestsSent             uint64
	responsesReceived        uint64
	responsesSent            uint64
	firstRequestSentAt       atomic.Value
	lastRequestSentAt        atomic.Value
	firstResponseReceivedAt  atomic.Value
	lastResponseReceivedAt   atomic.Value
	firstRequestReceivedAt   atomic.Value
	lastRequestReceivedAt    atomic.Value
}

func (p *CandidatePair) String() string {
	if p == nil {
		return ""
	}

	return fmt.Sprintf(
		"prio %d (local, prio %d) %s <-> %s (remote, prio %d), state: %s, nominated: %v, nominateOnBindingSuccess: %v",
		p.priority(),
		p.Local.Priority(),
		p.Local,
		p.Remote,
		p.Remote.Priority(),
		p.state,
		p.nominated,
		p.nominateOnBindingSuccess,
	)
}

func (p *CandidatePair) equal(other *CandidatePair) bool {
	if p == nil && other == nil {
		return true
	}
	if p == nil || other == nil {
		return false
	}

	return p.Local.Equal(other.Local) && p.Remote.Equal(other.Remote)
}

func (p *CandidatePair) setPriorityOverride(prio uint64) {
	p.priorityOverride = prio
	p.hasPriorityOverride = true
}

func (p *CandidatePair) priority() uint64 {
	if p.hasPriorityOverride {
		return p.priorityOverride
	}

	var g, d uint32
	if p.iceRoleControlling {
		g = p.Local.Priority()
		d = p.Remote.Priority()
	} else {
		g = p.Remote.Priority()
		d = p.Local.Priority()
	}

	localMin := func(x, y uint32) uint64 {
		if x < y {
			return uint64(x)
		}

		return uint64(y)
	}
	localMax := func(x, y uint32) uint64 {
		if x > y {
			return uint64(x)
		}

		return uint64(y)
	}
	cmp := func(x, y uint32) uint64 {
		if x > y {
			return uint64(1)
		}

		return uint64(0)
	}

	return (1<<32-1)*localMin(g, d) + 2*localMax(g, d) + cmp(g, d)
}

func (p *CandidatePair) Write(b []byte) (int, error) {
	return p.Local.writeTo(b, p.Remote)
}

func (a *Agent) sendSTUN(msg *stun.Message, local, remote Candidate) {
	_, err := local.writeTo(msg.Raw, remote)
	if err != nil {
		a.log.Tracef("Failed to send STUN message: %s", err)
	}
}

func (p *CandidatePair) UpdateRoundTripTime(rtt time.Duration) {
	rttNs := rtt.Nanoseconds()
	atomic.StoreInt64(&p.currentRoundTripTime, rttNs)
	atomic.AddInt64(&p.totalRoundTripTime, rttNs)
	atomic.AddUint64(&p.responsesReceived, 1)

	now := time.Now()
	p.firstResponseReceivedAt.CompareAndSwap(nil, now)
	p.lastResponseReceivedAt.Store(now)
}

func (p *CandidatePair) CurrentRoundTripTime() float64 {
	return time.Duration(atomic.LoadInt64(&p.currentRoundTripTime)).Seconds()
}

func (p *CandidatePair) TotalRoundTripTime() float64 {
	return time.Duration(atomic.LoadInt64(&p.totalRoundTripTime)).Seconds()
}

func (p *CandidatePair) RequestsReceived() uint64 {
	return atomic.LoadUint64(&p.requestsReceived)
}

func (p *CandidatePair) RequestsSent() uint64 {
	return atomic.LoadUint64(&p.requestsSent)
}

func (p *CandidatePair) ResponsesReceived() uint64 {
	return atomic.LoadUint64(&p.responsesReceived)
}

func (p *CandidatePair) ResponsesSent() uint64 {
	return atomic.LoadUint64(&p.responsesSent)
}

func (p *CandidatePair) PacketsSent() uint32 {
	return atomic.LoadUint32(&p.packetsSent)
}

func (p *CandidatePair) PacketsReceived() uint32 {
	return atomic.LoadUint32(&p.packetsReceived)
}

func (p *CandidatePair) BytesSent() uint64 {
	return atomic.LoadUint64(&p.bytesSent)
}

func (p *CandidatePair) BytesReceived() uint64 {
	return atomic.LoadUint64(&p.bytesReceived)
}

func (p *CandidatePair) LastPacketSentAt() time.Time {
	if v, ok := p.lastPacketSentAt.Load().(time.Time); ok {
		return v
	}

	return time.Time{}
}

func (p *CandidatePair) LastPacketReceivedAt() time.Time {
	if v, ok := p.lastPacketReceivedAt.Load().(time.Time); ok {
		return v
	}

	return time.Time{}
}

func (p *CandidatePair) UpdatePacketSent(n int) {
	if n <= 0 {
		return
	}

	atomic.AddUint32(&p.packetsSent, 1)
	atomic.AddUint64(&p.bytesSent, uint64(n))
	p.lastPacketSentAt.Store(time.Now())
}

func (p *CandidatePair) UpdatePacketReceived(n int) {
	if n <= 0 {
		return
	}

	atomic.AddUint32(&p.packetsReceived, 1)
	atomic.AddUint64(&p.bytesReceived, uint64(n))
	p.lastPacketReceivedAt.Store(time.Now())
}

func (p *CandidatePair) FirstRequestSentAt() time.Time {
	if v, ok := p.firstRequestSentAt.Load().(time.Time); ok {
		return v
	}

	return time.Time{}
}

func (p *CandidatePair) LastRequestSentAt() time.Time {
	if v, ok := p.lastRequestSentAt.Load().(time.Time); ok {
		return v
	}

	return time.Time{}
}

func (p *CandidatePair) FirstReponseReceivedAt() time.Time {
	return p.FirstResponseReceivedAt()
}

func (p *CandidatePair) FirstResponseReceivedAt() time.Time {
	if v, ok := p.firstResponseReceivedAt.Load().(time.Time); ok {
		return v
	}

	return time.Time{}
}

func (p *CandidatePair) LastResponseReceivedAt() time.Time {
	if v, ok := p.lastResponseReceivedAt.Load().(time.Time); ok {
		return v
	}

	return time.Time{}
}

func (p *CandidatePair) FirstRequestReceivedAt() time.Time {
	if v, ok := p.firstRequestReceivedAt.Load().(time.Time); ok {
		return v
	}

	return time.Time{}
}

func (p *CandidatePair) LastRequestReceivedAt() time.Time {
	if v, ok := p.lastRequestReceivedAt.Load().(time.Time); ok {
		return v
	}

	return time.Time{}
}

func (p *CandidatePair) UpdateRequestSent() {
	atomic.AddUint64(&p.requestsSent, 1)
	now := time.Now()
	p.firstRequestSentAt.CompareAndSwap(nil, now)
	p.lastRequestSentAt.Store(now)
}

func (p *CandidatePair) UpdateResponseSent() {
	atomic.AddUint64(&p.responsesSent, 1)
}

func (p *CandidatePair) UpdateRequestReceived() {
	atomic.AddUint64(&p.requestsReceived, 1)
	now := time.Now()
	p.firstRequestReceivedAt.CompareAndSwap(nil, now)
	p.lastRequestReceivedAt.Store(now)
}

func (p *CandidatePair) ID() uint64 {
	return p.id
}

type CandidatePairState int

const (
	CandidatePairStateWaiting CandidatePairState = iota + 1

	CandidatePairStateInProgress

	CandidatePairStateFailed

	CandidatePairStateSucceeded
)

func (c CandidatePairState) String() string {
	switch c {
	case CandidatePairStateWaiting:
		return "waiting"
	case CandidatePairStateInProgress:
		return "in-progress"
	case CandidatePairStateFailed:
		return "failed"
	case CandidatePairStateSucceeded:
		return "succeeded"
	}

	return "Unknown candidate pair state"
}

type CandidateRelatedAddress struct {
	Address string
	Port    int
}

func (c *CandidateRelatedAddress) String() string {
	if c == nil {
		return ""
	}

	return fmt.Sprintf(" related %s:%d", c.Address, c.Port)
}

func (c *CandidateRelatedAddress) Equal(other *CandidateRelatedAddress) bool {
	if c == nil && other == nil {
		return true
	}

	return c != nil && other != nil &&
		c.Address == other.Address &&
		c.Port == other.Port
}

type CandidateType byte

const (
	CandidateTypeUnspecified CandidateType = iota
	CandidateTypeHost
	CandidateTypeServerReflexive
	CandidateTypePeerReflexive
	CandidateTypeRelay
)

func (c CandidateType) String() string {
	switch c {
	case CandidateTypeHost:
		return "host"
	case CandidateTypeServerReflexive:
		return "srflx"
	case CandidateTypePeerReflexive:
		return "prflx"
	case CandidateTypeRelay:
		return "relay"
	case CandidateTypeUnspecified:
		return "Unknown candidate type"
	}

	return "Unknown candidate type"
}

func (c CandidateType) Preference() uint16 {
	switch c {
	case CandidateTypeHost:
		return 126
	case CandidateTypePeerReflexive:
		return 110
	case CandidateTypeServerReflexive:
		return 100
	case CandidateTypeRelay, CandidateTypeUnspecified:
		return 0
	}

	return 0
}

func containsCandidateType(candidateType CandidateType, candidateTypeList []CandidateType) bool {
	if candidateTypeList == nil {
		return false
	}

	return slices.Contains(candidateTypeList, candidateType)
}

var (
	ErrUnknownType = errors.New("Unknown")

	ErrSchemeType = errors.New("unknown scheme type")

	ErrSTUNQuery = errors.New("queries not supported in STUN address")

	ErrInvalidQuery = errors.New("invalid query")

	ErrHost = errors.New("invalid hostname")

	ErrPort = errors.New("invalid port")

	ErrLocalUfragInsufficientBits = errors.New("local username fragment is less than 24 bits long")

	ErrLocalPwdInsufficientBits = errors.New("local password is less than 128 bits long")

	ErrProtoType = errors.New("invalid transport protocol type")

	ErrClosed = taskloop.ErrClosed

	ErrNoCandidatePairs = errors.New("no candidate pairs available")

	ErrCanceledByCaller = errors.New("connecting canceled by caller")

	ErrMultipleStart = errors.New("attempted to start agent twice")

	ErrRemoteUfragEmpty = errors.New("remote ufrag is empty")

	ErrRemotePwdEmpty = errors.New("remote pwd is empty")

	ErrNoOnCandidateHandler = errors.New("no OnCandidate provided")

	ErrMultipleGatherAttempted = errors.New("attempting to gather candidates during gathering state")

	ErrUsernameEmpty = errors.New("username is empty")

	ErrPasswordEmpty = errors.New("password is empty")

	ErrAddressParseFailed = errors.New("failed to parse address")

	ErrLiteUsingNonHostCandidates = errors.New("lite agents must only use host candidates")

	ErrUselessUrlsProvided = errors.New("agent does not need URL with selected candidate types")

	ErrUnsupportedNAT1To1IPCandidateType = errors.New("unsupported address rewrite candidate type")

	ErrUnsupportedAddressRewriteCandidateType = ErrUnsupportedNAT1To1IPCandidateType

	ErrInvalidNAT1To1IPMapping = errors.New("invalid address rewrite mapping")

	ErrInvalidAddressRewriteMapping = ErrInvalidNAT1To1IPMapping

	ErrExternalMappedIPNotFound = errors.New("external mapped IP not found")

	ErrMulticastDNSWithNAT1To1IPMapping = errors.New(
		"mDNS gathering cannot be used with address rewrite for host candidate",
	)

	ErrMulticastDNSWithAddressRewrite = ErrMulticastDNSWithNAT1To1IPMapping

	ErrIneffectiveNAT1To1IPMappingHost = errors.New("address rewrite for host candidate ineffective")

	ErrIneffectiveAddressRewriteHost = ErrIneffectiveNAT1To1IPMappingHost

	ErrIneffectiveNAT1To1IPMappingSrflx = errors.New("address rewrite for srflx candidate ineffective")

	ErrIneffectiveAddressRewriteSrflx = ErrIneffectiveNAT1To1IPMappingSrflx

	ErrInvalidMulticastDNSHostName = errors.New(
		"invalid mDNS HostName, must end with .local and can only contain a single '.'",
	)

	ErrRunCanceled = errors.New("run was canceled by done")

	ErrTCPRemoteAddrAlreadyExists = errors.New("conn with same remote addr already exists")

	ErrUnknownCandidateTyp = errors.New("unknown candidate typ")

	ErrDetermineNetworkType = errors.New("unable to determine networkType")

	ErrOnlyControllingAgentCanRenominate = errors.New("only controlling agent can renominate")

	ErrRenominationNotEnabled = errors.New("renomination is not enabled")

	ErrCandidatePairNotFound = errors.New("candidate pair not found")

	ErrCandidatePairNotSucceeded = errors.New("candidate pair not in succeeded state")

	ErrInvalidNominationAttribute = errors.New("invalid nomination attribute type")

	ErrInvalidNominationValueGenerator = errors.New("nomination value generator cannot be nil")

	ErrInvalidNetworkMonitorInterval = errors.New("network monitor interval must be greater than 0")

	ErrAgentOptionNotUpdatable = errors.New("option can only be set during agent construction")

	errAttributeTooShortICECandidate = errors.New("attribute not long enough to be ICE candidate")
	errGetXorMappedAddrResponse      = errors.New("failed to get XOR-MAPPED-ADDRESS response")
	errInvalidAddress                = errors.New("invalid address")
	errNotImplemented                = errors.New("not implemented yet")
	errNoXorAddrMapping              = errors.New("no address mapping")
	errParseFoundation               = errors.New("failed to parse foundation")
	errParseComponent                = errors.New("failed to parse component")
	errParsePort                     = errors.New("failed to parse port")
	errParsePriority                 = errors.New("failed to parse priority")
	errParseRelatedAddr              = errors.New("failed to parse related addresses")
	errParseExtension                = errors.New("failed to parse extension")
	errParseTCPType                  = errors.New("failed to parse TCP type")
	errUDPMuxDisabled                = errors.New("UDPMux is not enabled")
	errUnknownRole                   = errors.New("unknown role")
	errWriteSTUNMessage              = errors.New("failed to send STUN message")
	errWriteSTUNMessageToIceConn     = errors.New("failed to write STUN message to ICE connection")
	errXORMappedAddrTimeout          = errors.New("timeout while waiting for XORMappedAddr")
	errFailedToCastUDPAddr           = errors.New("failed to cast net.Addr to net.UDPAddr")
	errInvalidIPAddress              = errors.New("invalid ip address")
)

var errInvalidNAT1To1IPMapping = errors.New("invalid NAT1To1 IP mapping")

type AddressRewriteMode int

const (
	addressRewriteModeUnspecified AddressRewriteMode = iota
	AddressRewriteReplace
	AddressRewriteAppend
)

type AddressRewriteRule struct {
	External        []string
	Local           string
	Iface           string
	CIDR            string
	AsCandidateType CandidateType
	Mode            AddressRewriteMode
	Networks        []NetworkType
}

func validateIPString(ipStr string) (net.IP, bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, false, fmt.Errorf("%w: %s", errInvalidNAT1To1IPMapping, ipStr)
	}
	return ip, strings.Contains(ipStr, ":"), nil
}

type addressRewriteMapper struct{}

func (m *addressRewriteMapper) hasCandidateType(_ CandidateType) bool { return false }

func (m *addressRewriteMapper) shouldReplace(_ CandidateType) bool { return false }

func (m *addressRewriteMapper) findExternalIPs(_ CandidateType, _, _ string) ([]net.IP, bool, AddressRewriteMode, error) {
	return nil, false, addressRewriteModeUnspecified, nil
}

type turnClient interface {
	Listen() error
	Allocate() (net.PacketConn, error)
	Close()
}

type TURNClientConfig struct{}

func defaultTurnClient(_ *TURNClientConfig) (turnClient, error) {
	return nil, io.EOF
}

func configuredNetworkTypes(networkTypes []NetworkType) []NetworkType {
	if len(networkTypes) == 0 {
		return supportedNetworkTypes()
	}

	return networkTypes
}

func effectiveURLProtoType(url stun.URI) stun.ProtoType {
	if url.Proto != stun.ProtoTypeUnknown {
		return url.Proto
	}

	switch url.Scheme {
	case stun.SchemeTypeSTUN, stun.SchemeTypeTURN:
		return stun.ProtoTypeUDP
	case stun.SchemeTypeSTUNS, stun.SchemeTypeTURNS:
		return stun.ProtoTypeTCP
	default:
		return stun.ProtoTypeUnknown
	}
}

func urlSupportsSrflxGathering(url stun.URI) bool {
	if effectiveURLProtoType(url) != stun.ProtoTypeUDP {
		return false
	}

	return url.Scheme == stun.SchemeTypeSTUN || url.Scheme == stun.SchemeTypeTURN
}

func closeConnAndLog(c io.Closer, log logging.LeveledLogger, msg string, args ...any) {
	if c == nil || (reflect.ValueOf(c).Kind() == reflect.Ptr && reflect.ValueOf(c).IsNil()) {
		log.Warnf("Connection is not allocated: "+msg, args...)

		return
	}

	log.Warnf(msg, args...)
	if err := c.Close(); err != nil {
		log.Warnf("Failed to close connection: %v", err)
	}
}

func (a *Agent) GatherCandidates() error {
	var gatherErr error

	if runErr := a.loop.Run(a.loop, func(ctx context.Context) {
		if a.gatheringState != GatheringStateNew {
			gatherErr = ErrMultipleGatherAttempted

			return
		} else if a.onCandidateHdlr.Load() == nil {
			gatherErr = ErrNoOnCandidateHandler

			return
		}

		a.gatherCandidateCancel()
		ctx, cancel := context.WithCancel(ctx)
		a.gatherCandidateCancel = cancel
		done := make(chan struct{})
		a.gatherCandidateDone = done

		go a.gatherCandidates(ctx, done)
	}); runErr != nil {
		return runErr
	}

	return gatherErr
}

func (a *Agent) gatherCandidates(ctx context.Context, done chan struct{}) {
	defer close(done)
	if err := a.setGatheringState(GatheringStateGathering); err != nil {
		a.log.Warnf("Failed to set gatheringState to GatheringStateGathering: %v", err)

		return
	}

	a.gatherCandidatesInternal(ctx)

	switch a.continualGatheringPolicy {
	case GatherOnce:
		if err := a.setGatheringState(GatheringStateComplete); err != nil {
			a.log.Warnf("Failed to set gatheringState to GatheringStateComplete: %v", err)
		}
	case GatherContinually:

		_, addrs, err := localInterfaces(
			a.net,
			a.interfaceFilter,
			a.ipFilter,
			a.networkTypes,
			a.includeLoopback,
		)
		if err != nil {
			a.log.Warnf("Failed to get initial interfaces for monitoring: %v", err)
		} else {
			for _, info := range addrs {
				a.lastKnownInterfaces[info.addr.String()] = info.addr
			}
			a.log.Infof("Initialized network monitoring with %d IP addresses", len(addrs))
		}
		go a.startNetworkMonitoring(ctx)
	}
}

func (a *Agent) shouldRewriteCandidateType(candidateType CandidateType) bool {
	return a.addressRewriteMapper != nil && a.addressRewriteMapper.hasCandidateType(candidateType)
}

func (a *Agent) shouldRewriteHostCandidates() bool {
	return a.mDNSMode != MulticastDNSModeQueryAndGather && a.shouldRewriteCandidateType(CandidateTypeHost)
}

func (a *Agent) applyHostAddressRewrite(addr netip.Addr, mappedAddrs []netip.Addr, iface string) ([]netip.Addr, bool) {
	mappedIPs, matched, mode, innerErr := a.addressRewriteMapper.findExternalIPs(
		CandidateTypeHost,
		addr.String(),
		iface,
	)
	if innerErr != nil {
		a.log.Warnf("Address rewrite mapping is enabled but no external IP is found for %s", addr.String())

		return mappedAddrs, true
	}
	if !matched {
		return mappedAddrs, true
	}

	if mode == AddressRewriteReplace {
		mappedAddrs = mappedAddrs[:0]
	}
	mappedAddrs = appendHostMappedAddrs(mappedAddrs, mappedIPs, addr, a.log)
	if len(mappedAddrs) == 0 && mode == AddressRewriteReplace {
		a.log.Warnf("Address rewrite mapping is enabled but produced no usable external IP for %s", addr.String())

		return mappedAddrs, false
	}

	return mappedAddrs, true
}

func appendHostMappedAddrs(
	mappedAddrs []netip.Addr,
	mappedIPs []net.IP,
	addr netip.Addr,
	log logging.LeveledLogger,
) []netip.Addr {
	for _, mappedIP := range mappedIPs {
		conv, ok := netip.AddrFromSlice(mappedIP)
		if !ok {
			log.Warnf("failed to convert mapped external IP to netip.Addr'%s'", addr.String())

			continue
		}

		mappedAddrs = append(mappedAddrs, conv.Unmap())
	}

	return mappedAddrs
}

func (a *Agent) applyHostRewriteForUDPMux(candidateIPs []net.IP, udpAddr *net.UDPAddr) ([]net.IP, bool) {
	mappedIPs, matched, mode, err := a.addressRewriteMapper.findExternalIPs(CandidateTypeHost, udpAddr.IP.String(), "")
	if err != nil {
		a.log.Warnf("Address rewrite mapping is enabled but failed for %s: %v", udpAddr.IP.String(), err)

		return candidateIPs, false
	}
	if !matched {
		return candidateIPs, true
	}
	if len(mappedIPs) == 0 {
		if mode == AddressRewriteReplace {
			return candidateIPs, false
		}

		return candidateIPs, true
	}
	if mode == AddressRewriteReplace {
		candidateIPs = candidateIPs[:0]
	}

	return append(candidateIPs, mappedIPs...), true
}

func (a *Agent) gatherCandidatesInternal(ctx context.Context) {
	var wg sync.WaitGroup
	for _, t := range a.candidateTypes {
		switch t {
		case CandidateTypeHost:
			wg.Add(1)
			go func() {
				a.gatherCandidatesLocal(ctx, a.networkTypes)
				wg.Done()
			}()
		case CandidateTypeServerReflexive:
			a.gatherServerReflexiveCandidates(ctx, &wg)
		case CandidateTypeRelay:
			wg.Add(1)
			go func() {
				a.gatherCandidatesRelay(ctx, a.urls)
				wg.Done()
			}()
		case CandidateTypePeerReflexive, CandidateTypeUnspecified:
		}
	}

	wg.Wait()
}

func (a *Agent) gatherServerReflexiveCandidates(ctx context.Context, wg *sync.WaitGroup) {
	replaceSrflx := a.addressRewriteMapper != nil && a.addressRewriteMapper.shouldReplace(CandidateTypeServerReflexive)
	if !replaceSrflx {
		wg.Add(1)
		go func() {
			if a.udpMuxSrflx != nil {
				a.gatherCandidatesSrflxUDPMux(ctx, a.urls, a.networkTypes)
			} else {
				a.gatherCandidatesSrflx(ctx, a.urls, a.networkTypes)
			}
			wg.Done()
		}()
	}
	if a.addressRewriteMapper != nil && a.addressRewriteMapper.hasCandidateType(CandidateTypeServerReflexive) {
		wg.Add(1)
		go func() {
			a.gatherCandidatesSrflxMapped(ctx, a.networkTypes)
			wg.Done()
		}()
	}
}

func (a *Agent) gatherCandidatesLocal(ctx context.Context, networkTypes []NetworkType) {
	networks := map[string]struct{}{}
	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			networks[tcp] = struct{}{}
		} else {
			networks[udp] = struct{}{}
		}
	}

	if a.udpMux != nil {
		if err := a.gatherCandidatesLocalUDPMux(ctx); err != nil {
			a.log.Warnf("Failed to create host candidate for UDPMux: %s", err)
		}
		delete(networks, udp)
	}

	_, localAddrs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, networkTypes, a.includeLoopback)
	if err != nil {
		a.log.Warnf("Failed to iterate local interfaces, host candidates will not be gathered %s", err)

		return
	}

	for _, info := range localAddrs {
		addr := info.addr
		ifaceName := info.iface
		mappedAddrs := []netip.Addr{addr}
		if a.shouldRewriteHostCandidates() {
			var ok bool
			mappedAddrs, ok = a.applyHostAddressRewrite(addr, mappedAddrs, ifaceName)
			if !ok {
				continue
			}
		}

		for mappedIdx, mappedIP := range mappedAddrs {
			address := mappedIP.String()
			var isLocationTracked bool
			if a.mDNSMode == MulticastDNSModeQueryAndGather {
				address = a.mDNSName
			} else {

				isLocationTracked = shouldFilterLocationTrackedIP(mappedIP)
			}

			for network := range networks {

				if network == tcp && mappedIdx > 0 {
					continue
				}

				type connAndPort struct {
					conn net.PacketConn
					port int
				}
				var (
					conns   []connAndPort
					tcpType TCPType
				)

				switch network {
				case tcp:
					if a.tcpMux == nil {
						continue
					}

					if addrProvider, ok := a.tcpMux.(interface{ LocalAddr() net.Addr }); ok {
						if muxAddr, ok := addrProvider.LocalAddr().(*net.TCPAddr); ok {
							if ip := muxAddr.IP; ip != nil && !ip.IsUnspecified() && !ip.Equal(addr.AsSlice()) {
								continue
							}
						}
					}

					var muxConns []net.PacketConn
					if multi, ok := a.tcpMux.(AllConnsGetter); ok {
						a.log.Debugf("GetAllConns by ufrag: %s", a.localUfrag)

						muxConns, err = multi.GetAllConns(a.localUfrag, mappedIP.Is6(), addr.AsSlice())
						if err != nil {
							a.log.Warnf("Failed to get all TCP connections by ufrag: %s %s %s", network, addr, a.localUfrag)

							continue
						}
					} else {
						a.log.Debugf("GetConn by ufrag: %s", a.localUfrag)

						conn, err := a.tcpMux.GetConnByUfrag(a.localUfrag, mappedIP.Is6(), addr.AsSlice())
						if err != nil {
							a.log.Warnf("Failed to get TCP connections by ufrag: %s %s %s", network, addr, a.localUfrag)

							continue
						}
						muxConns = []net.PacketConn{conn}
					}

					for _, conn := range muxConns {
						if tcpConn, ok := conn.LocalAddr().(*net.TCPAddr); ok {
							conns = append(conns, connAndPort{conn, tcpConn.Port})
						} else {
							a.log.Warnf("Failed to get port of connection from TCPMux: %s %s %s", network, addr, a.localUfrag)
						}
					}
					if len(conns) == 0 {

						continue
					}
					tcpType = TCPTypePassive

				case udp:
					conn, err := listenUDPInPortRange(a.net, a.log, int(a.portMax), int(a.portMin), network, &net.UDPAddr{
						IP:   addr.AsSlice(),
						Port: 0,
						Zone: addr.Zone(),
					})
					if err != nil {
						a.log.Warnf("Failed to listen %s %s", network, addr)

						continue
					}

					if udpConn, ok := conn.LocalAddr().(*net.UDPAddr); ok {
						conns = append(conns, connAndPort{conn, udpConn.Port})
					} else {
						a.log.Warnf("Failed to get port of UDPAddr from ListenUDPInPortRange: %s %s %s", network, addr, a.localUfrag)

						continue
					}
				}

				for _, connAndPort := range conns {
					hostConfig := CandidateHostConfig{
						Network:   network,
						Address:   address,
						Port:      connAndPort.port,
						Component: ComponentRTP,
						TCPType:   tcpType,

						IsLocationTracked: isLocationTracked,
					}

					candidateHost, err := NewCandidateHost(&hostConfig)

					if err == nil && a.mDNSMode == MulticastDNSModeQueryAndGather {
						err = candidateHost.setIPAddr(addr)
					}

					if err != nil {
						closeConnAndLog(
							connAndPort.conn,
							a.log,
							"failed to create host candidate: %s %s %d: %v",
							network, mappedIP,
							connAndPort.port,
							err,
						)

						continue
					}

					if err := a.addCandidate(ctx, candidateHost, connAndPort.conn); err != nil {
						if closeErr := candidateHost.close(); closeErr != nil {
							a.log.Warnf("Failed to close candidate: %v", closeErr)
						}
						a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
					}
				}
			}
		}
	}
}

func shouldFilterLocationTrackedIP(candidateIP netip.Addr) bool {

	return candidateIP.Is6() && (candidateIP.IsLinkLocalUnicast() || candidateIP.IsLinkLocalMulticast())
}

func shouldFilterLocationTracked(candidateIP net.IP) bool {
	addr, ok := netip.AddrFromSlice(candidateIP)
	if !ok {
		return false
	}

	return shouldFilterLocationTrackedIP(addr)
}

func (a *Agent) gatherCandidatesLocalUDPMux(ctx context.Context) error {
	if a.udpMux == nil {
		return errUDPMuxDisabled
	}

	localAddresses := a.udpMux.GetListenAddresses()
	existingConfigs := make(map[CandidateHostConfig]struct{})

	for _, addr := range localAddresses {
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			return errInvalidAddress
		}
		candidateIPs := []net.IP{udpAddr.IP}

		if _, ok := a.udpMux.(*UDPMuxDefault); ok && !a.includeLoopback && udpAddr.IP.IsLoopback() {

			continue
		}

		if a.shouldRewriteHostCandidates() {
			var ok bool
			candidateIPs, ok = a.applyHostRewriteForUDPMux(candidateIPs, udpAddr)
			if !ok {
				continue
			}
		}

		for _, candidateIP := range candidateIPs {
			var address string
			var isLocationTracked bool
			if a.mDNSMode == MulticastDNSModeQueryAndGather {
				address = a.mDNSName
			} else {
				address = candidateIP.String()

				isLocationTracked = shouldFilterLocationTracked(candidateIP)
			}

			hostConfig := CandidateHostConfig{
				Network:           udp,
				Address:           address,
				Port:              udpAddr.Port,
				Component:         ComponentRTP,
				IsLocationTracked: isLocationTracked,
			}

			if _, ok := existingConfigs[hostConfig]; ok {
				continue
			}

			conn, err := a.udpMux.GetConn(a.localUfrag, udpAddr)
			if err != nil {
				return err
			}

			c, err := NewCandidateHost(&hostConfig)
			if err != nil {
				closeConnAndLog(conn, a.log, "failed to create host mux candidate: %s %d: %v", candidateIP, udpAddr.Port, err)

				continue
			}

			if err := a.addCandidate(ctx, c, conn); err != nil {
				if closeErr := c.close(); closeErr != nil {
					a.log.Warnf("Failed to close candidate: %v", closeErr)
				}

				closeConnAndLog(conn, a.log, "failed to add candidate: %s %d: %v", candidateIP, udpAddr.Port, err)

				continue
			}

			existingConfigs[hostConfig] = struct{}{}
		}
	}

	return nil
}

func (a *Agent) gatherCandidatesSrflxMapped(ctx context.Context, networkTypes []NetworkType) {
	var wg sync.WaitGroup
	defer wg.Wait()

	_, ifaces, _ := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, networkTypes, a.includeLoopback)

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		network := networkType.String()
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := listenUDPInPortRange(
				a.net,
				a.log,
				int(a.portMax),
				int(a.portMin),
				network,
				&net.UDPAddr{IP: nil, Port: 0},
			)
			if err != nil {
				a.log.Warnf("Failed to listen %s: %v", network, err)

				return
			}

			lAddr, ok := conn.LocalAddr().(*net.UDPAddr)
			if !ok {
				closeConnAndLog(conn, a.log, "Address rewrite mapping is enabled but LocalAddr is not a UDPAddr")

				return
			}

			addresses, ok := a.resolveSrflxAddresses(lAddr.IP, findIfaceForIP(ifaces, lAddr.IP))
			if !ok {
				closeConnAndLog(
					conn, a.log, "Address rewrite mapping did not provide usable external IPs for %s", lAddr.IP.String(),
				)

				return
			}

			for idx, mappedIP := range addresses {
				currentConn := conn
				currentAddr := lAddr
				if idx > 0 {
					newConn, listenErr := listenUDPInPortRange(
						a.net,
						a.log,
						int(a.portMax),
						int(a.portMin),
						network,
						&net.UDPAddr{IP: lAddr.IP, Port: 0},
					)
					if listenErr != nil {
						closeConnAndLog(newConn, a.log, "Failed to listen %s for additional srflx mapping: %v", network, listenErr)

						return
					}
					currentConn = newConn
					var ok bool
					currentAddr, ok = currentConn.LocalAddr().(*net.UDPAddr)
					if !ok {
						closeConnAndLog(currentConn, a.log, "Address rewrite mapping is enabled but LocalAddr is not a UDPAddr")

						return
					}
				}

				if shouldFilterLocationTracked(mappedIP) {
					closeConnAndLog(currentConn, a.log, "external IP is somehow filtered for location tracking reasons %s", mappedIP)

					continue
				}

				srflxConfig := CandidateServerReflexiveConfig{
					Network:   network,
					Address:   mappedIP.String(),
					Port:      currentAddr.Port,
					Component: ComponentRTP,
					RelAddr:   currentAddr.IP.String(),
					RelPort:   currentAddr.Port,
				}
				c, err := NewCandidateServerReflexive(&srflxConfig)
				if err != nil {
					closeConnAndLog(currentConn, a.log, "failed to create server reflexive candidate: %s %s %d: %v",
						network,
						mappedIP.String(),
						currentAddr.Port,
						err)

					continue
				}

				if err := a.addCandidate(ctx, c, currentConn); err != nil {
					if closeErr := c.close(); closeErr != nil {
						a.log.Warnf("Failed to close candidate: %v", closeErr)
					}
					a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
					closeConnAndLog(
						currentConn,
						a.log,
						"closing srflx conn after addCandidate failure: %v",
						err,
					)
				}
			}
		}()
	}
}

func (a *Agent) gatherCandidatesSrflxUDPMux(ctx context.Context, urls []*stun.URI, networkTypes []NetworkType) {
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		for i := range urls {
			if !urlSupportsSrflxGathering(*urls[i]) {
				continue
			}

			for _, listenAddr := range a.udpMuxSrflx.GetListenAddresses() {
				udpAddr, ok := listenAddr.(*net.UDPAddr)
				if !ok {
					a.log.Warn("Failed to cast udpMuxSrflx listen address to UDPAddr")

					continue
				}
				wg.Add(1)
				go func(url stun.URI, network string, localAddr *net.UDPAddr) {
					defer wg.Done()

					hostPort := net.JoinHostPort(url.Host, strconv.Itoa(url.Port))
					serverAddr, err := a.net.ResolveUDPAddr(network, hostPort)
					if err != nil {
						a.log.Debugf("Failed to resolve STUN host: %s %s: %v", network, hostPort, err)

						return
					}

					if shouldFilterLocationTracked(serverAddr.IP) {
						a.log.Warnf("STUN host %s is somehow filtered for location tracking reasons", hostPort)

						return
					}

					xorAddr, err := a.udpMuxSrflx.GetXORMappedAddr(serverAddr, a.stunGatherTimeout)
					if err != nil {
						a.log.Warnf("Failed get server reflexive address %s %s: %v", network, url, err)

						return
					}

					conn, err := a.udpMuxSrflx.GetConnForURL(a.localUfrag, url.String(), localAddr)
					if err != nil {
						a.log.Warnf("Failed to find connection in UDPMuxSrflx %s %s: %v", network, url, err)

						return
					}

					ip := xorAddr.IP
					port := xorAddr.Port

					srflxConfig := CandidateServerReflexiveConfig{
						Network:   network,
						Address:   ip.String(),
						Port:      port,
						Component: ComponentRTP,
						RelAddr:   localAddr.IP.String(),
						RelPort:   localAddr.Port,
					}
					c, err := NewCandidateServerReflexive(&srflxConfig)
					if err != nil {
						closeConnAndLog(conn, a.log, "failed to create server reflexive candidate: %s %s %d: %v", network, ip, port, err)

						return
					}

					if err := a.addCandidate(ctx, c, conn); err != nil {
						if closeErr := c.close(); closeErr != nil {
							a.log.Warnf("Failed to close candidate: %v", closeErr)
						}
						a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
					}
				}(*urls[i], networkType.String(), udpAddr)
			}
		}
	}
}

func (a *Agent) gatherCandidatesSrflx(ctx context.Context, urls []*stun.URI, networkTypes []NetworkType) {
	var wg sync.WaitGroup
	defer wg.Wait()

	useFilteredLocalAddrs := a.interfaceFilter != nil || a.ipFilter != nil
	localAddrs := []ifaceAddr{}
	if useFilteredLocalAddrs {
		_, addrs, err := localInterfaces(a.net, a.interfaceFilter, a.ipFilter, networkTypes, a.includeLoopback)
		if err != nil {
			a.log.Warnf("Failed to iterate local interfaces, srflx candidates will not be gathered %s", err)

			return
		}
		localAddrs = addrs
	}

	gatherForURL := func(url stun.URI, network string, listenAddr *net.UDPAddr) {
		defer wg.Done()

		hostPort := net.JoinHostPort(url.Host, strconv.Itoa(url.Port))
		serverAddr, err := a.net.ResolveUDPAddr(network, hostPort)
		if err != nil {
			a.log.Debugf("Failed to resolve STUN host: %s %s: %v", network, hostPort, err)

			return
		}

		if shouldFilterLocationTracked(serverAddr.IP) {
			a.log.Warnf("STUN host %s is somehow filtered for location tracking reasons", hostPort)

			return
		}

		conn, err := listenUDPInPortRange(
			a.net,
			a.log,
			int(a.portMax),
			int(a.portMin),
			network,
			listenAddr,
		)
		if err != nil {
			closeConnAndLog(conn, a.log, "failed to listen for %s: %v", serverAddr.String(), err)

			return
		}

		cancelCtx, cancelFunc := context.WithCancel(ctx)
		defer cancelFunc()
		go func() {
			select {
			case <-cancelCtx.Done():
				return
			case <-a.loop.Done():
				_ = conn.Close()
			}
		}()

		xorAddr, err := stunx.GetXORMappedAddr(conn, serverAddr, a.stunGatherTimeout)
		if err != nil {
			closeConnAndLog(conn, a.log, "failed to get server reflexive address %s %s: %v", network, url, err)

			return
		}

		ip := xorAddr.IP
		port := xorAddr.Port

		lAddr := conn.LocalAddr().(*net.UDPAddr)
		srflxConfig := CandidateServerReflexiveConfig{
			Network:   network,
			Address:   ip.String(),
			Port:      port,
			Component: ComponentRTP,
			RelAddr:   lAddr.IP.String(),
			RelPort:   lAddr.Port,
		}
		c, err := NewCandidateServerReflexive(&srflxConfig)
		if err != nil {
			closeConnAndLog(conn, a.log, "failed to create server reflexive candidate: %s %s %d: %v", network, ip, port, err)

			return
		}

		if err := a.addCandidate(ctx, c, conn); err != nil {
			if closeErr := c.close(); closeErr != nil {
				a.log.Warnf("Failed to close candidate: %v", closeErr)
			}
			a.log.Warnf("Failed to append to localCandidates and run onCandidateHdlr: %v", err)
		}
	}

	for _, networkType := range networkTypes {
		if networkType.IsTCP() {
			continue
		}

		for i := range urls {
			if !urlSupportsSrflxGathering(*urls[i]) {
				continue
			}

			if !useFilteredLocalAddrs {
				wg.Add(1)
				go gatherForURL(*urls[i], networkType.String(), &net.UDPAddr{IP: nil, Port: 0})

				continue
			}

			for j := range localAddrs {
				if networkType.IsIPv4() && localAddrs[j].addr.Is6() {
					continue
				}
				if networkType.IsIPv6() && !localAddrs[j].addr.Is6() {
					continue
				}

				wg.Add(1)
				go gatherForURL(
					*urls[i],
					networkType.String(),
					&net.UDPAddr{IP: localAddrs[j].addr.AsSlice(), Zone: localAddrs[j].addr.Zone(), Port: 0},
				)
			}
		}
	}
}

func (a *Agent) gatherCandidatesRelay(_ context.Context, urls []*stun.URI) {
	for _, url := range urls {
		switch {
		case url.Scheme != stun.SchemeTypeTURN && url.Scheme != stun.SchemeTypeTURNS:
			continue
		case url.Username == "":
			a.log.Errorf("Failed to gather relay candidates: %v", ErrUsernameEmpty)

			return
		case url.Password == "":
			a.log.Errorf("Failed to gather relay candidates: %v", ErrPasswordEmpty)

			return
		}
		a.log.Debugf("Skipping TURN URL %v: TURN gathering disabled in this build", url)
	}
}

func (a *Agent) resolveSrflxAddresses(localIP net.IP, iface string) ([]net.IP, bool) {
	addresses := []net.IP{localIP}
	if !a.shouldRewriteCandidateType(CandidateTypeServerReflexive) {
		return addresses, true
	}

	mappedIPs, matched, mode, err := a.addressRewriteMapper.findExternalIPs(
		CandidateTypeServerReflexive,
		localIP.String(),
		iface,
	)
	if err != nil {
		a.log.Warnf("Address rewrite mapping is enabled but no external IP is found for %s: %v", localIP.String(), err)

		return nil, false
	}

	if !matched {
		return addresses, true
	}

	if len(mappedIPs) == 0 {
		if mode == AddressRewriteReplace {
			return nil, false
		}

		return addresses, true
	}

	if mode == AddressRewriteReplace {
		return mappedIPs, true
	}

	return mappedIPs, true
}

func findIfaceForIP(ifaces []ifaceAddr, ip net.IP) string {
	if ip == nil {
		return ""
	}
	for _, info := range ifaces {
		if info.addr.String() == ip.String() {
			return info.iface
		}
	}

	return ""
}

func (a *Agent) startNetworkMonitoring(ctx context.Context) {
	ticker := time.NewTicker(a.networkMonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.detectNetworkChanges() {
				a.gatherCandidatesInternal(ctx)
			}
		}
	}
}

func (a *Agent) detectNetworkChanges() bool {

	if stdNet, ok := a.net.(*transport.StdNet); ok {
		if err := stdNet.UpdateInterfaces(); err != nil {
			a.log.Warnf("Failed to update interfaces: %v", err)
		}
	}

	_, currentAddrs, err := localInterfaces(
		a.net,
		a.interfaceFilter,
		a.ipFilter,
		a.networkTypes,
		a.includeLoopback,
	)
	if err != nil {
		a.log.Warnf("Failed to get local interfaces during network monitoring: %v", err)

		return false
	}

	currentInterfaces := make(map[string]netip.Addr)
	for _, info := range currentAddrs {
		key := info.addr.String()
		currentInterfaces[key] = info.addr
	}

	hasAdditions := false

	for key, addr := range currentInterfaces {
		if _, exists := a.lastKnownInterfaces[key]; !exists {
			a.log.Infof("New IP address detected: %s", addr)
			hasAdditions = true
		}
	}

	a.lastKnownInterfaces = currentInterfaces

	return hasAdditions
}

type ConnectionState int

const (
	ConnectionStateUnknown ConnectionState = iota

	ConnectionStateNew

	ConnectionStateChecking

	ConnectionStateConnected

	ConnectionStateCompleted

	ConnectionStateFailed

	ConnectionStateDisconnected

	ConnectionStateClosed
)

func (c ConnectionState) String() string {
	switch c {
	case ConnectionStateNew:
		return "New"
	case ConnectionStateChecking:
		return "Checking"
	case ConnectionStateConnected:
		return "Connected"
	case ConnectionStateCompleted:
		return "Completed"
	case ConnectionStateFailed:
		return "Failed"
	case ConnectionStateDisconnected:
		return "Disconnected"
	case ConnectionStateClosed:
		return "Closed"
	default:
		return "Invalid"
	}
}

type GatheringState int

const (
	GatheringStateUnknown GatheringState = iota

	GatheringStateNew

	GatheringStateGathering

	GatheringStateComplete
)

func (t GatheringState) String() string {
	switch t {
	case GatheringStateNew:
		return "new"
	case GatheringStateGathering:
		return "gathering"
	case GatheringStateComplete:
		return "complete"
	default:
		return ErrUnknownType.Error()
	}
}

type ContinualGatheringPolicy int

const (
	GatherOnce ContinualGatheringPolicy = iota
	GatherContinually
)

func (c ContinualGatheringPolicy) String() string {
	switch c {
	case GatherOnce:
		return "gather_once"
	case GatherContinually:
		return "gather_continually"
	default:
		return unknownStr
	}
}

const (
	unknownStr        = "unknown"
	relayProtocolDTLS = "dtls"
	relayProtocolTLS  = "tls"
)

type tiebreaker uint64

const tiebreakerSize = 8

func (a tiebreaker) AddToAs(m *stun.Message, t stun.AttrType) error {
	v := make([]byte, tiebreakerSize)
	binary.BigEndian.PutUint64(v, uint64(a))
	m.Add(t, v)

	return nil
}

func (a *tiebreaker) GetFromAs(m *stun.Message, t stun.AttrType) error {
	v, err := m.Get(t)
	if err != nil {
		return err
	}
	if err = stun.CheckSize(t, len(v), tiebreakerSize); err != nil {
		return err
	}
	*a = tiebreaker(binary.BigEndian.Uint64(v))

	return nil
}

type AttrControlled uint64

func (c AttrControlled) AddTo(m *stun.Message) error {
	return tiebreaker(c).AddToAs(m, stun.AttrICEControlled)
}

func (c *AttrControlled) GetFrom(m *stun.Message) error {
	return (*tiebreaker)(c).GetFromAs(m, stun.AttrICEControlled)
}

type AttrControlling uint64

func (c AttrControlling) AddTo(m *stun.Message) error {
	return tiebreaker(c).AddToAs(m, stun.AttrICEControlling)
}

func (c *AttrControlling) GetFrom(m *stun.Message) error {
	return (*tiebreaker)(c).GetFromAs(m, stun.AttrICEControlling)
}

type AttrControl struct {
	Role       Role
	Tiebreaker uint64
}

func (c *AttrControl) GetFrom(m *stun.Message) error {
	if m.Contains(stun.AttrICEControlling) {
		c.Role = Controlling

		return (*tiebreaker)(&c.Tiebreaker).GetFromAs(m, stun.AttrICEControlling)
	}
	if m.Contains(stun.AttrICEControlled) {
		c.Role = Controlled

		return (*tiebreaker)(&c.Tiebreaker).GetFromAs(m, stun.AttrICEControlled)
	}

	return stun.ErrAttributeNotFound
}

var errMDNSDisabled = errors.New("mDNS is disabled in this build")

type MulticastDNSMode byte

const (
	MulticastDNSModeDisabled MulticastDNSMode = iota + 1

	MulticastDNSModeQueryOnly

	MulticastDNSModeQueryAndGather
)

type mdnsConn struct{}

func (*mdnsConn) Close() error { return nil }

func (*mdnsConn) QueryAddr(_ context.Context, _ string) (dnsmessage.ResourceHeader, netip.Addr, error) {
	return dnsmessage.ResourceHeader{}, netip.Addr{}, errMDNSDisabled
}

func generateMulticastDNSName() (string, error) {

	u, err := uuid.NewRandom()

	return u.String() + ".local", err
}

func createMulticastDNS(
	_ transport.Net,
	_ []NetworkType,
	_ []*transport.Interface,
	_ bool,
	_ net.IP,
	mDNSMode MulticastDNSMode,
	_ string,
	_ logging.LeveledLogger,
	_ logging.LoggerFactory,
) (*mdnsConn, MulticastDNSMode, error) {
	return nil, mDNSMode, nil
}

type ifaceAddr struct {
	addr  netip.Addr
	iface string
}

func isSupportedIPv6Partial(ip net.IP) bool {
	if len(ip) != net.IPv6len ||

		isZeros(ip[0:12]) ||
		ip[0] == 0xfe && ip[1]&0xc0 == 0xc0 {
		return false
	}

	return true
}

func isZeros(ip net.IP) bool {
	for i := range ip {
		if ip[i] != 0 {
			return false
		}
	}

	return true
}

func localInterfaces(
	n transport.Net,
	interfaceFilter func(string) (keep bool),
	ipFilter func(net.IP) (keep bool),
	networkTypes []NetworkType,
	includeLoopback bool,
) ([]*transport.Interface, []ifaceAddr, error) {
	ipAddrs := []ifaceAddr{}
	ifaces, err := n.Interfaces()
	if err != nil {
		return nil, ipAddrs, err
	}

	filteredIfaces := make([]*transport.Interface, 0, len(ifaces))

	var ipV4Requested, ipv6Requested bool
	if len(networkTypes) == 0 {
		ipV4Requested = true
		ipv6Requested = true
	} else {
		for _, typ := range networkTypes {
			if typ.IsIPv4() {
				ipV4Requested = true
			}

			if typ.IsIPv6() {
				ipv6Requested = true
			}
		}
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if (iface.Flags&net.FlagLoopback != 0) && !includeLoopback {
			continue
		}

		if interfaceFilter != nil && !interfaceFilter(iface.Name) {
			continue
		}

		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		atLeastOneAddr := false
		for _, addr := range ifaceAddrs {
			ipAddr, _, _, err := parseAddrFromIface(addr, iface.Name)
			if err != nil || (ipAddr.IsLoopback() && !includeLoopback) {
				continue
			}
			if ipAddr.Is6() {
				if !ipv6Requested {
					continue
				} else if !isSupportedIPv6Partial(ipAddr.AsSlice()) {
					continue
				}
			} else if !ipV4Requested {
				continue
			}

			if ipFilter != nil && !ipFilter(ipAddr.AsSlice()) {
				continue
			}

			atLeastOneAddr = true
			ipAddrs = append(ipAddrs, ifaceAddr{addr: ipAddr, iface: iface.Name})
		}

		if atLeastOneAddr {
			ifaceCopy := iface
			filteredIfaces = append(filteredIfaces, ifaceCopy)
		}
	}

	return filteredIfaces, ipAddrs, nil
}

func listenUDPInPortRange(
	netTransport transport.Net,
	log logging.LeveledLogger,
	portMax, portMin int,
	network string,
	lAddr *net.UDPAddr,
) (transport.UDPConn, error) {
	if (lAddr.Port != 0) || ((portMin == 0) && (portMax == 0)) {
		return netTransport.ListenUDP(network, lAddr)
	}

	if portMin == 0 {
		portMin = 1024
	}

	if portMax == 0 {
		portMax = 0xFFFF
	}

	if portMin > portMax {
		return nil, ErrPort
	}

	portStart := globalMathRandomGenerator.Intn(portMax-portMin+1) + portMin
	portCurrent := portStart
	for {
		addr := &net.UDPAddr{
			IP:   lAddr.IP,
			Zone: lAddr.Zone,
			Port: portCurrent,
		}

		c, e := netTransport.ListenUDP(network, addr)
		if e == nil {
			return c, e
		}
		log.Debugf("Failed to listen %s: %v", lAddr.String(), e)
		if webrtc.IsAddrUnavailable(e) {
			return nil, e
		}
		portCurrent++
		if portCurrent > portMax {
			portCurrent = portMin
		}
		if portCurrent == portStart {
			break
		}
	}

	return nil, ErrPort
}

const (
	udp  = "udp"
	tcp  = "tcp"
	udp4 = "udp4"
	udp6 = "udp6"
	tcp4 = "tcp4"
	tcp6 = "tcp6"
)

func supportedNetworkTypes() []NetworkType {
	return []NetworkType{
		NetworkTypeUDP4,
		NetworkTypeUDP6,
		NetworkTypeTCP4,
		NetworkTypeTCP6,
	}
}

type NetworkType int

const (
	NetworkTypeUDP4 NetworkType = iota + 1

	NetworkTypeUDP6

	NetworkTypeTCP4

	NetworkTypeTCP6
)

func (t NetworkType) String() string {
	switch t {
	case NetworkTypeUDP4:
		return udp4
	case NetworkTypeUDP6:
		return udp6
	case NetworkTypeTCP4:
		return tcp4
	case NetworkTypeTCP6:
		return tcp6
	default:
		return ErrUnknownType.Error()
	}
}

func (t NetworkType) IsUDP() bool {
	return t == NetworkTypeUDP4 || t == NetworkTypeUDP6
}

func (t NetworkType) IsTCP() bool {
	return t == NetworkTypeTCP4 || t == NetworkTypeTCP6
}

func (t NetworkType) NetworkShort() string {
	switch t {
	case NetworkTypeUDP4, NetworkTypeUDP6:
		return udp
	case NetworkTypeTCP4, NetworkTypeTCP6:
		return tcp
	default:
		return ErrUnknownType.Error()
	}
}

func (t NetworkType) IsReliable() bool {
	switch t {
	case NetworkTypeUDP4, NetworkTypeUDP6:
		return false
	case NetworkTypeTCP4, NetworkTypeTCP6:
		return true
	}

	return false
}

func (t NetworkType) IsIPv4() bool {
	switch t {
	case NetworkTypeUDP4, NetworkTypeTCP4:
		return true
	case NetworkTypeUDP6, NetworkTypeTCP6:
		return false
	}

	return false
}

func (t NetworkType) IsIPv6() bool {
	switch t {
	case NetworkTypeUDP4, NetworkTypeTCP4:
		return false
	case NetworkTypeUDP6, NetworkTypeTCP6:
		return true
	}

	return false
}

func determineNetworkType(network string, ip netip.Addr) (NetworkType, error) {

	ip = ip.Unmap()
	switch {
	case strings.HasPrefix(strings.ToLower(network), udp):
		if ip.Is4() {
			return NetworkTypeUDP4, nil
		}

		return NetworkTypeUDP6, nil

	case strings.HasPrefix(strings.ToLower(network), tcp):
		if ip.Is4() {
			return NetworkTypeTCP4, nil
		}

		return NetworkTypeTCP6, nil
	}

	return NetworkType(0), fmt.Errorf("%w from %s %s", ErrDetermineNetworkType, network, ip)
}

type PriorityAttr uint32

const prioritySize = 4

func (p PriorityAttr) AddTo(m *stun.Message) error {
	v := make([]byte, prioritySize)
	binary.BigEndian.PutUint32(v, uint32(p))
	m.Add(stun.AttrPriority, v)

	return nil
}

func (p *PriorityAttr) GetFrom(m *stun.Message) error {
	v, err := m.Get(stun.AttrPriority)
	if err != nil {
		return err
	}
	if err = stun.CheckSize(stun.AttrPriority, len(v), prioritySize); err != nil {
		return err
	}
	*p = PriorityAttr(binary.BigEndian.Uint32(v))

	return nil
}

const (
	runesAlpha                 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	runesDigit                 = "0123456789"
	runesCandidateIDFoundation = runesAlpha + runesDigit + "+/"

	lenUFrag = 16
	lenPwd   = 32
)

var (
	globalMathRandomGenerator  = webrtc.NewRandGenerator()
	globalCandidateIDGenerator = candidateIDGenerator{globalMathRandomGenerator}
)

type candidateIDGenerator struct {
	webrtc.RandGenerator
}

func (g *candidateIDGenerator) Generate() string {

	return "candidate:" + g.RandGenerator.GenerateString(32, runesCandidateIDFoundation)
}

func generatePwd() (string, error) {
	return webrtc.CryptoRandString(lenPwd, runesAlpha)
}

func generateUFrag() (string, error) {
	return webrtc.CryptoRandString(lenUFrag, runesAlpha)
}

const (
	DefaultNominationAttribute stun.AttrType = 0xC001
)

type NominationAttribute struct {
	Value uint32
}

func (a *NominationAttribute) GetFromWithType(m *stun.Message, attrType stun.AttrType) error {
	v, err := m.Get(attrType)
	if err != nil {
		return err
	}
	if len(v) < 4 {
		return stun.ErrAttributeSizeInvalid
	}

	a.Value = uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])

	return nil
}

func (a NominationAttribute) AddToWithType(m *stun.Message, attrType stun.AttrType) error {

	v := make([]byte, 4)
	v[1] = byte(a.Value >> 16)
	v[2] = byte(a.Value >> 8)
	v[3] = byte(a.Value)

	m.Add(attrType, v)

	return nil
}

type NominationSetter struct {
	Value    uint32
	AttrType stun.AttrType
}

func (n NominationSetter) AddTo(m *stun.Message) error {
	attr := NominationAttribute{Value: n.Value}

	return attr.AddToWithType(m, n.AttrType)
}

type Role byte

const (
	Controlling Role = iota
	Controlled
)

func (r *Role) UnmarshalText(text []byte) error {
	switch string(text) {
	case "controlling":
		*r = Controlling
	case "controlled":
		*r = Controlled
	default:
		return fmt.Errorf("%w %q", errUnknownRole, text)
	}

	return nil
}

func (r Role) MarshalText() (text []byte, err error) {
	return []byte(r.String()), nil
}

func (r Role) String() string {
	switch r {
	case Controlling:
		return "controlling"
	case Controlled:
		return "controlled"
	default:
		return "unknown"
	}
}

type pairCandidateSelector interface {
	Start()
	ContactCandidates()
	PingCandidate(local, remote Candidate)
	HandleSuccessResponse(m *stun.Message, local, remote Candidate, remoteAddr net.Addr)
	HandleBindingRequest(m *stun.Message, local, remote Candidate)
}

type controllingSelector struct {
	startTime     time.Time
	agent         *Agent
	nominatedPair *CandidatePair
	log           logging.LeveledLogger
}

func (s *controllingSelector) Start() {
	s.startTime = time.Now()
	s.nominatedPair = nil
}

func (s *controllingSelector) isNominatable(c Candidate) bool {
	switch {
	case c.Type() == CandidateTypeHost:
		return time.Since(s.startTime).Nanoseconds() >= s.agent.hostAcceptanceMinWait.Nanoseconds()
	case c.Type() == CandidateTypeServerReflexive:
		return time.Since(s.startTime).Nanoseconds() >= s.agent.srflxAcceptanceMinWait.Nanoseconds()
	case c.Type() == CandidateTypePeerReflexive:
		return time.Since(s.startTime).Nanoseconds() >= s.agent.prflxAcceptanceMinWait.Nanoseconds()
	case c.Type() == CandidateTypeRelay:
		return time.Since(s.startTime).Nanoseconds() >= s.agent.relayAcceptanceMinWait.Nanoseconds()
	}

	s.log.Errorf("Invalid candidate type: %s", c.Type())

	return false
}

func (s *controllingSelector) ContactCandidates() {
	switch {
	case s.agent.getSelectedPair() != nil:
		if s.agent.validateSelectedPair() {
			s.log.Trace("Checking keepalive")
			s.agent.checkKeepalive()

			if s.agent.automaticRenomination && s.agent.enableRenomination {
				s.agent.keepAliveCandidatesForRenomination()
			}

			s.checkForAutomaticRenomination()
		}
	case s.nominatedPair != nil:
		s.nominatePair(s.nominatedPair)
	default:
		p := s.agent.getBestValidCandidatePair()
		if p != nil && s.isNominatable(p.Local) && s.isNominatable(p.Remote) {
			s.log.Tracef("Nominatable pair found, nominating (%s, %s)", p.Local, p.Remote)
			p.nominated = true
			s.nominatedPair = p
			s.nominatePair(p)

			return
		}
		s.agent.pingAllCandidates()
	}
}

func (s *controllingSelector) nominatePair(pair *CandidatePair) {

	msg, err := stun.Build(stun.BindingRequest, stun.TransactionID,
		stun.NewUsername(s.agent.remoteUfrag+":"+s.agent.localUfrag),
		UseCandidate(),
		AttrControlling(s.agent.tieBreaker),
		PriorityAttr(pair.Local.Priority()),
		stun.NewShortTermIntegrity(s.agent.remotePwd),
		stun.Fingerprint,
	)
	if err != nil {
		s.log.Error(err.Error())

		return
	}

	s.log.Tracef("Ping STUN (nominate candidate pair) from %s to %s", pair.Local, pair.Remote)
	s.agent.sendBindingRequest(msg, pair.Local, pair.Remote)
}

func (s *controllingSelector) HandleBindingRequest(message *stun.Message, local, remote Candidate) {
	s.agent.sendBindingSuccess(message, local, remote)

	pair := s.agent.findPair(local, remote)

	if pair == nil {
		pair = s.agent.addPair(local, remote)
		pair.UpdateRequestReceived()

		return
	}
	pair.UpdateRequestReceived()

	if pair.state == CandidatePairStateSucceeded && s.nominatedPair == nil && s.agent.getSelectedPair() == nil {
		bestPair := s.agent.getBestAvailableCandidatePair()
		if bestPair == nil {
			s.log.Tracef("No best pair available")
		} else if bestPair.equal(pair) && s.isNominatable(pair.Local) && s.isNominatable(pair.Remote) {
			s.log.Tracef(
				"The candidate (%s, %s) is the best candidate available, marking it as nominated",
				pair.Local,
				pair.Remote,
			)
			s.nominatedPair = pair
			s.nominatePair(pair)
		}
	}

	if s.agent.userBindingRequestHandler != nil {
		if shouldSwitch := s.agent.userBindingRequestHandler(message, local, remote, pair); shouldSwitch {
			s.agent.setSelectedPair(pair)
		}
	}
}

func (s *controllingSelector) HandleSuccessResponse(m *stun.Message, local, remote Candidate, remoteAddr net.Addr) {
	ok, pendingRequest, rtt := s.agent.handleInboundBindingSuccess(m.TransactionID)
	if !ok {
		s.log.Warnf("Discard success response from (%s), unknown TransactionID 0x%x", remote, m.TransactionID)

		return
	}

	transactionAddr := pendingRequest.destination

	if !addrEqual(transactionAddr, remoteAddr) {
		s.log.Debugf(
			"Discard message: transaction source and destination does not match expected(%s), actual(%s)",
			transactionAddr,
			remote,
		)

		return
	}

	s.log.Tracef("Inbound STUN (SuccessResponse) from %s to %s", remote, local)
	pair := s.agent.findPair(local, remote)

	if pair == nil {

		s.log.Error("Success response from invalid candidate pair")

		return
	}

	pair.state = CandidatePairStateSucceeded
	s.log.Tracef("Found valid candidate pair: %s", pair)

	if pendingRequest.isUseCandidate {
		selectedPair := s.agent.getSelectedPair()

		if pendingRequest.nominationValue != nil {
			s.log.Infof("Renomination success response received for pair %s (nomination value: %d), switching to this pair",
				pair, *pendingRequest.nominationValue)
			s.agent.setSelectedPair(pair)
		} else if selectedPair == nil {
			s.agent.setSelectedPair(pair)
		}
	}

	pair.UpdateRoundTripTime(rtt)
}

func (s *controllingSelector) PingCandidate(local, remote Candidate) {
	msg, err := stun.Build(stun.BindingRequest, stun.TransactionID,
		stun.NewUsername(s.agent.remoteUfrag+":"+s.agent.localUfrag),
		AttrControlling(s.agent.tieBreaker),
		PriorityAttr(local.Priority()),
		stun.NewShortTermIntegrity(s.agent.remotePwd),
		stun.Fingerprint,
	)
	if err != nil {
		s.log.Error(err.Error())

		return
	}

	s.agent.sendBindingRequest(msg, local, remote)
}

func (s *controllingSelector) checkForAutomaticRenomination() {
	if !s.agent.automaticRenomination || !s.agent.enableRenomination {
		s.log.Tracef("Automatic renomination check skipped: automaticRenomination=%v, enableRenomination=%v",
			s.agent.automaticRenomination, s.agent.enableRenomination)

		return
	}

	timeSinceStart := time.Since(s.startTime)
	if timeSinceStart < s.agent.renominationInterval {
		s.log.Tracef("Automatic renomination check skipped: not enough time since start (%v < %v)",
			timeSinceStart, s.agent.renominationInterval)

		return
	}

	if !s.agent.lastRenominationTime.IsZero() {
		timeSinceLastRenomination := time.Since(s.agent.lastRenominationTime)
		if timeSinceLastRenomination < s.agent.renominationInterval {
			s.log.Tracef("Automatic renomination check skipped: too soon since last renomination (%v < %v)",
				timeSinceLastRenomination, s.agent.renominationInterval)

			return
		}
	}

	currentPair := s.agent.getSelectedPair()
	if currentPair == nil {
		s.log.Tracef("Automatic renomination check skipped: no current selected pair")

		return
	}

	bestPair := s.agent.findBestCandidatePair()
	if bestPair == nil {
		s.log.Tracef("Automatic renomination check skipped: no best pair found")

		return
	}

	s.log.Debugf("Evaluating automatic renomination: current=%s (RTT=%.2fms), best=%s (RTT=%.2fms)",
		currentPair, currentPair.CurrentRoundTripTime()*1000,
		bestPair, bestPair.CurrentRoundTripTime()*1000)

	if s.agent.shouldRenominate(currentPair, bestPair) {
		s.log.Infof("Automatic renomination triggered: switching from %s to %s",
			currentPair, bestPair)

		s.agent.lastRenominationTime = time.Now()

		if err := s.agent.RenominateCandidate(bestPair.Local, bestPair.Remote); err != nil {
			s.log.Errorf("Failed to trigger automatic renomination: %v", err)
		}
	} else {
		s.log.Debugf("Automatic renomination not warranted")
	}
}

type controlledSelector struct {
	agent          *Agent
	log            logging.LeveledLogger
	lastNomination *uint32
}

func (s *controlledSelector) Start() {
	s.lastNomination = nil
}

func (s *controlledSelector) shouldAcceptNomination(nominationValue *uint32) bool {

	if nominationValue == nil {
		return true
	}

	if s.lastNomination == nil || *nominationValue > *s.lastNomination {
		s.lastNomination = nominationValue
		s.log.Tracef("Accepting nomination with value %d", *nominationValue)

		return true
	}

	s.log.Tracef("Rejecting nomination value %d (current is %d)", *nominationValue, *s.lastNomination)

	return false
}

func (s *controlledSelector) shouldSwitchSelectedPair(pair, selectedPair *CandidatePair, nominationValue *uint32) bool {
	switch {
	case selectedPair == nil:

		return true
	case selectedPair == pair:

		return false
	case nominationValue != nil:

		s.log.Debugf("Accepting renomination to pair %s (nomination value: %d)", pair, *nominationValue)

		return true
	}

	return !s.agent.needsToCheckPriorityOnNominated() ||
		selectedPair.priority() < pair.priority()
}

func (s *controlledSelector) ContactCandidates() {
	if s.agent.getSelectedPair() != nil {
		if s.agent.validateSelectedPair() {
			s.log.Trace("Checking keepalive")
			s.agent.checkKeepalive()
		}
	} else {
		s.agent.pingAllCandidates()
	}
}

func (s *controlledSelector) PingCandidate(local, remote Candidate) {
	msg, err := stun.Build(stun.BindingRequest, stun.TransactionID,
		stun.NewUsername(s.agent.remoteUfrag+":"+s.agent.localUfrag),
		AttrControlled(s.agent.tieBreaker),
		PriorityAttr(local.Priority()),
		stun.NewShortTermIntegrity(s.agent.remotePwd),
		stun.Fingerprint,
	)
	if err != nil {
		s.log.Error(err.Error())

		return
	}

	s.agent.sendBindingRequest(msg, local, remote)
}

func (s *controlledSelector) HandleSuccessResponse(m *stun.Message, local, remote Candidate, remoteAddr net.Addr) {

	ok, pendingRequest, rtt := s.agent.handleInboundBindingSuccess(m.TransactionID)
	if !ok {
		s.log.Warnf("Discard message from (%s), unknown TransactionID 0x%x", remote, m.TransactionID)

		return
	}

	transactionAddr := pendingRequest.destination

	if !addrEqual(transactionAddr, remoteAddr) {
		s.log.Debugf(
			"Discard message: transaction source and destination does not match expected(%s), actual(%s)",
			transactionAddr,
			remote,
		)

		return
	}

	s.log.Tracef("Inbound STUN (SuccessResponse) from %s to %s", remote, local)

	pair := s.agent.findPair(local, remote)
	if pair == nil {

		s.log.Error("Success response from invalid candidate pair")

		return
	}

	pair.state = CandidatePairStateSucceeded
	s.log.Tracef("Found valid candidate pair: %s", pair)
	if pair.nominateOnBindingSuccess {
		if selectedPair := s.agent.getSelectedPair(); selectedPair == nil ||
			(selectedPair != pair &&
				(!s.agent.needsToCheckPriorityOnNominated() || selectedPair.priority() <= pair.priority())) {
			s.agent.setSelectedPair(pair)
		} else if selectedPair != pair {
			s.log.Tracef("Ignore nominate new pair %s, already nominated pair %s", pair, selectedPair)
		}
	}

	pair.UpdateRoundTripTime(rtt)
}

func (s *controlledSelector) HandleBindingRequest(message *stun.Message, local, remote Candidate) {
	pair := s.agent.findPair(local, remote)
	if pair == nil {
		pair = s.agent.addPair(local, remote)
	}
	pair.UpdateRequestReceived()

	if message.Contains(stun.AttrUseCandidate) || message.Contains(s.agent.nominationAttribute) {

		var nominationValue *uint32
		var nomination NominationAttribute
		if err := nomination.GetFromWithType(message, s.agent.nominationAttribute); err == nil {
			nominationValue = &nomination.Value
			s.log.Tracef("Received nomination with value %d", nomination.Value)
		}

		if !s.shouldAcceptNomination(nominationValue) {
			s.log.Tracef("Rejecting nomination request due to renomination rules")
			s.agent.sendBindingSuccess(message, local, remote)

			return
		}

		if pair.state == CandidatePairStateSucceeded {

			selectedPair := s.agent.getSelectedPair()
			if s.shouldSwitchSelectedPair(pair, selectedPair, nominationValue) {
				s.log.Tracef("Accepting nomination for pair %s", pair)
				s.agent.setSelectedPair(pair)
			} else {
				s.log.Tracef("Ignore nominate new pair %s, already nominated pair %s", pair, selectedPair)
			}
		} else {

			pair.nominateOnBindingSuccess = true
		}
	}

	s.agent.sendBindingSuccess(message, local, remote)

	if pair.state != CandidatePairStateSucceeded || s.agent.getSelectedPair() == nil {
		s.PingCandidate(local, remote)
	}

	if s.agent.userBindingRequestHandler != nil {
		if shouldSwitch := s.agent.userBindingRequestHandler(message, local, remote, pair); shouldSwitch {
			s.agent.setSelectedPair(pair)
		}
	}
}

type liteSelector struct {
	pairCandidateSelector
}

func (s *liteSelector) ContactCandidates() {
	if _, ok := s.pairCandidateSelector.(*controllingSelector); ok {

		s.pairCandidateSelector.ContactCandidates()
	} else if v, ok := s.pairCandidateSelector.(*controlledSelector); ok {
		v.agent.validateSelectedPair()
	}
}

type CandidatePairStats struct {
	Timestamp                     time.Time
	LocalCandidateID              string
	RemoteCandidateID             string
	State                         CandidatePairState
	Nominated                     bool
	PacketsSent                   uint32
	PacketsReceived               uint32
	BytesSent                     uint64
	BytesReceived                 uint64
	LastPacketSentTimestamp       time.Time
	LastPacketReceivedTimestamp   time.Time
	FirstRequestTimestamp         time.Time
	LastRequestTimestamp          time.Time
	FirstResponseTimestamp        time.Time
	LastResponseTimestamp         time.Time
	FirstRequestReceivedTimestamp time.Time
	LastRequestReceivedTimestamp  time.Time
	TotalRoundTripTime            float64
	CurrentRoundTripTime          float64
	AvailableOutgoingBitrate      float64
	AvailableIncomingBitrate      float64
	CircuitBreakerTriggerCount    uint32
	RequestsReceived              uint64
	RequestsSent                  uint64
	ResponsesReceived             uint64
	ResponsesSent                 uint64
	RetransmissionsReceived       uint64
	RetransmissionsSent           uint64
	ConsentRequestsSent           uint64
	ConsentExpiredTimestamp       time.Time
}

type CandidatePairInfo struct {
	ID                   uint64
	LocalCandidateType   CandidateType
	RemoteCandidateType  CandidateType
	State                CandidatePairState
	Nominated            bool
	CurrentRoundTripTime time.Duration
	RenominationQuality  float64
}

type CandidateStats struct {
	Timestamp     time.Time
	ID            string
	NetworkType   NetworkType
	IP            string
	Port          int
	CandidateType CandidateType
	Priority      uint32
	URL           string
	RelayProtocol string
	Deleted       bool
}

var ErrGetTransportAddress = errors.New("failed to get local transport address")

type TCPMux interface {
	io.Closer
	GetConnByUfrag(ufrag string, isIPv6 bool, local net.IP) (net.PacketConn, error)
	RemoveConnByUfrag(ufrag string)
}

type AllConnsGetter interface {
	GetAllConns(ufrag string, isIPv6 bool, localIP net.IP) ([]net.PacketConn, error)
}

type TCPMuxParams struct {
	Listener                     net.Listener
	Logger                       logging.LeveledLogger
	ReadBufferSize               int
	WriteBufferSize              int
	FirstStunBindTimeout         time.Duration
	AliveDurationForConnFromStun time.Duration
}

type TCPMuxDefault struct {
	params *TCPMuxParams
}

func NewTCPMuxDefault(params TCPMuxParams) *TCPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}
	return &TCPMuxDefault{params: &params}
}

func (m *TCPMuxDefault) LocalAddr() net.Addr {
	if m.params == nil || m.params.Listener == nil {
		return nil
	}
	return m.params.Listener.Addr()
}

func (m *TCPMuxDefault) GetConnByUfrag(_ string, _ bool, _ net.IP) (net.PacketConn, error) {
	return nil, ErrGetTransportAddress
}

func (m *TCPMuxDefault) RemoveConnByUfrag(_ string) {}

func (m *TCPMuxDefault) Close() error { return nil }

type TCPType int

const (
	TCPTypeUnspecified TCPType = iota

	TCPTypeActive

	TCPTypePassive

	TCPTypeSimultaneousOpen
)

func NewTCPType(value string) TCPType {
	switch strings.ToLower(value) {
	case "active":
		return TCPTypeActive
	case "passive":
		return TCPTypePassive
	case "so":
		return TCPTypeSimultaneousOpen
	default:
		return TCPTypeUnspecified
	}
}

func (t TCPType) String() string {
	switch t {
	case TCPTypeUnspecified:
		return ""
	case TCPTypeActive:
		return "active"
	case TCPTypePassive:
		return "passive"
	case TCPTypeSimultaneousOpen:
		return "so"
	default:
		return ErrUnknownType.Error()
	}
}

func (a *Agent) AwaitConnect(ctx context.Context) error {
	select {
	case <-a.loop.Done():
		return a.loop.Err()
	case <-ctx.Done():
		return ErrCanceledByCaller
	case <-a.onConnected:
	}

	return nil
}

func (a *Agent) StartDial(remoteUfrag, remotePwd string) (*Conn, error) {
	conn, err := a.startConnect(true, remoteUfrag, remotePwd)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (a *Agent) Dial(ctx context.Context, remoteUfrag, remotePwd string) (*Conn, error) {
	conn, err := a.StartDial(remoteUfrag, remotePwd)
	if err != nil {
		return nil, err
	}
	err = a.AwaitConnect(ctx)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (a *Agent) StartAccept(remoteUfrag, remotePwd string) (*Conn, error) {
	conn, err := a.startConnect(false, remoteUfrag, remotePwd)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (a *Agent) Accept(ctx context.Context, remoteUfrag, remotePwd string) (*Conn, error) {
	conn, err := a.StartAccept(remoteUfrag, remotePwd)
	if err != nil {
		return nil, err
	}
	err = a.AwaitConnect(ctx)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

type Conn struct {
	bytesReceived atomic.Uint64
	bytesSent     atomic.Uint64
	agent         *Agent
}

func (c *Conn) BytesSent() uint64 {
	return c.bytesSent.Load()
}

func (c *Conn) BytesReceived() uint64 {
	return c.bytesReceived.Load()
}

func (a *Agent) startConnect(isControlling bool, remoteUfrag, remotePwd string) (*Conn, error) {
	err := a.loop.Err()
	if err != nil {
		return nil, err
	}
	err = a.startConnectivityChecks(isControlling, remoteUfrag, remotePwd)
	if err != nil {
		return nil, err
	}

	return &Conn{
		agent: a,
	}, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	err := c.agent.loop.Err()
	if err != nil {
		return 0, err
	}

	n, err := c.agent.buf.Read(p)
	c.bytesReceived.Add(uint64(n))

	return n, err
}

func (c *Conn) Write(packet []byte) (int, error) {
	err := c.agent.loop.Err()
	if err != nil {
		return 0, err
	}

	if stun.IsMessage(packet) {
		return 0, errWriteSTUNMessageToIceConn
	}

	pair := c.agent.getSelectedPair()
	if pair == nil {
		if err = c.agent.loop.Run(c.agent.loop, func(_ context.Context) {
			pair = c.agent.getBestValidCandidatePair()
		}); err != nil {
			return 0, err
		}

		if pair == nil {
			return 0, err
		}
	}

	n, err := pair.Write(packet)
	if n > 0 {
		c.bytesSent.Add(uint64(n))
		pair.UpdatePacketSent(n)
	}

	return n, err
}

func (c *Conn) GetCandidatePairsInfo() []CandidatePairInfo {
	var pairs []CandidatePairInfo

	err := c.agent.loop.Run(c.agent.loop, func(_ context.Context) {
		pairs = make([]CandidatePairInfo, 0, len(c.agent.checklist))
		for _, cp := range c.agent.checklist {
			pairs = append(pairs, CandidatePairInfo{
				ID:                   cp.id,
				LocalCandidateType:   cp.Local.Type(),
				RemoteCandidateType:  cp.Remote.Type(),
				State:                cp.state,
				Nominated:            cp.nominated,
				CurrentRoundTripTime: time.Duration(atomic.LoadInt64(&cp.currentRoundTripTime)),
				RenominationQuality:  c.agent.evaluateCandidatePairQuality(cp),
			})
		}
	})
	if err != nil {
		return nil
	}

	return pairs
}

func (c *Conn) WriteToPair(pairID uint64, packet []byte) (int, error) {
	if err := c.agent.loop.Err(); err != nil {
		return 0, err
	}

	if stun.IsMessage(packet) {
		return 0, errWriteSTUNMessageToIceConn
	}

	var pair *CandidatePair
	var lookupErr error

	if err := c.agent.loop.Run(c.agent.loop, func(_ context.Context) {
		pair = c.agent.pairsByID[pairID]
		if pair == nil {
			lookupErr = ErrCandidatePairNotFound

			return
		}
		if pair.state != CandidatePairStateSucceeded {
			lookupErr = ErrCandidatePairNotSucceeded
		}
	}); err != nil {
		return 0, err
	}

	if lookupErr != nil {
		return 0, lookupErr
	}

	n, err := pair.Write(packet)
	if n > 0 {
		pair.UpdatePacketSent(n)
	}

	return n, err
}

func (c *Conn) Close() error {
	return c.agent.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	pair := c.agent.getSelectedPair()
	if pair == nil {
		return nil
	}

	return pair.Local.addr()
}

func (c *Conn) RemoteAddr() net.Addr {
	pair := c.agent.getSelectedPair()
	if pair == nil {
		return nil
	}

	return pair.Remote.addr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}

	return c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.agent.buf.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	pair := c.agent.getSelectedPair()
	if pair == nil || pair.Local == nil {
		return nil
	}

	if d, ok := pair.Local.(interface {
		setWriteDeadline(time.Time) error
	}); ok {
		return d.setWriteDeadline(t)
	}

	return nil
}

type UDPMux interface {
	io.Closer
	GetConn(ufrag string, addr net.Addr) (net.PacketConn, error)
	RemoveConnByUfrag(ufrag string)
	GetListenAddresses() []net.Addr
}

type UDPMuxDefault struct {
	params                   UDPMuxParams
	closedChan               chan struct{}
	closeOnce                sync.Once
	connsIPv4, connsIPv6     map[string]*udpMuxedConn
	addressMapMu             sync.RWMutex
	addressMap               map[ipPort]*udpMuxedConn
	pool                     *sync.Pool
	mu                       sync.Mutex
	localAddrsForUnspecified []net.Addr
}

type UDPMuxParams struct {
	Logger        logging.LeveledLogger
	UDPConn       net.PacketConn
	UDPConnString string
	Net           transport.Net
}

func NewUDPMuxDefault(params UDPMuxParams) *UDPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}

	var localAddrsForUnspecified []net.Addr
	if udpAddr, ok := params.UDPConn.LocalAddr().(*net.UDPAddr); !ok {
		params.Logger.Errorf("LocalAddr is not a net.UDPAddr, got %T", params.UDPConn.LocalAddr())
	} else if ok && udpAddr.IP.IsUnspecified() {

		params.Logger.Warn("UDPMuxDefault should not listening on unspecified address, use NewMultiUDPMuxFromPort instead")
		var networks []NetworkType
		switch {
		case udpAddr.IP.To4() != nil:
			networks = []NetworkType{NetworkTypeUDP4}

		case udpAddr.IP.To16() != nil:
			networks = []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6}

		default:
			params.Logger.Errorf("LocalAddr expected IPV4 or IPV6, got %T", params.UDPConn.LocalAddr())
		}
		if len(networks) > 0 {
			if params.Net == nil {
				var err error
				if params.Net, err = transport.NewNet(); err != nil {
					params.Logger.Errorf("Failed to get create network: %v", err)
				}
			}

			_, addrs, err := localInterfaces(params.Net, nil, nil, networks, true)
			if err == nil {
				localAddrsForUnspecified = make([]net.Addr, len(addrs))
				for i, addr := range addrs {
					localAddrsForUnspecified[i] = &net.UDPAddr{
						IP:   addr.addr.AsSlice(),
						Port: udpAddr.Port,
						Zone: addr.addr.Zone(),
					}
				}
			} else {
				params.Logger.Errorf("Failed to get local interfaces for unspecified addr: %v", err)
			}
		}
	}
	params.UDPConnString = params.UDPConn.LocalAddr().String()

	mux := &UDPMuxDefault{
		addressMap: map[ipPort]*udpMuxedConn{},
		params:     params,
		connsIPv4:  make(map[string]*udpMuxedConn),
		connsIPv6:  make(map[string]*udpMuxedConn),
		closedChan: make(chan struct{}, 1),
		pool: &sync.Pool{
			New: func() any {

				return newBufferHolder(receiveMTU)
			},
		},
		localAddrsForUnspecified: localAddrsForUnspecified,
	}

	go mux.connWorker()

	return mux
}

func (m *UDPMuxDefault) LocalAddr() net.Addr {
	return m.params.UDPConn.LocalAddr()
}

func (m *UDPMuxDefault) GetListenAddresses() []net.Addr {
	if len(m.localAddrsForUnspecified) > 0 {
		return m.localAddrsForUnspecified
	}

	return []net.Addr{m.LocalAddr()}
}

func (m *UDPMuxDefault) GetConn(ufrag string, addr net.Addr) (net.PacketConn, error) {

	if len(m.localAddrsForUnspecified) == 0 && m.params.UDPConnString != addr.String() {
		return nil, errInvalidAddress
	}

	var isIPv6 bool
	if udpAddr, _ := addr.(*net.UDPAddr); udpAddr != nil && udpAddr.IP.To4() == nil {
		isIPv6 = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	if conn, ok := m.getConn(ufrag, isIPv6); ok {
		return conn, nil
	}

	c := m.createMuxedConn(ufrag)
	go func() {
		<-c.CloseChannel()
		m.RemoveConnByUfrag(ufrag)
	}()

	if isIPv6 {
		m.connsIPv6[ufrag] = c
	} else {
		m.connsIPv4[ufrag] = c
	}

	return c, nil
}

func (m *UDPMuxDefault) RemoveConnByUfrag(ufrag string) {
	removedConns := make([]*udpMuxedConn, 0, 2)

	m.mu.Lock()
	if c, ok := m.connsIPv4[ufrag]; ok {
		delete(m.connsIPv4, ufrag)
		removedConns = append(removedConns, c)
	}
	if c, ok := m.connsIPv6[ufrag]; ok {
		delete(m.connsIPv6, ufrag)
		removedConns = append(removedConns, c)
	}
	m.mu.Unlock()

	if len(removedConns) == 0 {

		return
	}

	m.addressMapMu.Lock()
	defer m.addressMapMu.Unlock()

	for _, c := range removedConns {
		addresses := c.getAddresses()
		for _, addr := range addresses {
			delete(m.addressMap, addr)
		}
	}
}

func (m *UDPMuxDefault) IsClosed() bool {
	select {
	case <-m.closedChan:
		return true
	default:
		return false
	}
}

func (m *UDPMuxDefault) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		for _, c := range m.connsIPv4 {
			_ = c.Close()
		}
		for _, c := range m.connsIPv6 {
			_ = c.Close()
		}

		m.connsIPv4 = make(map[string]*udpMuxedConn)
		m.connsIPv6 = make(map[string]*udpMuxedConn)

		close(m.closedChan)

		_ = m.params.UDPConn.Close()
	})

	return err
}

func (m *UDPMuxDefault) writeTo(buf []byte, rAddr net.Addr) (n int, err error) {
	return m.params.UDPConn.WriteTo(buf, rAddr)
}

func (m *UDPMuxDefault) registerConnForAddress(conn *udpMuxedConn, addr ipPort) {
	if m.IsClosed() {
		return
	}

	m.addressMapMu.Lock()
	defer m.addressMapMu.Unlock()

	existing, ok := m.addressMap[addr]
	if ok {
		existing.removeAddress(addr)
	}
	m.addressMap[addr] = conn

	m.params.Logger.Debugf("Registered %s for %s", addr.addr.String(), conn.params.Key)
}

func (m *UDPMuxDefault) createMuxedConn(key string) *udpMuxedConn {
	c := newUDPMuxedConn(&udpMuxedConnParams{
		Mux:       m,
		Key:       key,
		AddrPool:  m.pool,
		LocalAddr: m.LocalAddr(),
		Logger:    m.params.Logger,
	})

	return c
}

func (m *UDPMuxDefault) connWorker() {
	logger := m.params.Logger

	defer func() {
		_ = m.Close()
	}()

	buf := make([]byte, receiveMTU)
	for {
		n, addr, err := m.params.UDPConn.ReadFrom(buf)
		if m.IsClosed() {
			return
		} else if err != nil {
			if os.IsTimeout(err) {
				continue
			} else if !errors.Is(err, io.EOF) {
				logger.Errorf("Failed to read UDP packet: %v", err)
			}

			return
		}

		netUDPAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			logger.Errorf("Underlying PacketConn did not return a UDPAddr")

			return
		}
		udpAddr, err := newIPPort(netUDPAddr.IP, netUDPAddr.Zone, uint16(netUDPAddr.Port))
		if err != nil {
			logger.Errorf("Failed to create a new IP/Port host pair")

			return
		}

		m.addressMapMu.Lock()
		destinationConn := m.addressMap[udpAddr]
		m.addressMapMu.Unlock()

		if destinationConn == nil && stun.IsMessage(buf[:n]) {
			msg := &stun.Message{
				Raw: append([]byte{}, buf[:n]...),
			}

			if err = msg.Decode(); err != nil {
				m.params.Logger.Warnf("Failed to handle decode ICE from %s: %v", addr.String(), err)

				continue
			}

			attr, stunAttrErr := msg.Get(stun.AttrUsername)
			if stunAttrErr != nil {
				m.params.Logger.Warnf("No Username attribute in STUN message from %s", addr.String())

				continue
			}

			ufrag := strings.Split(string(attr), ":")[0]
			isIPv6 := netUDPAddr.IP.To4() == nil

			m.mu.Lock()
			destinationConn, _ = m.getConn(ufrag, isIPv6)
			m.mu.Unlock()
		}

		if destinationConn == nil {
			m.params.Logger.Tracef("Dropping packet from %s, addr: %s", udpAddr.addr, addr)

			continue
		}

		if err = destinationConn.writePacket(buf[:n], netUDPAddr); err != nil {
			m.params.Logger.Errorf("Failed to write packet: %v", err)
		}
	}
}

func (m *UDPMuxDefault) getConn(ufrag string, isIPv6 bool) (val *udpMuxedConn, ok bool) {
	if isIPv6 {
		val, ok = m.connsIPv6[ufrag]
	} else {
		val, ok = m.connsIPv4[ufrag]
	}

	return
}

type bufferHolder struct {
	next *bufferHolder
	buf  []byte
	addr *net.UDPAddr
}

func newBufferHolder(size int) *bufferHolder {
	return &bufferHolder{
		buf: make([]byte, size),
	}
}

func (b *bufferHolder) reset() {
	b.next = nil
	b.addr = nil
}

type ipPort struct {
	addr netip.Addr
	port uint16
}

func newIPPort(ip net.IP, zone string, port uint16) (ipPort, error) {
	n, ok := netip.AddrFromSlice(ip.To16())
	if !ok {
		return ipPort{}, errInvalidIPAddress
	}

	return ipPort{
		addr: n.WithZone(zone),
		port: port,
	}, nil
}

type UniversalUDPMux interface {
	UDPMux
	GetXORMappedAddr(stunAddr net.Addr, deadline time.Duration) (*stun.XORMappedAddress, error)
	GetRelayedAddr(turnAddr net.Addr, deadline time.Duration) (*net.Addr, error)
	GetConnForURL(ufrag string, url string, addr net.Addr) (net.PacketConn, error)
}

type UniversalUDPMuxDefault struct {
	*UDPMuxDefault
	params       UniversalUDPMuxParams
	xorMappedMap map[string]*xorMapped
}

type UniversalUDPMuxParams struct {
	Logger                logging.LeveledLogger
	UDPConn               net.PacketConn
	XORMappedAddrCacheTTL time.Duration
	Net                   transport.Net
}

func NewUniversalUDPMuxDefault(params UniversalUDPMuxParams) *UniversalUDPMuxDefault {
	if params.Logger == nil {
		params.Logger = logging.NewDefaultLoggerFactory().NewLogger("ice")
	}
	if params.XORMappedAddrCacheTTL == 0 {
		params.XORMappedAddrCacheTTL = time.Second * 25
	}

	mux := &UniversalUDPMuxDefault{
		params:       params,
		xorMappedMap: make(map[string]*xorMapped),
	}

	mux.params.UDPConn = &udpConn{
		PacketConn: params.UDPConn,
		mux:        mux,
		logger:     params.Logger,
	}

	udpMuxParams := UDPMuxParams{
		Logger:  params.Logger,
		UDPConn: mux.params.UDPConn,
		Net:     mux.params.Net,
	}
	mux.UDPMuxDefault = NewUDPMuxDefault(udpMuxParams)

	return mux
}

type udpConn struct {
	net.PacketConn
	mux    *UniversalUDPMuxDefault
	logger logging.LeveledLogger
}

func (m *UniversalUDPMuxDefault) GetRelayedAddr(net.Addr, time.Duration) (*net.Addr, error) {
	return nil, errNotImplemented
}

func (m *UniversalUDPMuxDefault) GetConnForURL(ufrag string, url string, addr net.Addr) (net.PacketConn, error) {
	return m.UDPMuxDefault.GetConn(fmt.Sprintf("%s%s", ufrag, url), addr)
}

func (c *udpConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}

	if stun.IsMessage(p[:n]) {
		msg := &stun.Message{
			Raw: append([]byte{}, p[:n]...),
		}

		if err = msg.Decode(); err != nil {
			c.logger.Warnf("Failed to handle decode ICE from %s: %v", addr.String(), err)

			return n, addr, nil
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {

			return n, addr, err
		}

		if c.mux.isXORMappedResponse(msg, udpAddr.String()) {
			err = c.mux.handleXORMappedResponse(udpAddr, msg)
			if err != nil {
				c.logger.Debugf("%w: %v", errGetXorMappedAddrResponse, err)
				err = nil
			}

			return n, addr, err
		}
	}

	return n, addr, err
}

func (m *UniversalUDPMuxDefault) isXORMappedResponse(msg *stun.Message, stunAddr string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.xorMappedMap[stunAddr]
	_, err := msg.Get(stun.AttrXORMappedAddress)

	return err == nil && ok
}

func (m *UniversalUDPMuxDefault) handleXORMappedResponse(stunAddr *net.UDPAddr, msg *stun.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mappedAddr, ok := m.xorMappedMap[stunAddr.String()]
	if !ok {
		return errNoXorAddrMapping
	}

	var addr stun.XORMappedAddress
	if err := addr.GetFrom(msg); err != nil {
		return err
	}

	m.xorMappedMap[stunAddr.String()] = mappedAddr
	mappedAddr.SetAddr(&addr)

	return nil
}

func (m *UniversalUDPMuxDefault) GetXORMappedAddr(
	serverAddr net.Addr,
	deadline time.Duration,
) (*stun.XORMappedAddress, error) {
	m.mu.Lock()
	mappedAddr, ok := m.xorMappedMap[serverAddr.String()]

	if ok {
		if mappedAddr.expired() {
			mappedAddr.closeWaiters()
			delete(m.xorMappedMap, serverAddr.String())
			ok = false
		} else if mappedAddr.pending() {
			ok = false
		}
	}
	m.mu.Unlock()
	if ok {
		return mappedAddr.addr, nil
	}

	waitAddrReceived, err := m.writeSTUN(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errWriteSTUNMessage, err)
	}

	select {
	case <-waitAddrReceived:

		m.mu.Lock()
		mappedAddr := *m.xorMappedMap[serverAddr.String()]
		m.mu.Unlock()
		if mappedAddr.addr == nil {
			return nil, errNoXorAddrMapping
		}

		return mappedAddr.addr, nil
	case <-time.After(deadline):
		return nil, errXORMappedAddrTimeout
	}
}

func (m *UniversalUDPMuxDefault) writeSTUN(serverAddr net.Addr) (chan struct{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	addrMap, ok := m.xorMappedMap[serverAddr.String()]
	if !ok {
		addrMap = &xorMapped{
			expiresAt:        time.Now().Add(m.params.XORMappedAddrCacheTTL),
			waitAddrReceived: make(chan struct{}),
		}
		m.xorMappedMap[serverAddr.String()] = addrMap
	}

	req, err := stun.Build(stun.BindingRequest, stun.TransactionID)
	if err != nil {
		return nil, err
	}

	if _, err = m.params.UDPConn.WriteTo(req.Raw, serverAddr); err != nil {
		return nil, err
	}

	return addrMap.waitAddrReceived, nil
}

type xorMapped struct {
	addr             *stun.XORMappedAddress
	waitAddrReceived chan struct{}
	expiresAt        time.Time
}

func (a *xorMapped) closeWaiters() {
	select {
	case <-a.waitAddrReceived:

		break
	default:

		close(a.waitAddrReceived)
	}
}

func (a *xorMapped) pending() bool {
	return a.addr == nil
}

func (a *xorMapped) expired() bool {
	return a.expiresAt.Before(time.Now())
}

func (a *xorMapped) SetAddr(addr *stun.XORMappedAddress) {
	a.addr = addr
	a.closeWaiters()
}

type udpMuxedConnState int

const (
	udpMuxedConnOpen udpMuxedConnState = iota
	udpMuxedConnWaiting
	udpMuxedConnClosed
)

type udpMuxedConnParams struct {
	Mux       *UDPMuxDefault
	AddrPool  *sync.Pool
	Key       string
	LocalAddr net.Addr
	Logger    logging.LeveledLogger
}

type udpMuxedConn struct {
	params           *udpMuxedConnParams
	addresses        []ipPort
	bufHead, bufTail *bufferHolder
	notify           chan struct{}
	closedChan       chan struct{}
	state            udpMuxedConnState
	mu               sync.Mutex
}

func newUDPMuxedConn(params *udpMuxedConnParams) *udpMuxedConn {
	return &udpMuxedConn{
		params:     params,
		notify:     make(chan struct{}, 1),
		closedChan: make(chan struct{}),
	}
}

func (c *udpMuxedConn) ReadFrom(b []byte) (n int, rAddr net.Addr, err error) {
	for {
		c.mu.Lock()
		if c.bufTail != nil {
			pkt := c.bufTail
			c.bufTail = pkt.next

			if pkt == c.bufHead {
				c.bufHead = nil
			}
			c.mu.Unlock()

			if len(b) < len(pkt.buf) {
				err = io.ErrShortBuffer
			} else {
				n = copy(b, pkt.buf)
				rAddr = pkt.addr
			}

			pkt.reset()
			c.params.AddrPool.Put(pkt)

			return n, rAddr, err
		}

		if c.state == udpMuxedConnClosed {
			c.mu.Unlock()

			return 0, nil, io.EOF
		}

		c.state = udpMuxedConnWaiting
		c.mu.Unlock()

		select {
		case <-c.notify:
		case <-c.closedChan:
			return 0, nil, io.EOF
		}
	}
}

func (c *udpMuxedConn) WriteTo(buf []byte, rAddr net.Addr) (n int, err error) {
	if c.isClosed() {
		return 0, io.ErrClosedPipe
	}

	netUDPAddr, ok := rAddr.(*net.UDPAddr)
	if !ok {
		return 0, errFailedToCastUDPAddr
	}

	port := netUDPAddr.Port
	if port < 0 || port > 0xFFFF {
		return 0, ErrPort
	}
	ipAndPort, err := newIPPort(netUDPAddr.IP, netUDPAddr.Zone, uint16(port))
	if err != nil {
		return 0, err
	}
	if !c.containsAddress(ipAndPort) {
		c.addAddress(ipAndPort)
	}

	return c.params.Mux.writeTo(buf, rAddr)
}

func (c *udpMuxedConn) LocalAddr() net.Addr {
	return c.params.LocalAddr
}

func (c *udpMuxedConn) SetDeadline(time.Time) error {
	return nil
}

func (c *udpMuxedConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *udpMuxedConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *udpMuxedConn) CloseChannel() <-chan struct{} {
	return c.closedChan
}

func (c *udpMuxedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != udpMuxedConnClosed {
		for pkt := c.bufTail; pkt != nil; {
			next := pkt.next

			pkt.reset()
			c.params.AddrPool.Put(pkt)

			pkt = next
		}
		c.bufHead = nil
		c.bufTail = nil

		c.state = udpMuxedConnClosed
		close(c.closedChan)
	}

	return nil
}

func (c *udpMuxedConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.state == udpMuxedConnClosed
}

func (c *udpMuxedConn) getAddresses() []ipPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	addresses := make([]ipPort, len(c.addresses))
	copy(addresses, c.addresses)

	return addresses
}

func (c *udpMuxedConn) addAddress(addr ipPort) {
	c.mu.Lock()
	c.addresses = append(c.addresses, addr)
	c.mu.Unlock()

	c.params.Mux.registerConnForAddress(c, addr)
}

func (c *udpMuxedConn) removeAddress(addr ipPort) {
	c.mu.Lock()
	defer c.mu.Unlock()

	newAddresses := make([]ipPort, 0, len(c.addresses))
	for _, a := range c.addresses {
		if a != addr {
			newAddresses = append(newAddresses, a)
		}
	}

	c.addresses = newAddresses
}

func (c *udpMuxedConn) containsAddress(addr ipPort) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Contains(c.addresses, addr)
}

func (c *udpMuxedConn) writePacket(data []byte, addr *net.UDPAddr) error {
	pkt := c.params.AddrPool.Get().(*bufferHolder)
	if cap(pkt.buf) < len(data) {
		c.params.AddrPool.Put(pkt)

		return io.ErrShortBuffer
	}

	pkt.buf = append(pkt.buf[:0], data...)
	pkt.addr = addr

	c.mu.Lock()
	if c.state == udpMuxedConnClosed {
		c.mu.Unlock()

		pkt.reset()
		c.params.AddrPool.Put(pkt)

		return io.ErrClosedPipe
	}

	if c.bufHead != nil {
		c.bufHead.next = pkt
	}
	c.bufHead = pkt

	if c.bufTail == nil {
		c.bufTail = pkt
	}

	state := c.state
	c.state = udpMuxedConnOpen
	c.mu.Unlock()

	if state == udpMuxedConnWaiting {
		select {
		case c.notify <- struct{}{}:
		default:
		}
	}

	return nil
}

type (
	URL = stun.URI

	ProtoType = stun.ProtoType

	SchemeType = stun.SchemeType
)

const (
	SchemeTypeSTUN = stun.SchemeTypeSTUN

	SchemeTypeSTUNS = stun.SchemeTypeSTUNS

	SchemeTypeTURN = stun.SchemeTypeTURN

	SchemeTypeTURNS = stun.SchemeTypeTURNS
)

const (
	ProtoTypeUDP = stun.ProtoTypeUDP

	ProtoTypeTCP = stun.ProtoTypeTCP
)

const Unknown = 0

var ParseURL = stun.ParseURI

var NewSchemeType = stun.NewSchemeType

var NewProtoType = stun.NewProtoType

type UseCandidateAttr struct{}

func (UseCandidateAttr) AddTo(m *stun.Message) error {
	m.Add(stun.AttrUseCandidate, nil)

	return nil
}

func (UseCandidateAttr) IsSet(m *stun.Message) bool {
	_, err := m.Get(stun.AttrUseCandidate)

	return err == nil
}

func UseCandidate() UseCandidateAttr {
	return UseCandidateAttr{}
}
