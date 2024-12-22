package gosnmp

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

var empty = &TsmSecurityParameters{}

type TsmSecurityParameters struct {
	mu                      sync.Mutex
	EnableEngineIdDiscovery bool
	SecurityName            []byte
	EngineID                []byte
	TMStateReference        []byte
	TransportDomain         []byte
	TransportAddress        []byte
	TransportProtection     []byte
	Logger                  Logger
}

func (sp *TsmSecurityParameters) Log() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	sp.Logger.Printf("SECURITY PARAMETERS:%s", sp.SafeString())
}

func (sp *TsmSecurityParameters) Copy() SnmpV3SecurityParameters {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return &TsmSecurityParameters{
		SecurityName:            sp.SecurityName,
		EnableEngineIdDiscovery: sp.EnableEngineIdDiscovery,
		EngineID:                sp.EngineID,
		TMStateReference:        sp.TMStateReference,
		TransportDomain:         sp.TransportDomain,
		TransportAddress:        sp.TransportAddress,
		TransportProtection:     sp.TransportProtection,
		Logger:                  sp.Logger,
	}
}

func (sp *TsmSecurityParameters) Description() string {
	var sb strings.Builder
	sb.WriteString("SecurityName=")
	sb.Write(sp.SecurityName)

	sb.WriteString(",EngineID=(")
	sb.WriteString(hex.EncodeToString(sp.EngineID))
	sb.WriteString(")")

	return sb.String()
}

func (sp *TsmSecurityParameters) SafeString() string {
	return fmt.Sprintf("AuthoritativeEngineID:%s, AuthoritativeEngineBoots:%d", sp.SecurityName, sp.EngineID)
}

func (sp *TsmSecurityParameters) InitPacket(packet *SnmpPacket) error {
	return nil
}

func (sp *TsmSecurityParameters) InitSecurityKeys() error {
	return nil
}

func (sp *TsmSecurityParameters) validate(flags SnmpV3MsgFlags) error {
	return nil
}

func (sp *TsmSecurityParameters) init(log Logger) error {
	sp.Logger = log
	return nil
}

func (sp *TsmSecurityParameters) discoveryRequired() *SnmpPacket {
	if sp.EnableEngineIdDiscovery && len(sp.EngineID) == 0 {
		var emptyPdus []SnmpPDU

		// send blank packet to discover authoriative engine ID/boots/time
		blankPacket := &SnmpPacket{
			Version:            Version3,
			MsgFlags:           Reportable | NoAuthNoPriv,
			SecurityModel:      TransportSecurityModel,
			SecurityParameters: &TsmSecurityParameters{Logger: sp.Logger},
			PDUType:            GetRequest,
			Logger:             sp.Logger,
			Variables:          emptyPdus,
		}
		return blankPacket
	}
	return nil
}

func (sp *TsmSecurityParameters) getDefaultContextEngineID() string {
	if len(sp.EngineID) == 0 {
		return ""
	}
	return string(sp.EngineID)
}

func (sp *TsmSecurityParameters) setSecurityParameters(in SnmpV3SecurityParameters) error {
	return nil
}

func (sp *TsmSecurityParameters) marshal(flags SnmpV3MsgFlags) ([]byte, error) {
	return []byte{}, nil
}

func (sp *TsmSecurityParameters) unmarshal(flags SnmpV3MsgFlags, packet []byte, cursor int) (int, error) {
	return cursor, nil
}

func (sp *TsmSecurityParameters) authenticate(packet []byte) error {
	return nil
}

func (sp *TsmSecurityParameters) isAuthentic(packetBytes []byte, packet *SnmpPacket) (bool, error) {
	s, ok := packet.SecurityParameters.(*TsmSecurityParameters)
	if !ok || s == nil {
		return false, fmt.Errorf("param SnmpV3SecurityParameters is not of type *TsmSecurityParameters")
	}
	return true, nil
}

func (sp *TsmSecurityParameters) encryptPacket(scopedPdu []byte) ([]byte, error) {
	return scopedPdu, nil
}

func (sp *TsmSecurityParameters) decryptPacket(packet []byte, cursor int) ([]byte, error) {
	return packet, nil
}

func (sp *TsmSecurityParameters) getIdentifier() string {
	if len(sp.EngineID) == 0 {
		return ""
	}
	return string(sp.EngineID)
}

func (sp *TsmSecurityParameters) getLogger() Logger {
	return sp.Logger
}

func (sp *TsmSecurityParameters) setLogger(logger Logger) {
	sp.Logger = logger
}
