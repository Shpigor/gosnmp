package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	g "github.com/gosnmp/gosnmp"
	"github.com/rs/zerolog/log"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var waitTimeSeconds int
var address string
var caCertPath string
var certPath string
var keyPath string

var caCert *x509.Certificate
var certPool *x509.CertPool

func init() {
	var err error
	flag.StringVar(&address, "h", "192.168.7.185:1620", "connection address to the HAProxy.")
	flag.IntVar(&waitTimeSeconds, "w", 60, "waiting time in seconds before close connection")
	flag.StringVar(&caCertPath, "ca", "examples/tsm/ca.pem", "path to ca certificate file.")
	flag.StringVar(&certPath, "c", "examples/tsm/cert.pem", "path to certificate file.")
	flag.StringVar(&keyPath, "k", "examples/tsm/private.key", "path to private key file.")
	flag.Parse()
	certPool = x509.NewCertPool()
	caCert, err = parseCertFile(caCertPath)
	if err != nil {
		log.Error().Msgf("can't parse ca certificate file: %+v", err)
		os.Exit(127)
	}
	certPool.AddCert(caCert)
}

func main() {
	mainCtx, mainCancel := context.WithCancel(context.Background())
	listenSysSignal(mainCancel)
	conn, err := openConnection()
	if err != nil {
		log.Error().Msgf("got error while connecting to tcp server: %+v", err)
	} else {
		go processConnection(conn)
		sendSnmpTrap(conn)
	}
	<-mainCtx.Done()
}

func openConnection() (net.Conn, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Error().Msgf("got error while parsing private key: %+v", err)
		return nil, err
	}
	return tls.Dial("tcp", address, &tls.Config{
		Certificates:          []tls.Certificate{cert},
		RootCAs:               certPool,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: validateServerCert,
		VerifyConnection:      verifyConnection,
	})
}

func sendSnmpTrap(conn net.Conn) {

	// Create an SNMP PDU
	pduObject := g.SnmpPDU{
		Name:  "1.3.6.1.6.3.1.1.4.1.0", // sysDescr
		Type:  g.ObjectIdentifier,
		Value: "1.3.6.1.4.1.6232.8.1.4.5",
	}
	pduMac := g.SnmpPDU{
		Name:  "1.3.6.1.4.1.6232.8.1.4.1.0",
		Type:  g.OctetString,
		Value: "000BC216FE32",
	}

	// Create an SNMP packet
	packet := g.SnmpPacket{
		Version:       g.Version3,
		PDUType:       g.SNMPv2Trap,
		SecurityModel: g.TransportSecurityModel,
		//Variables:       []g.SnmpPDU{pduObject, pduMac, pduIp, pduData, pduData2, pduFirmware},
		Variables:          []g.SnmpPDU{pduObject, pduMac},
		MsgFlags:           g.AuthNoPriv | g.Reportable,
		ContextEngineID:    "8000185803000bc21713e2",
		MsgID:              1,
		RequestID:          1,
		Error:              0,
		ErrorIndex:         0,
		MsgMaxSize:         65507,
		Logger:             g.NewLogger(&log.Logger),
		SecurityParameters: &g.TsmSecurityParameters{},
	}

	// Send the SNMP packet over the TLS connection
	log.Info().Msgf("SNMP packet: %s", packet.SafeString())
	bytes, err := packet.MarshalMsg()
	if err != nil {
		log.Error().Msgf("package marshal error: %s", err)
	}
	_, err = conn.Write(bytes)
	if err != nil {
		log.Error().Msgf("client: write: %s", err)
	}
}

func verifyConnection(state tls.ConnectionState) error {
	//resp, err := ocsp.ParseResponse(state.OCSPResponse, caCert)
	//if err != nil {
	//	log.Error().Msgf("got error while parsing OCSP response: %+v", err)
	//	return err
	//}
	//log.Printf("Verifying peer connection: [%+v, %+v] %d - %d", resp.ProducedAt, resp.NextUpdate, resp.SerialNumber, resp.Status)
	return nil
}

func validateServerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	_, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		log.Error().Msgf("Verifying peer certificate error: %+v", err)
		return err
	}
	//log.Info().Msgf("server side certificate: %+v", serverCert)
	return nil
}

func parseCertFile(filename string) (*x509.Certificate, error) {
	certFileBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certFileBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func processConnection(conn net.Conn) {
	buffer := make([]byte, 65535)
	for {
		n, err := conn.Read(buffer)
		if err != nil && err == io.EOF {
			log.Error().Msgf("got error while reading data: %+v", err)
			return
		}
		log.Info().Msgf("received data: %s", string(buffer[:n]))
	}
}

func listenSysSignal(cancel context.CancelFunc) {
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel)
	go func() {
		for {
			sig := <-signalChannel
			if sig == syscall.SIGTERM {
				log.Info().Msg("Got kill signal. ")
				log.Info().Msg("Program will terminate now.")
				cancel()
			} else if sig == syscall.SIGINT {
				log.Info().Msg("Got CTRL+C signal")
				log.Info().Msg("Closing.")
				cancel()
			} else {
				log.Trace().Msgf("Ignoring signal: %d", sig)
			}
		}
	}()
}
