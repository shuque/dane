package dane

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
)

const bufsize = 2048

//
// DoXMPP connects to an XNPP server, issue a STARTTLS command, negotiates
// TLS and returns a TLS connection. See RFC 6120, Section 5.4.2 for details.
//
func DoXMPP(tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	var servicename, rolename string
	var line, transcript string

	buf := make([]byte, bufsize)

	server := daneconfig.Server
	conn, err := getTCPconn(server.Ipaddr, server.Port, daneconfig.TimeoutTCP)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	if daneconfig.Servicename != "" {
		servicename = daneconfig.Servicename
	} else {
		servicename = server.Name
	}

	switch daneconfig.Appname {
	case "xmpp-client":
		rolename = "client"
	case "xmpp-server":
		rolename = "server"
	}

	// send initial stream header
	outstring := fmt.Sprintf(
		"<?xml version='1.0'?><stream:stream to='%s' "+
			"version='1.0' xml:lang='en' xmlns='jabber:%s' "+
			"xmlns:stream='http://etherx.jabber.org/streams'>",
		servicename, rolename)
	transcript += fmt.Sprintf("send: %s\n", outstring)
	writer.WriteString(outstring)
	writer.Flush()

	// read response stream header; look for STARTTLS feature support
	_, err = reader.Read(buf)
	if err != nil {
		return nil, err
	}
	line = string(buf)
	transcript += fmt.Sprintf("recv: %s\n", line)
	gotSTARTTLS := false
	if strings.Contains(line, "<starttls") && strings.Contains(line,
		"urn:ietf:params:xml:ns:xmpp-tls") {
		gotSTARTTLS = true
	}
	if !gotSTARTTLS {
		return nil, fmt.Errorf("XMPP STARTTLS unavailable")
	}

	// issue STARTTLS command
	outstring = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
	transcript += fmt.Sprintf("send: %s\n", outstring)
	writer.WriteString(outstring + "\r\n")
	writer.Flush()

	// read response and look for proceed element
	_, err = reader.Read(buf)
	if err != nil {
		return nil, err
	}
	line = string(buf)
	transcript += fmt.Sprintf("recv: %s\n", line)
	if !strings.Contains(line, "<proceed") {
		return nil, fmt.Errorf("XMPP STARTTLS command failed")
	}

	daneconfig.Transcript = transcript
	return TLShandshake(conn, tlsconfig)
}

//
// DoPOP3 connects to a POP3 server, sends the STLS command, negotiates TLS,
// and returns a TLS connection.
//
func DoPOP3(tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	var line, transcript string

	server := daneconfig.Server
	conn, err := getTCPconn(server.Ipaddr, server.Port, daneconfig.TimeoutTCP)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read POP3 greeting
	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	transcript += fmt.Sprintf("recv: %s\n", line)

	// Send STLS command
	transcript += "send: STLS\n"
	writer.WriteString("STLS\r\n")
	writer.Flush()

	// Read STLS response, look for +OK
	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	transcript += fmt.Sprintf("recv: %s\n", line)
	if !strings.HasPrefix(line, "+OK") {
		return nil, fmt.Errorf("POP3 STARTTLS unavailable")
	}

	daneconfig.Transcript = transcript
	return TLShandshake(conn, tlsconfig)
}

//
// DoIMAP connects to an IMAP server, issues a STARTTLS command, negotiates
// TLS, and returns a TLS connection.
//
func DoIMAP(tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	var gotSTARTTLS bool
	var line, transcript string

	server := daneconfig.Server
	conn, err := getTCPconn(server.Ipaddr, server.Port, daneconfig.TimeoutTCP)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read IMAP greeting
	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	transcript += fmt.Sprintf("recv: %s\n", line)

	// Send Capability command, read response, looking for STARTTLS
	transcript += "send: . CAPABILITY\n"
	writer.WriteString(". CAPABILITY\r\n")
	writer.Flush()

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		transcript += fmt.Sprintf("recv: %s\n", line)
		if strings.HasPrefix(line, "* CAPABILITY") && strings.Contains(line, "STARTTLS") {
			gotSTARTTLS = true
		}
		if strings.HasPrefix(line, ". OK") {
			break
		}
	}

	if !gotSTARTTLS {
		return nil, fmt.Errorf("IMAP STARTTLS capability unavailable")
	}

	// Send STARTTLS
	transcript += "send: . STARTTLS\n"
	writer.WriteString(". STARTTLS\r\n")
	writer.Flush()

	// Look for OK response
	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	transcript += fmt.Sprintf("recv: %s\n", line)
	if !strings.HasPrefix(line, ". OK") {
		return nil, fmt.Errorf("STARTTLS failed to negotiate")
	}

	daneconfig.Transcript = transcript
	return TLShandshake(conn, tlsconfig)
}

//
// parseSMTPline parses an SMTP protocol line, and returns the replycode,
// command string, whether the response is done (for a multi-line response),
// and an error (on failure).
//
func parseSMTPline(line string) (int, string, bool, error) {

	var responseDone = false

	replycode, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", responseDone, fmt.Errorf("invalid reply code: %s", line)
	}
	if line[3] != '-' {
		responseDone = true
	}
	rest := line[4:]
	return replycode, rest, responseDone, err
}

//
// DoSMTP connects to an SMTP server, checks for STARTTLS support, negotiates
// TLS, and returns a TLS connection.
//
func DoSMTP(tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	var replycode int
	var line, rest, transcript string
	var responseDone, gotSTARTTLS bool

	server := daneconfig.Server
	conn, err := getTCPconn(server.Ipaddr, server.Port, daneconfig.TimeoutTCP)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read possibly multi-line SMTP greeting
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		transcript += fmt.Sprintf("recv: %s\n", line)
		replycode, _, responseDone, err = parseSMTPline(line)
		if err != nil {
			return nil, err
		}
		if responseDone {
			break
		}
	}
	if replycode != 220 {
		return nil, fmt.Errorf("invalid reply code (%d) in SMTP greeting", replycode)
	}

	// Send EHLO, read possibly multi-line response, look for STARTTLS
	transcript += "send: EHLO localhost\n"
	writer.WriteString("EHLO localhost\r\n")
	writer.Flush()

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		transcript += fmt.Sprintf("recv: %s\n", line)
		replycode, rest, responseDone, err = parseSMTPline(line)
		if err != nil {
			return nil, err
		}
		if replycode != 250 {
			return nil, fmt.Errorf("invalid reply code in EHLO response")
		}
		if strings.Contains(rest, "STARTTLS") {
			gotSTARTTLS = true
		}
		if responseDone {
			break
		}
	}

	if !gotSTARTTLS {
		return nil, fmt.Errorf("SMTP STARTTLS support not detected")
	}

	// Send STARTTLS command and read success reply code
	transcript += "send: STARTTLS\n"
	writer.WriteString("STARTTLS\r\n")
	writer.Flush()

	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	transcript += fmt.Sprintf("recv: %s\n", line)
	replycode, _, _, err = parseSMTPline(line)
	if err != nil {
		return nil, err
	}
	if replycode != 220 {
		return nil, fmt.Errorf("invalid reply code to STARTTLS command")
	}

	daneconfig.Transcript = transcript
	return TLShandshake(conn, tlsconfig)
}

//
// StartTLS -
//
func StartTLS(tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	switch daneconfig.Appname {
	case "smtp":
		return DoSMTP(tlsconfig, daneconfig)
	case "imap":
		return DoIMAP(tlsconfig, daneconfig)
	case "pop3":
		return DoPOP3(tlsconfig, daneconfig)
	case "xmpp-client", "xmpp-server":
		return DoXMPP(tlsconfig, daneconfig)
	default:
		return nil, fmt.Errorf("unknown STARTTLS application: %s", daneconfig.Appname)
	}
}
