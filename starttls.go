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
// DoXMPP -
// See RFC 6120, Section 5.4.2 for details
//
func DoXMPP(server *Server, tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	var servicename, rolename, line string
	buf := make([]byte, bufsize)

	conn, err := getTCPconn(server.Ipaddr, server.Port)
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
	writer.WriteString(outstring)
	writer.Flush()

	// read response stream header; look for STARTTLS feature support
	_, err = reader.Read(buf)
	if err != nil {
		return nil, err
	}
	line = string(buf)
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
	writer.WriteString(outstring + "\r\n")
	writer.Flush()

	// read response and look for proceed element
	_, err = reader.Read(buf)
	if err != nil {
		return nil, err
	}
	line = string(buf)
	if !strings.Contains(line, "<proceed") {
		return nil, fmt.Errorf("XMPP STARTTLS command failed")
	}

	return TLShandshake(conn, tlsconfig)
}

//
// DoPOP3 -
//
func DoPOP3(server *Server, tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	var line string

	conn, err := getTCPconn(server.Ipaddr, server.Port)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read POP3 greeting
	_, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	// Send STLS command
	writer.WriteString("STLS\r\n")
	writer.Flush()

	// Read STLS response, look for +OK
	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "+OK") {
		return nil, fmt.Errorf("POP3 STARTTLS unavailable")
	}

	return TLShandshake(conn, tlsconfig)
}

//
// DoIMAP -
//
func DoIMAP(server *Server, tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	var gotSTARTTLS bool
	var line string

	conn, err := getTCPconn(server.Ipaddr, server.Port)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read IMAP greeting
	_, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	// Send Capability command, read response, looking for STARTTLS
	writer.WriteString(". CAPABILITY\r\n")
	writer.Flush()

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
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
	writer.WriteString(". STARTTLS\r\n")
	writer.Flush()

	// Look for OK response
	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, ". OK") {
		return nil, fmt.Errorf("STARTTLS failed to negotiate")
	}

	return TLShandshake(conn, tlsconfig)
}

//
// parseSMTPline -
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
// DoSMTP -
//
func DoSMTP(server *Server, tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	var replycode int
	var line, rest string
	var responseDone, gotSTARTTLS bool

	conn, err := getTCPconn(server.Ipaddr, server.Port)
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
		replycode, _, responseDone, err = parseSMTPline(line)
		if err != nil {
			return nil, err
		}
		if responseDone {
			break
		}
	}
	if replycode != 220 {
		return nil, fmt.Errorf("invalid reply code in SMTP greeting")
	}

	// Send EHLO, read possibly multi-line response, look for STARTTLS
	writer.WriteString("EHLO localhost\r\n")
	writer.Flush()

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
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
	writer.WriteString("STARTTLS\r\n")
	writer.Flush()

	line, err = reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	replycode, _, _, err = parseSMTPline(line)
	if err != nil {
		return nil, err
	}
	if replycode != 220 {
		return nil, fmt.Errorf("invalid reply code to STARTTLS command")
	}

	return TLShandshake(conn, tlsconfig)
}

//
// StartTLS -
//
func StartTLS(server *Server, tlsconfig *tls.Config, daneconfig *Config) (*tls.Conn, error) {

	switch daneconfig.Appname {
	case "smtp":
		return DoSMTP(server, tlsconfig, daneconfig)
	case "imap":
		return DoIMAP(server, tlsconfig, daneconfig)
	case "pop3":
		return DoPOP3(server, tlsconfig, daneconfig)
	case "xmpp-client", "xmpp-server":
		return DoXMPP(server, tlsconfig, daneconfig)
	default:
		return nil, fmt.Errorf("Unknown STARTTLS application: %s", daneconfig.Appname)
	}
}
