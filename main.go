package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
)

// Global command-line flags
var (
	insecure      = flag.Bool("k", true, "Ignore certificate errors (default: true)")
	headOnly      = flag.Bool("I", false, "Fetch response headers only")
	verbose       = flag.Bool("v", false, "Enable verbose logging, including TLS handshake, packets, and ClientHello details")
	help          = flag.Bool("help", false, "Show usage help information")
	requestURL    string
	httpProxyAddr = flag.String("L", "", "Run HTTP proxy on specified address (e.g., http://:8080)")
	dohURL        = flag.String("doh", "https://ns.net.kg/dns-query", "DNS over HTTPS resolver URL")
)

// customDial handles TCP connections with IPv6 preference
func customDial(network, addr, serverName string) (net.Conn, error) {
	if *verbose {
		log.Printf("[VERBOSE] Dialing TCP with IPv6 preference: network=%s, addr=%s", network, addr)
	}

	// Create a dialer with IPv6 preference
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Force IPv6 for resolver connections
				return net.Dial("tcp6", address)
			},
		},
	}

	// Try IPv6 first
	conn, err := dialer.Dial("tcp6", addr)
	if err != nil {
		if *verbose {
			log.Printf("[VERBOSE] IPv6 connection failed, falling back to IPv4: %v", err)
		}
		// Fallback to IPv4
		conn, err = dialer.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
	}

	if *verbose {
		log.Printf("[VERBOSE] TCP connection established: local=%s, remote=%s", conn.LocalAddr(), conn.RemoteAddr())
	}

	return conn, nil
}

// fetchECHConfigBytes queries ECHConfig via DNS HTTPS records and returns raw bytes
func fetchECHConfigBytes(domain string) ([]byte, error) {
	c := new(dns.Client)
	c.Net = "tcp6" // Prefer IPv6 for DNS queries
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	r, _, err := c.Exchange(m, "[2001:4860:4860::8888]:53") // Use Google's IPv6 DNS
	if err != nil {
		if *verbose {
			log.Printf("[VERBOSE] IPv6 DNS query failed, trying IPv4: %v", err)
		}
		// Fallback to IPv4
		r, _, err = c.Exchange(m, "8.8.8.8:53")
		if err != nil {
			return nil, err
		}
	}
	for _, ans := range r.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, param := range https.Value {
				if *verbose {
					fmt.Printf("[DEBUG] Parameter: %+v, Type: %T\n", param, param)
				}
				if param.Key() == 5 { // ECH parameter
					var echBytes []byte
					if v, ok := getFieldBytes(param, "Value"); ok {
						echBytes = v
					} else if d, ok := getFieldBytes(param, "Data"); ok {
						echBytes = d
					} else if s := param.String(); s != "" {
						if *verbose {
							fmt.Printf("[DEBUG] Attempting to decode base64 from param.String(): %s\n", s)
						}
						b64 := s
						data, err := base64.StdEncoding.DecodeString(b64)
						if err != nil {
							data, err = base64.RawURLEncoding.DecodeString(b64)
						}
						if err == nil && len(data) > 0 {
							if *verbose {
								fmt.Printf("[DEBUG] base64 decoded successfully, length=%d\n", len(data))
							}
							echBytes = data
						}
					}
					if len(echBytes) > 0 {
						if *verbose {
							cfgs, err := utls.UnmarshalECHConfigs(echBytes)
							if err != nil {
								fmt.Printf("[VERBOSE] Failed to parse ECHConfigList: %v\n", err)
							} else {
								fmt.Printf("[VERBOSE] ECHConfigList contains %d configurations:\n", len(cfgs))
								for i, cfg := range cfgs {
									fmt.Printf("[VERBOSE] Config[%d]: %+v\n", i, cfg)
								}
							}
						}
						return echBytes, nil
					}
					if *verbose {
						fmt.Printf("[DEBUG] Found ECH parameter but no Value/Data field, and base64 decoding failed: %+v\n", param)
					}
				}
			}
		}
	}
	return nil, nil // Not found
}

// getFieldBytes uses reflection to get []byte field named 'name'
func getFieldBytes(obj interface{}, name string) ([]byte, bool) {
	val := reflect.ValueOf(obj)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	field := val.FieldByName(name)
	if field.IsValid() && field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8 {
		return field.Bytes(), true
	}
	return nil, false
}

// newUTLSConn creates a TLS connection with verbose logging and fingerprint spoofing
func newUTLSConn(network, addr, serverName string) (net.Conn, error) {
	if *verbose {
		log.Printf("[VERBOSE] Using ServerName=%q", serverName)
	}

	conn, err := customDial(network, addr, serverName)
	if err != nil {
		return nil, err
	}

	var verifyFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	if *insecure {
		verifyFunc = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil // Skip all verification
		}
	}

	echConfigBytes, _ := fetchECHConfigBytes(serverName)
	var config *utls.Config
	var clientHelloID utls.ClientHelloID
	if len(echConfigBytes) > 0 {
		if *verbose {
			log.Printf("[VERBOSE] Found ECH config for %s, using ECH handshake, bytes: %d", serverName, len(echConfigBytes))
		}
		config = &utls.Config{
			InsecureSkipVerify:             *insecure,
			ServerName:                     serverName,
			MinVersion:                     utls.VersionTLS13,
			MaxVersion:                     utls.VersionTLS13,
			VerifyPeerCertificate:          verifyFunc,
			EncryptedClientHelloConfigList: echConfigBytes,
		}
		clientHelloID = utls.HelloGolang
		uConn := utls.UClient(conn, config, clientHelloID)
		if *verbose {
			log.Printf("[VERBOSE] TLS Client Hello details (fingerprint: golang default):")
			log.Printf("[VERBOSE]   Supported Versions: %v", getSupportedVersions(config.MinVersion, config.MaxVersion))
			log.Printf("[VERBOSE]   ServerName=%s", config.ServerName)
		}
		if err := uConn.Handshake(); err != nil {
			conn.Close()
			if *verbose {
				log.Printf("[VERBOSE] TLS handshake failed: %v", err)
			}
			return nil, fmt.Errorf("TLS handshake failed: %v", err)
		}
		if *verbose {
			state := uConn.ConnectionState()
			log.Printf("[VERBOSE] TLS handshake completed: version=%s, cipher suite=%s, ServerName=%s",
				tlsVersionToString(state.Version), cipherSuiteToString(state.CipherSuite), state.ServerName)
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				log.Printf("[VERBOSE] Server certificate: subject=%s, issuer=%s, SANs=%v",
					cert.Subject, cert.Issuer, cert.DNSNames)
			} else {
				log.Printf("[VERBOSE] No server certificates received")
			}
		}
		return uConn, nil
	} else {
		if *verbose {
			log.Printf("[VERBOSE] No ECH config for %s, using fallback handshake", serverName)
		}
		config = &utls.Config{
			InsecureSkipVerify:    *insecure,
			ServerName:            "", // Non-ECH domain uses empty ServerName first
			MinVersion:            utls.VersionTLS12,
			MaxVersion:            utls.VersionTLS13,
			VerifyPeerCertificate: verifyFunc,
		}
		clientHelloID = utls.HelloGolang
		uConn := utls.UClient(conn, config, clientHelloID)
		if *verbose {
			log.Printf("[VERBOSE] TLS Client Hello details (fallback, empty ServerName):")
		}
		if err := uConn.Handshake(); err != nil {
			if *verbose {
				log.Printf("[VERBOSE] TLS handshake with empty ServerName failed: %v", err)
				log.Printf("[VERBOSE] Retrying with ServerName=%s", serverName)
			}
			conn.Close()
			conn2, err2 := customDial(network, addr, serverName)
			if err2 != nil {
				return nil, err2
			}
			config2 := &utls.Config{
				InsecureSkipVerify:    *insecure,
				ServerName:            serverName,
				MinVersion:            utls.VersionTLS12,
				MaxVersion:            utls.VersionTLS13,
				VerifyPeerCertificate: verifyFunc,
			}
			uConn2 := utls.UClient(conn2, config2, clientHelloID)
			if err := uConn2.Handshake(); err != nil {
				conn2.Close()
				if *verbose {
					log.Printf("[VERBOSE] TLS handshake with ServerName=%s failed: %v", serverName, err)
				}
				return nil, fmt.Errorf("TLS handshake failed (retry): %v", err)
			}
			if *verbose {
				state := uConn2.ConnectionState()
				log.Printf("[VERBOSE] TLS handshake completed (retry): version=%s, cipher suite=%s, ServerName=%s",
					tlsVersionToString(state.Version), cipherSuiteToString(state.CipherSuite), state.ServerName)
				if len(state.PeerCertificates) > 0 {
					cert := state.PeerCertificates[0]
					log.Printf("[VERBOSE] Server certificate: subject=%s, issuer=%s, SANs=%v",
						cert.Subject, cert.Issuer, cert.DNSNames)
				} else {
					log.Printf("[VERBOSE] No server certificates received (retry)")
				}
			}
			return uConn2, nil
		}
		if *verbose {
			state := uConn.ConnectionState()
			log.Printf("[VERBOSE] TLS handshake completed: version=%s, cipher suite=%s, ServerName=%s",
				tlsVersionToString(state.Version), cipherSuiteToString(state.CipherSuite), state.ServerName)
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				log.Printf("[VERBOSE] Server certificate: subject=%s, issuer=%s, SANs=%v",
					cert.Subject, cert.Issuer, cert.DNSNames)
			} else {
				log.Printf("[VERBOSE] No server certificates received")
			}
		}
		return uConn, nil
	}
}

// tlsVersionToString converts TLS version to string
func tlsVersionToString(version uint16) string {
	switch version {
	case utls.VersionTLS13:
		return "TLS1.3"
	case utls.VersionTLS12:
		return "TLS1.2"
	case utls.VersionTLS11:
		return "TLS1.1"
	case utls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("Unknown(%d)", version)
	}
}

// cipherSuiteToString converts cipher suite to string
func cipherSuiteToString(cipherSuite uint16) string {
	switch cipherSuite {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0xC02F:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xC030:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	default:
		return fmt.Sprintf("Unknown(0x%x)", cipherSuite)
	}
}

// getSupportedVersions gets supported TLS versions
func getSupportedVersions(minVersion, maxVersion uint16) []string {
	versions := []uint16{minVersion}
	if maxVersion > minVersion {
		for v := minVersion + 1; v <= maxVersion; v++ {
			versions = append(versions, v)
		}
	}
	var vers []string
	for _, v := range versions {
		vers = append(vers, tlsVersionToString(v))
	}
	return vers
}

func newCustomTransport(ipAddr, serverName string) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if *verbose {
				log.Printf("[VERBOSE] DialTLSContext: network=%s, addr=%s, serverName=%s", network, ipAddr, serverName)
			}
			return newUTLSConn(network, ipAddr, serverName)
		},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
	}
}

// dohQueryAAAARecord queries AAAA record via DoH and returns the last IPv6 address
func dohQueryAAAARecord(domain string) (string, error) {
	url := fmt.Sprintf("%s?name=%s&type=AAAA", *dohURL, domain)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{}
				// Try IPv6 first
				conn, err := dialer.DialContext(ctx, "tcp6", addr)
				if err != nil {
					if *verbose {
						log.Printf("[VERBOSE] DoH IPv6 connection failed, falling back to IPv4: %v", err)
					}
					return dialer.DialContext(ctx, "tcp", addr)
				}
				return conn, nil
			},
		},
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH query for %s failed: %v", domain, err)
	}
	defer resp.Body.Close()
	var result struct {
		Answer []struct {
			Data string `json:"data"`
			Type int    `json:"type"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("Failed to parse DoH response: %v", err)
	}
	for _, ans := range result.Answer {
		if ans.Type == 28 { // AAAA record
			if *verbose {
				log.Printf("[VERBOSE] DoH resolved %s to IPv6 %s", domain, ans.Data)
			}
			return ans.Data, nil
		}
	}
	// Fallback to A record if no AAAA record found
	if *verbose {
		log.Printf("[VERBOSE] No AAAA record found for %s, falling back to A record", domain)
	}
	return dohQueryARecord(domain)
}

// dohQueryARecord queries A record via DoH and returns the last IP
func dohQueryARecord(domain string) (string, error) {
	url := fmt.Sprintf("%s?name=%s&type=A", *dohURL, domain)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{}
				// Try IPv6 first
				conn, err := dialer.DialContext(ctx, "tcp6", addr)
				if err != nil {
					if *verbose {
						log.Printf("[VERBOSE] DoH IPv6 connection failed, falling back to IPv4: %v", err)
					}
					return dialer.DialContext(ctx, "tcp", addr)
				}
				return conn, nil
			},
		},
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH query for %s failed: %v", domain, err)
	}
	defer resp.Body.Close()
	var result struct {
		Answer []struct {
			Data string `json:"data"`
			Type int    `json:"type"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("Failed to parse DoH response: %v", err)
	}
	for _, ans := range result.Answer {
		if ans.Type == 1 { // A record
			if *verbose {
				log.Printf("[VERBOSE] DoH resolved %s to IPv4 %s", domain, ans.Data)
			}
			return ans.Data, nil
		}
	}
	return "", fmt.Errorf("No A record found for %s", domain)
}

// loadCA loads or generates CA certificate and private key
func loadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		log.Printf("[HTTPPROXY] CA files not found, generating new CA: %s, %s", certFile, keyFile)
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		caTmpl := x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "MyMITMCA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caKey.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})
		if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			return nil, nil, err
		}
		log.Printf("[HTTPPROXY] New CA generated and saved to %s, %s", certFile, keyFile)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(keyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return caCert, caKey, nil
}

// generateCertForDomain generates a certificate for the domain
func generateCertForDomain(domain string, caCert *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// doSmartRequest performs the HTTP request with DoH resolution
func doSmartRequest(origReq *http.Request) (*http.Response, error) {
	parsedURL := origReq.URL
	origHost := parsedURL.Hostname()
	if origHost == "" && origReq.Host != "" {
		origHost = origReq.Host
	}
	port := "443"
	ip, err := dohQueryAAAARecord(origHost)
	if err != nil {
		log.Printf("[doSmartRequest] [ERROR] DoH resolution for %s failed: %v", origHost, err)
		return nil, fmt.Errorf("[ERROR] DoH resolution for %s failed: %v", origHost, err)
	}
	// Ensure IPv6 address is properly formatted with brackets
	sni := origHost
	if *verbose {
		log.Printf("[doSmartRequest] Request: URL=%s, Method=%s, Host=%s, Headers=%v", origReq.URL.String(), origReq.Method, origReq.Host, origReq.Header)
		log.Printf("[doSmartRequest] Outbound: IP=%s, Port=%s, SNI=%s", ip, port, sni)
	}

	client := &http.Client{
		Transport: newCustomTransport(net.JoinHostPort(ip, port), sni),
	}

	var fullURL string
	if origReq.URL.Scheme == "" {
		fullURL = "https://" + origHost + origReq.URL.RequestURI()
	} else {
		fullURL = origReq.URL.String()
	}

	req, err := http.NewRequest(origReq.Method, fullURL, origReq.Body)
	if err != nil {
		log.Printf("[doSmartRequest] [ERROR] Failed to create request: %v", err)
		return nil, err
	}
	for k, v := range origReq.Header {
		req.Header[k] = v
	}
	if origReq.Host != "" {
		req.Host = origReq.Host
	}

	if *verbose {
		log.Printf("[doSmartRequest] Sending request to %s", req.URL.String())
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[doSmartRequest] [ERROR] client.Do failed: %v", err)
		return nil, err
	}

	if *verbose {
		log.Printf("[doSmartRequest] Response: Status=%s, Code=%d", resp.Status, resp.StatusCode)
		for k, v := range resp.Header {
			log.Printf("[doSmartRequest] Response Header: %s: %s", k, strings.Join(v, ", "))
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("[doSmartRequest] Response Body (first 1KB): %q", body)
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
	}

	return resp, nil
}

// handleHTTPProxyConn handles a single HTTP proxy connection (MITM)
func handleHTTPProxyConn(conn net.Conn) {
	defer func() {
		if *verbose {
			log.Printf("[HTTPPROXY] Connection from %s closed", conn.RemoteAddr())
		}
		conn.Close()
	}()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[HTTPPROXY] Failed to read request line from %s: %v", conn.RemoteAddr(), err)
		return
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "CONNECT ") {
		log.Printf("[HTTPPROXY] Only CONNECT method supported, received: %s from %s", line, conn.RemoteAddr())
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		log.Printf("[HTTPPROXY] Invalid CONNECT line from %s: %s", conn.RemoteAddr(), line)
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	hostPort := parts[1]
	domain, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		if strings.Contains(hostPort, ":") {
			log.Printf("[HTTPPROXY] Invalid host:port from %s: %s", conn.RemoteAddr(), hostPort)
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		domain = hostPort
		port = "443"
	}
	if *verbose {
		log.Printf("[HTTPPROXY] CONNECT request %s:%s from %s", domain, port, conn.RemoteAddr())
	}
	hostHeader := ""
	for {
		h, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[HTTPPROXY] Failed to read headers from %s: %v", conn.RemoteAddr(), err)
			return
		}
		h = strings.TrimSpace(h)
		if h == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(h), "host:") {
			hostHeader = strings.TrimSpace(h[5:])
		}
	}
	if hostHeader != "" {
		log.Printf("[DEBUG] [MITM] HTTP Host header: %s", hostHeader)
	}

	if *verbose {
		log.Printf("[HTTPPROXY] Sending 200 Connection Established to client %s for %s:%s", conn.RemoteAddr(), domain, port)
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("[HTTPPROXY] Failed to write 200 response to %s: %v", conn.RemoteAddr(), err)
		return
	}
	caCert, caKey, err := loadCA("ca.pem", "ca.key")
	if err != nil {
		log.Printf("[HTTPPROXY] Failed to load CA: %v", err)
		return
	}
	cert, err := generateCertForDomain(domain, caCert, caKey)
	if err != nil {
		log.Printf("[HTTPPROXY] Failed to generate certificate for %s: %v", domain, err)
		return
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   domain,
	}
	clientTLS := tls.Server(conn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("[HTTPPROXY] TLS handshake with client %s failed: %v", conn.RemoteAddr(), err)
		return
	}
	if *verbose {
		log.Printf("[HTTPPROXY] TLS handshake with client %s completed for %s:%s", conn.RemoteAddr(), domain, port)
	}
	clientReader := bufio.NewReader(clientTLS)
	var firstRequestBuf []byte
	var hostHeaderAfterTLS string
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			log.Printf("[HTTPPROXY] Failed to read decrypted HTTP request from %s: %v", conn.RemoteAddr(), err)
			return
		}
		firstRequestBuf = append(firstRequestBuf, []byte(line)...)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "host:") {
			hostHeaderAfterTLS = strings.TrimSpace(trimmed[5:])
		}
		if trimmed == "" {
			break
		}
	}
	if hostHeaderAfterTLS != "" {
		log.Printf("[DEBUG] [MITM] Decrypted HTTP Host header: %s", hostHeaderAfterTLS)
	}
	reqReader := io.MultiReader(bytes.NewReader(firstRequestBuf), clientReader)
	req, err := http.ReadRequest(bufio.NewReader(reqReader))
	if err != nil {
		log.Printf("[HTTPPROXY] Failed to parse HTTP request from client %s: %v", conn.RemoteAddr(), err)
		return
	}
	req.RequestURI = ""
	resp, err := doSmartRequest(req)
	if err != nil {
		log.Printf("[HTTPPROXY] doSmartRequest failed: %v", err)
		clientTLS.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer resp.Body.Close()
	err = resp.Write(clientTLS)
	if err != nil {
		log.Printf("[HTTPPROXY] Failed to write response to client %s: %v", conn.RemoteAddr(), err)
	}
	if *verbose {
		log.Printf("[HTTPPROXY] Response relayed to client %s for %s", conn.RemoteAddr(), req.Host)
	}
}

// httpProxyHandler handles HTTP proxy
func httpProxyHandler(addr string) error {
	ln, err := net.Listen("tcp6", addr)
	if err != nil {
		if *verbose {
			log.Printf("[HTTPPROXY] IPv6 listen failed, falling back to IPv4: %v", err)
		}
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("Failed to listen on %s: %v (try another port, e.g., :1081)", addr, err)
		}
	}
	log.Printf("[HTTPPROXY] Listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[HTTPPROXY] Accept error: %v", err)
			continue
		}
		if *verbose {
			log.Printf("[HTTPPROXY] Accepted connection from %s", conn.RemoteAddr())
		}
		go handleHTTPProxyConn(conn)
	}
}

// printHelp prints usage information
func printHelp() {
	fmt.Println(`doh6 - Advanced HTTP proxy and DNS resolution tool

Usage:
  doh6 -L http://:port [--doh URL] [-v]
  doh6 [curl-style options] <URL> [-v] [-I]

Options:
  -L http://:port        Listen on specified port for HTTP proxy (e.g., http://:8080)
  --doh URL              DNS over HTTPS resolver URL (default: https://ns.net.kg/dns-query)
  -v                     Enable verbose logging
  -I                     Fetch headers only (HEAD request)
  -h, --help             Show this help message

Examples:
  doh6 -L http://:8080 -v
  doh6 https://www.google.com -v
  doh6 -I https://example.com
`)
}

func main() {
	flag.Usage = printHelp
	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	if len(os.Args) == 1 || *verbose && (*httpProxyAddr == "" && len(flag.Args()) == 0) {
		printHelp()
		os.Exit(0)
	}
	if (*httpProxyAddr == "" && len(flag.Args()) == 0) || (*httpProxyAddr != "" && len(flag.Args()) > 0) {
		printHelp()
		os.Exit(1)
	}
	if *httpProxyAddr != "" {
		addr := *httpProxyAddr
		if strings.HasPrefix(addr, "http://") {
			addr = addr[len("http://"):]
		} else {
			log.Fatal("Invalid -L format, expected http://:port")
		}
		if err := httpProxyHandler(addr); err != nil {
			log.Fatalf("[HTTPPROXY] Error: %v", err)
		}
		return
	}

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("Usage: doh6 [options] URL")
	}
	requestURL = args[0]

	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		log.Fatalf("Invalid URL: %v", err)
	}
	origHost := parsedURL.Hostname()
	port := "443"
	ip, err := dohQueryAAAARecord(origHost)
	if err != nil {
		log.Fatalf("[ERROR] DoH resolution for %s failed: %v", origHost, err)
	}
	// Ensure IPv6 address is properly formatted with brackets
	connectAddr := net.JoinHostPort(ip, port)
	sni := origHost
	if *verbose {
		log.Printf("[VERBOSE] DoH resolved %s to %s", origHost, ip)
	}

	if *verbose {
		log.Printf("[VERBOSE] Starting request: URL=%s, HeadOnly=%v, Insecure=%v",
			requestURL, *headOnly, *insecure)
	}

	client := &http.Client{
		Transport: newCustomTransport(connectAddr, sni),
	}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	if *headOnly {
		req.Method = "HEAD"
	}

	if *verbose {
		uConn, err := newUTLSConn("tcp6", connectAddr, sni)
		log.Printf("[VERBOSE] HTTP request Host header: %s", req.Host)
		if err != nil {
			log.Printf("[VERBOSE] Failed to establish TLS connection: %v", err)
		} else {
			defer uConn.Close()
			rawRequest := fmt.Sprintf(
				"%s %s HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"User-Agent: doh6/1.0\r\n"+
					"Accept: */*\r\n"+
					"Connection: close\r\n"+
					"Accept-Encoding: identity\r\n\r\n",
				req.Method, req.URL.RequestURI(), req.Host)
			_, err = uConn.Write([]byte(rawRequest))
			if err != nil {
				log.Printf("[VERBOSE] Failed to send raw request: %v", err)
			} else {
				buf := make([]byte, 1024)
				n, err := uConn.Read(buf)
				if err != nil && err != io.EOF {
					log.Printf("[VERBOSE] Failed to read raw response: %v", err)
				} else {
					log.Printf("[VERBOSE] Raw server response: %q", buf[:n])
				}
			}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		if *verbose {
			if resp != nil && resp.Body != nil {
				buf := new(bytes.Buffer)
				_, readErr := io.CopyN(buf, resp.Body, 1024)
				if readErr != nil && readErr != io.EOF {
					log.Printf("[VERBOSE] Failed to read raw response data: %v", readErr)
				} else {
					log.Printf("[VERBOSE] Raw response data (first 1024 bytes): %q", buf.Bytes())
				}
				resp.Body.Close()
			} else {
				log.Printf("[VERBOSE] No response body available")
			}
		}
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP/%d.%d %d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status)
	for k, v := range resp.Header {
		fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
	}
	if !*headOnly {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read response body: %v", err)
		} else {
			fmt.Printf("\n%s\n", body)
		}
	}
}
