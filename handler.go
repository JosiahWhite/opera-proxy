package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const BAD_REQ_MSG = "Bad Request\n"

type AuthProvider func() string

type ProxyHandler struct {
	logger        *CondLogger
	dialer        ContextDialer
	httptransport http.RoundTripper
}

func NewProxyHandler(dialer ContextDialer, logger *CondLogger) *ProxyHandler {
	httptransport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           dialer.DialContext,
	}
	return &ProxyHandler{
		logger:        logger,
		dialer:        dialer,
		httptransport: httptransport,
	}
}

func (s *ProxyHandler) HandleTunnel(wr http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	conn, err := s.dialer.DialContext(ctx, "tcp", req.RequestURI)
	if err != nil {
		s.logger.Error("Can't satisfy CONNECT request: %v", err)
		http.Error(wr, "Can't satisfy CONNECT request", http.StatusBadGateway)
		return
	}

	if req.ProtoMajor == 0 || req.ProtoMajor == 1 {
		// Upgrade client connection
		localconn, _, err := hijack(wr)
		if err != nil {
			s.logger.Error("Can't hijack client connection: %v", err)
			http.Error(wr, "Can't hijack client connection", http.StatusInternalServerError)
			return
		}
		defer localconn.Close()

		// Inform client connection is built
		fmt.Fprintf(localconn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor, req.ProtoMinor)

		proxy(req.Context(), localconn, conn)
	} else if req.ProtoMajor == 2 {
		wr.Header()["Date"] = nil
		wr.WriteHeader(http.StatusOK)
		flush(wr)
		proxyh2(req.Context(), req.Body, wr, conn)
	} else {
		s.logger.Error("Unsupported protocol version: %s", req.Proto)
		http.Error(wr, "Unsupported protocol version.", http.StatusBadRequest)
		return
	}
}

func (s *ProxyHandler) HandleRequest(wr http.ResponseWriter, req *http.Request) {
	req.RequestURI = ""
	if req.ProtoMajor == 2 {
		req.URL.Scheme = "http" // We can't access :scheme pseudo-header, so assume http
		req.URL.Host = req.Host
	}
	resp, err := s.httptransport.RoundTrip(req)
	if err != nil {
		s.logger.Error("HTTP fetch error: %v", err)
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	s.logger.Info("%v %v %v %v", req.RemoteAddr, req.Method, req.URL, resp.Status)
	delHopHeaders(resp.Header)
	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	flush(wr)
	copyBody(wr, resp.Body)
}

func (s *ProxyHandler) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	s.logger.Info("Request: %v %v %v %v", req.RemoteAddr, req.Proto, req.Method, req.URL)

	isConnect := strings.ToUpper(req.Method) == "CONNECT"
	if (req.URL.Host == "" || req.URL.Scheme == "" && !isConnect) && req.ProtoMajor < 2 ||
		req.Host == "" && req.ProtoMajor == 2 {
		http.Error(wr, BAD_REQ_MSG, http.StatusBadRequest)
		return
	}
	delHopHeaders(req.Header)
	if isConnect {
		s.HandleTunnel(wr, req)
	} else {
		s.HandleRequest(wr, req)
	}
}

func (s *ProxyHandler) handleTCPSocks(conn net.Conn, bufConn *bufio.Reader) {
	var err error
	var destEndPoint string
	if destEndPoint, err = readSocks5Address(bufConn); err != nil {
		msg := make([]byte, 10)
		msg[0] = 5
		msg[1] = 4 // host unreachable
		msg[2] = 0 // Reserved
		msg[3] = uint8(1)
		copy(msg[4:], []byte{0, 0, 0, 0})
		msg[8] = 0
		msg[9] = 0
		conn.Write(msg)

		fmt.Println("socks: Failed to read destination address:", err)
		conn.Close()
		return
	}

	if strings.Contains(destEndPoint, ":443") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		proxyConn, err := s.dialer.DialContext(ctx, "tcp", destEndPoint)
		cancel()

		if err != nil {
			msg := make([]byte, 10)
			msg[0] = 5
			msg[1] = 4 // host unreachable
			msg[2] = 0 // Reserved
			msg[3] = uint8(1)
			copy(msg[4:], []byte{0, 0, 0, 0})
			msg[8] = 0
			msg[9] = 0
			conn.Write(msg)

			s.logger.Error("Can't satisfy CONNECT request: %v", err)
			conn.Close()
			return
		}
		defer proxyConn.Close()

		msg := make([]byte, 10)
		msg[0] = 5
		msg[1] = 0 // successfully connected
		msg[2] = 0 // Reserved
		msg[3] = uint8(1)
		copy(msg[4:], []byte{0, 0, 0, 0})
		msg[8] = 0
		msg[9] = 0
		conn.Write(msg)

		errCh := make(chan error, 2)

		tcpProxy := func(dst io.Writer, src io.Reader, errCh chan error) {
			type closeWriter interface {
				CloseWrite() error
			}

			_, err := io.Copy(dst, src)
			if tcpConn, ok := dst.(closeWriter); ok {
				tcpConn.CloseWrite()
			}
			errCh <- err
		}

		go tcpProxy(proxyConn, bufConn, errCh)
		go tcpProxy(conn, proxyConn, errCh)

		// Wait
		for i := 0; i < 2; i++ {
			e := <-errCh
			if e != nil {
				conn.Close()
				return
			}
		}

		conn.Close()
		return
	}

	msg := make([]byte, 10)
	msg[0] = 5
	msg[1] = 0 // successfully connected
	msg[2] = 0 // Reserved
	msg[3] = uint8(1)
	copy(msg[4:], []byte{0, 0, 0, 0})
	msg[8] = 0
	msg[9] = 0
	conn.Write(msg)

	server := http.Server{
		Handler: s,
	}

	server.Serve(&onceListener{
		conn:     conn,
		accepted: false,
	})

	// dont close conn as the http server will handle it
}

func (s *ProxyHandler) InitialHandler(conn net.Conn) {
	bufConn := bufio.NewReader(conn)

	var err error

	// Read the version byte
	version := []byte{0}
	if _, err = bufConn.Read(version); err != nil {
		fmt.Println("socks: Failed to get version byte:", err)
		conn.Close()
		return
	}

	// Ensure we are compatible
	if version[0] != 5 {
		fmt.Println("socks: Unsupported SOCKS version:", version)
		conn.Close()
		return
	}

	authHeader := []byte{0}
	if _, err = bufConn.Read(authHeader); err != nil {
		fmt.Println("socks: Failed to authenticate:", err)
		conn.Close()
		return
	}

	numMethods := int(authHeader[0])
	methods := make([]byte, numMethods)
	if _, err = io.ReadAtLeast(bufConn, methods, numMethods); err != nil {
		fmt.Println("socks: Failed to authenticate:", err)
		conn.Close()
		return
	}

	// no auth
	if _, err = conn.Write([]byte{5, 0}); err != nil {
		fmt.Println("socks: Failed to authenticate:", err)
		conn.Close()
		return
	}

	reqHeader := []byte{0, 0, 0}
	if _, err = io.ReadAtLeast(bufConn, reqHeader, 3); err != nil {
		fmt.Println("socks: Failed to get command version:", err)
		conn.Close()
		return
	}

	if reqHeader[0] != 5 {
		fmt.Println("socks: Unsupported command version:", reqHeader[0])
		conn.Close()
		return
	}

	method := reqHeader[1]

	switch method {
	case 1:
		s.handleTCPSocks(conn, bufConn)
	default:
		msg := make([]byte, 10)
		msg[0] = 5
		msg[1] = 7 // command not supported
		msg[2] = 0 // Reserved
		msg[3] = uint8(1)
		copy(msg[4:], []byte{0, 0, 0, 0})
		msg[8] = 0
		msg[9] = 0
		conn.Write(msg)

		fmt.Println("socks: Unsupported command type:", reqHeader[1])
		conn.Close()
		return
	}
}

func (s *ProxyHandler) Start(bindAddress string) error {
	listener, err := net.Listen("tcp", bindAddress)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}

		go s.InitialHandler(c)
	}
}

type onceListener struct {
	conn     net.Conn
	accepted bool
}

func (ol *onceListener) Accept() (net.Conn, error) {
	if ol.accepted {
		return nil, errors.New("done")
	}

	ol.accepted = true

	return ol.conn, nil
}

func (ol *onceListener) Close() error {
	return nil
}

func (ol *onceListener) Addr() net.Addr {
	return &net.TCPAddr{}
}
