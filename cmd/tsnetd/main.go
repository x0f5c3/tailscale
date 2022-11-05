// Server tsnetd "tailscale inetd" is a TCP proxy that can listen on tsnet addresses.
//
// My main motivation for this is to run multiple services on the same host, but give
// them memorable names and use cononical ports.
//
// Usage:
//
//	tsnetd tailscale-host-1:tailscale-port-1:target-host:target-port ...
//
// For example:
//
//	tsnetd cameras:http:localhost:8001 cameras:rtsp:localhost:rtsp phone:sip:localhost:sip
//
// This will register two nodes on your tailnet, "cameras" and "phone", using the auth key in
// the environment variable TS_AUTHKEY. On cameras it will forward port 80 to localhost:8001
// and port 554 (rtsp) to localhost:554, and on phone it will forward port 5060 (sip) to
// localhost:5060.
//
// You can get the same effect if you:
//  1. Run multiple tailscaleds in separate network namespaces or containers, but that can get complicated.
//  2. Use the caddy-tailscale extension, but that's HTTP only.
//  2. Use an HTTP proxy & vitual hosts, but now you have to set your own DNS. Also HTTP (or TLS) only.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"tailscale.com/tsnet"
)

var logf = func(string, ...any) {}

func proxy(s *tsnet.Server, a net.Conn, dst string) {
	c, err := s.LocalClient()
	if err != nil {
		return
	}
	who, err := c.WhoIs(context.TODO(), a.RemoteAddr().String())
	if err != nil {
		return
	}
	log.Printf("%s -> %s", who.UserProfile.LoginName, a.RemoteAddr())
	b, err := net.Dial("tcp", dst)
	if err != nil {
		log.Println("could not dial upstream:", err)
		return
	}

	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(a, b)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(b, a)
		errc <- err
	}()
	<-errc
}

func listen(s *tsnet.Server, port, dst string) {
	log.Printf("listening: %s:%s -> %s", s.Hostname, port, dst)
	// TODO TLS.
	ln, err := s.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	for {
		a, err := ln.Accept()
		if err != nil {
			log.Fatal("could not accept new connection:", err)
		}
		go proxy(s, a, dst)
	}
}

func parseDirective(arg string) (host, port, dst string, err error) {
	parts := strings.Split(arg, ":")
	if len(parts) != 4 {
		return "", "", "", fmt.Errorf("could not part proxy directive")
	}
	return parts[0], parts[1], parts[2] + ":" + parts[3], nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "\ttsnetd -tailscale-host:tailscale-port:target-host:target-port ...\n\n")
	fmt.Fprintf(os.Stderr, "flags:\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	flag.Usage = usage
	configdir, _ := os.UserConfigDir() // Ignore error. Empty string means we fall back to current directory.
	statedir := flag.String("state-dir", filepath.Join(configdir, "tsnetd"), "directory to keep tailscale state")
	authkey := flag.String("auth-key", "$TS_AUTHKEY", "a (possibly reusable) tailscale auth key")
	verbose := flag.Bool("verbose", false, "be verbose")
	flag.Parse()

	if *verbose {
		logf = log.Printf
	}

	// TODO support auth urls?
	if *authkey == "$TS_AUTHKEY" {
		// TODO(s): also support TS_AUTHKEY_${HOST} like caddy-tailscale
		*authkey = os.Getenv("TS_AUTHKEY")
	}
	if *authkey == "" {
		log.Fatalf("tsnetd needs a Tailscale auth key, set $TS_AUTHKEY or pass in -auth-key")
	}

	if flag.NArg() == 0 {
		usage()
	}

	nodes := map[string]map[string]string{}
	for _, arg := range flag.Args() {
		host, port, dst, err := parseDirective(arg)
		if err != nil {
			log.Fatalf("%v", err)
		}
		if nodes[host] == nil {
			nodes[host] = map[string]string{}
		}
		nodes[host][port] = dst
	}

	for n, m := range nodes {
		statedir := filepath.Join(*statedir, n)
		err := os.MkdirAll(statedir, 0770)
		if err != nil {
			log.Fatalf("could not make state directory: %v", err)
		}
		s := &tsnet.Server{
			Hostname: n,
			Dir:      statedir,
			Logf:     logf,
			AuthKey:  *authkey,
		}
		defer s.Close()
		for port, dst := range m {
			go listen(s, port, dst)
		}
	}
	select {}
}
