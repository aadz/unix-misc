/*
	$Id: go-socks.go,v 1.3 2018/04/14 07:19:05 aadz Exp aadz $
	by aadz, 2018
*/

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/armon/go-socks5"
)

const (
	listenOn = "0.0.0.0:27002"
)

var (
	authFile  string
	credStore socks5.StaticCredentials
)

func init() {
	// auth file in form user:password, one pair per a line , comments by "#"
	flag.StringVar(&authFile, "a", "/etc/go-socks/auth", "specify users' auth file")
	flag.Parse()
}

func main() {
	if err := readAuthFile(); err != nil {
		fmt.Printf("auth file read error: %v", err)
		os.Exit(1)
	}

	// Create a SOCKS5 server
	conf := &socks5.Config{}
	logger := log.New(os.Stdout, "go-socks5 ", log.LstdFlags)
	conf.Logger = logger
	conf.Credentials = credStore

	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("AuthMethods: %v\nCredentials: %v\nResolver: %v\nRules: %v\nRewriter: %v\nBindIP: %v\nLogger: %v\n",
	//conf.AuthMethods, conf.Credentials, conf.Resolver, conf.Rules, conf.Rewriter, conf.Logger)

	l, err := net.Listen("tcp", listenOn)
	if err != nil {
		logger.Fatal(err)
	}
	defer l.Close()
	logger.Print("Service started")

	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Print(err)
		}
		logger.Printf("connect from %v", conn.RemoteAddr())
		go server.ServeConn(conn)
	}
}

func readAuthFile() error {
	fStr, err := ioutil.ReadFile(authFile)
	if err != nil {
		return err
	}
	authList := strings.Split(string(fStr), "\n")

	authMap := make(socks5.StaticCredentials)
	for _, line := range authList {
		l := strings.Trim(line, " \r\t")
		if len(l) == 0 || l[0] == '#' { // skip comments
			continue
		}
		up := strings.SplitN(l, ":", 2) // split user:password line
		if len(up) == 2 && len(up[0]) > 0 && len(up[1]) > 0 {
			authMap[up[0]] = up[1]
		}
	}
	if len(authMap) == 0 {
		return fmt.Errorf("No user auth lines found in %s", authFile)
	}
	//fmt.Printf("Auth map: %v\n", authMap)
	credStore = authMap
	return nil
}
