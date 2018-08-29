/* Simple SOCKS5 server
   By aadz, 2018
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

// Configuration defaults
const (
	AUTH_FILE        = "/etc/go-socks/auth"
	LISTEN_ON        = "0.0.0.0:25002"
	LOG_FILE         = "/var/log/go-socks.log"
	PASSWORD_MIN_LEN = 8
)

var ( // global vars
	logger *log.Logger
)

func main() {
	// Get command line params
	var authFile, logFile, listenOn string
	flag.StringVar(&authFile, "a", AUTH_FILE, "specify users' auth file")
	flag.StringVar(&logFile, "l", LOG_FILE, "specify log file, \"-\" for STDERR")
	flag.StringVar(&listenOn, "listen", LISTEN_ON, "listen on")
	flag.Parse()

	// Open log
	var err error
	logDest := os.Stderr
	if logFile != "-" {
		logDest, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open log file %s: %s\n", logFile, err)
			logDest = os.Stderr // just use STDERR
		}
	}
	logger = log.New(logDest, "go-socks ", log.LstdFlags)

	// Create a SOCKS5 server
	var credStore socks5.CredentialStore
	if credStore, err = readAuthFile(authFile); err != nil {
		logger.Fatalf("[ERROR] Auth file read error: %s\n", err)
	}
	conf := &socks5.Config{}
	conf.Logger = logger
	conf.Credentials = credStore
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	startServer(server, listenOn)
}

// Read auth file in form of "user:password", one pair per a line,
// with comments by beginning "#"
func readAuthFile(authFile string) (socks5.CredentialStore, error) {
	fStr, err := ioutil.ReadFile(authFile)
	if err != nil {
		return nil, err
	}
	authList := strings.Split(string(fStr), "\n")
	authMap := make(socks5.StaticCredentials)

	for i, l := range authList {
		// skip empty lines and comments
		line := strings.Trim(l, " \r\t")
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// split user:password on the line
		up := strings.SplitN(line, ":", 2)

		// check the pair and add it to the auth store
		if len(up) == 2 {
			if len(up[0]) > 0 && len(up[1]) >= PASSWORD_MIN_LEN {
				authMap[up[0]] = up[1]
			} else if len(up[1]) < PASSWORD_MIN_LEN {
				logger.Printf("[WARN] Incorrect password for %s, it must be %d symbols at least",
					up[0], PASSWORD_MIN_LEN)
			}
		} else {
			logger.Printf("[WARN] Incorrect auth file line %d: %s", i, line)
		}
	}

	if len(authMap) == 0 {
		return nil, fmt.Errorf("No user auth lines found in %s", authFile)
	}

	return authMap, nil
}

func startServer(srv *socks5.Server, listenOn string) {
	l, err := net.Listen("tcp", listenOn)
	if err != nil {
		logger.Fatalf("[ERROR] %s", err)
	}
	defer l.Close()
	logger.Print("[INFO] Service started")

	// wait for connections
	for {
		conn, err := l.Accept()
		if err == nil {
			logger.Printf("[INFO] connect from %s", conn.RemoteAddr())
			go srv.ServeConn(conn)
		} else {
			logger.Printf("[ERROR] %s", err)
		}
	}
}
