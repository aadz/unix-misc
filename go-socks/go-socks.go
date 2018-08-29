/* By aadz, 2018 */

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

var (
	// command line perameters
	authFile string
	logFile  string

	// global vars
	credStore socks5.StaticCredentials
	logger    *log.Logger
)

func init() {
	flag.StringVar(&authFile, "a", AUTH_FILE, "specify users' auth file")
	flag.StringVar(&logFile, "l", LOG_FILE, "specify log file, \"-\" for STDERR")
	flag.Parse()

	// open log
	var err error
	logF := os.Stderr
	if logFile != "-" {
		logF, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open log file %s: %s\n", logFile, err)
			logF = os.Stderr // just use STDERR
		}
	}
	logger = log.New(logF, "go-socks ", log.LstdFlags)
}

func main() {
	if err := readAuthFile(); err != nil {
		logger.Fatalf("Auth file read error: %s\n", err)
		os.Exit(1)
	}

	// Create a SOCKS5 server
	conf := &socks5.Config{}
	conf.Logger = logger
	conf.Credentials = credStore
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	l, err := net.Listen("tcp", LISTEN_ON)
	if err != nil {
		logger.Fatal(err)
	}
	defer l.Close()
	logger.Print("Service started")

	// wait for connections
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Print(err)
		}
		logger.Printf("connect from %v", conn.RemoteAddr())
		go server.ServeConn(conn)
	}
}

// Read auth file in form user:password, one pair per a line , comments by "#"
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
		up := strings.SplitN(l, ":", 2) // split user:password on the line
		if len(up) == 2 && len(up[0]) > 0 && len(up[1]) >= PASSWORD_MIN_LEN {
			authMap[up[0]] = up[1]
		} else if len(up[1]) < PASSWORD_MIN_LEN {
			logger.Printf("Incorrect password for %s, it must be %d symbols at least",
				up[0], PASSWORD_MIN_LEN)
		}
	}
	if len(authMap) == 0 {
		return fmt.Errorf("No user auth lines found in %s", authFile)
	}
	//fmt.Printf("Auth map: %v\n", authMap)
	credStore = authMap
	return nil
}
