/*
TCP map - an utility for Postfix. See man socketmap_table.

Function lookup() is a subject of change as required, it should get a key as
a string and returns correctly formed reply to Postfix (type of []byte).
Test it as:
	postmap -q - socketmap:unix:/tmp/postfix_socketmap:get < keys_list

by aadz, 2017, all rights look as lefts
*/
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/yawn/netstring"
)

var (
	cfgListenOn string
	cfgDebug    bool
)

var socketIn *net.UnixListener

func lookup(name string) []byte {
	// map a request as "out" string and
	// (reminder of the requests' bytes sum divided by 16) + 1
	var b = []byte(name)
	var sum int

	for i := range b {
		sum += int(b[i])
	}

	// build result as a reply to the Postfix query
	result := fmt.Sprintf("OK out%0.2d", sum%16+1)
	return []byte(result)
}

func connHandler(conn *net.UnixConn) {
	buf := make([]byte, 1024)

	for {
		cnt, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("cannot read the request: %v", err)
			}
			break
		}
		req, _ := netstring.Decode(buf[0:cnt])
		if err != nil {
			log.Println(err)
			break
		}

		rep, _ := netstring.Encode(lookup(string(req[0])))
		if err != nil {
			log.Println(err)
			break
		}
		conn.Write(rep)
		if cfgDebug {
			log.Printf("map %s to %s", string(req[0]), rep)
		}
	}
	conn.Close() // was open in main()
}

func cmdLineGet() {
	flag.StringVar(&cfgListenOn, "s", "/tmp/postfix_socketmap", "domain socket file name")
	flag.BoolVar(&cfgDebug, "d", false, "enable debug logging")
	flag.Parse()
}

func errExit(e error) {
	if e != nil {
		log.Printf("fatal: %v", e)
		os.Exit(1)
	}
}

func init() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func(c chan os.Signal) {
		sig := <-c // Wait for a SIGINT or SIGKILL
		log.Printf("Caught signal %s: shutting down and delete %s.", sig, cfgListenOn)
		socketIn.Close()
		syscall.Unlink(cfgListenOn)
		os.Exit(0)
	}(sigChan)
}

func main() {
	log.Println("socketIn is", socketIn)
	cmdLineGet()
	var sock = &net.UnixAddr{cfgListenOn, "unix"}
	socketIn, err := net.ListenUnix("unix", sock)
	errExit(err)
	defer socketIn.Close()
	log.Printf("listening on %v", sock)

	for {
		clientConn, err := socketIn.AcceptUnix()
		if err == nil {
			go connHandler(clientConn)
		} else {
			log.Printf("could not accept client connection: %v", err)
		}
	}
}
