/*
TCP map - an utility for Postfix. See man tcp_table.

Function lookup() is a subject of change as required, it should get a key as
a string and returns correctly formed reply to Postfix (type of []byte).
Test it as:
	postmap -q - tcp:127.0.0.1:10044 < keys_list

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
)

var (
	cfgListenOn string
	cfgDebug    bool
)

func lookup(key string) []byte {
	// map a request as "out" string and
	// (reminder of the requests' bytes sum divided by 16) + 1
	var b = []byte(key)
	var sum int

	for i := range b {
		sum += int(b[i])
	}

	// build result as a reply to the Postfix query
	result := fmt.Sprintf("200 out%0.2d\n", sum%16+1)
	return []byte(result)
}

func connHandler(conn *net.TCPConn) {
	buf := make([]byte, 256)
	var req string

theHandler:
	for {
		for len(req) == 0 || req[len(req)-1] != 0xA { // req is empty or not trailing "\n"
			cnt, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("cannot read the request: %v", err)
				} else if cfgDebug { // end of file'd got
					log.Printf("connection from %v closed", conn.RemoteAddr())
				}
				break theHandler
			}
			req += string(buf[0:cnt])
		}

		if req[0:4] == "get " {
			rep := lookup(req[4 : len(req)-1])
			conn.Write(rep)
			if cfgDebug {
				log.Printf("map %s to %s", req[4:len(req)-1], rep)
			}
		} else {
			conn.Write([]byte("500 get-requests are only allowed here\n"))
		}
		// all is done with the request, so we set it empty for a new one
		req = ""
	}
	conn.Close() // was open in main()
}

func cmdLineGet() {
	flag.StringVar(&cfgListenOn, "l", "localhost:10044", "[address]:port to listen on")
	flag.BoolVar(&cfgDebug, "d", false, "enable debug logging")
	flag.Parse()
}

func errExit(e error) {
	if e != nil {
		log.Printf("fatal: %v", e)
		os.Exit(1)
	}
}

func main() {
	cmdLineGet()
	lAddr, err := net.ResolveTCPAddr("tcp", cfgListenOn)
	errExit(err)
	in, err := net.ListenTCP("tcp", lAddr)
	errExit(err)
	log.Println("listening on ", lAddr)

	for {
		clientConn, err := in.AcceptTCP()
		if err == nil {
			if cfgDebug {
				log.Printf("clent connection from %v", clientConn.RemoteAddr())
			}
			go connHandler(clientConn)
		} else {
			log.Printf("could not accept client connection: %v", err)
		}
	}
}
