/*
by aadz, 2016
TLS certificate information grabber. Example of run:

$ ./tls_cert_info www.google.com:443
2016/09/22 23:55:20 Connected to www.google.com:443
*** Certificate info:
Version:        3
Host:           [www.google.com]
Fingerprint:    90:86:a4:3b:f5:cf:1b:2e:4e:f7:97:96:f9:de:ba:b9:66:35:86:3f
NotBefore:      2016-09-14 08:20:40 +0000 UTC
NotAfter:       2016-12-07 08:19:00 +0000 UTC
*** Note:
It is 2016-09-22 23:55:20.646289871 +0300 MSK now: 75 days left

*/

package main

import (
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"time"
)

func main() {
	// Parameters check
	if len(os.Args) != 2 {
		show_help()
	}
	ssl_server := os.Args[1]

	// Connect to server
	conn, err := tls.Dial("tcp", ssl_server, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("Canot connect to %v: %v", ssl_server, err)
		os.Exit(1)
	}
	defer conn.Close()
	log.Println("Connected to", ssl_server)

	// Show server's certificate info
	crt := conn.ConnectionState().PeerCertificates[0]
	days_left := math.Ceil(crt.NotAfter.Sub(time.Now()).Seconds()/86400) - 1

	// Make fingerprint
	sha1Sum := sha1.Sum(crt.Raw)	// a bytes array
	Fingerprint := make([]string, len(sha1Sum))
	for i, b := range sha1Sum {
		Fingerprint[i] = fmt.Sprintf("%x", b)
	}

	fmt.Printf("*** Certificate info:\nVersion:\t%v\nHost:\t\t%v\nFingerprint:\t%v\nNotBefore:\t%v\nNotAfter:\t%v\n",
		crt.Version, crt.DNSNames, strings.Join(Fingerprint, ":"), crt.NotBefore, crt.NotAfter)
	fmt.Printf("*** Note:\nIt is %v now: %v days left\n", time.Now(), days_left)
}

func show_help() {
	fmt.Println("Usage:", os.Args[0], "<HOST>:<PORT>")
	os.Exit(0)
}
