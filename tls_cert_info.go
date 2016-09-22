/*
by aadz, 2016
TLS sertificate information grabber. Example of run:

$ ./tls_cert_info www.gmail.com:443
2016/09/22 21:15:09 Connected to www.gmail.com:443
*** Certificate info:
Version:        3
Host:           [www.gmail.com]
NotBefore:      2016-09-14 08:22:49 +0000 UTC
NotAfter:       2016-12-07 08:19:00 +0000 UTC
*** Note:
It is 2016-09-22 21:15:09.927378879 +0300 MSK now: 75 days left

*/
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"os"
	"time"
)


func main() {
	// Parameters check
	if len(os.Args) != 2 {
		show_help()
	}
	ssl_server := os.Args[1]

	// Connect to server
	tls_cfg := tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", ssl_server, &tls_cfg)
	if err != nil {
		log.Printf("Canot connect to %v : %v", ssl_server, err)
		os.Exit(1)
	}
	defer conn.Close()
	log.Println("Connected to", ssl_server)

	// Show server's certificate info
	crt := conn.ConnectionState().PeerCertificates[0]
	fmt.Printf("*** Certificate info:\nVersion:\t%v\nHost:\t\t%v\nNotBefore:\t%v\nNotAfter:\t%v\n",
		crt.Version, crt.DNSNames, crt.NotBefore, crt.NotAfter)
	days_left := math.Ceil(crt.NotAfter.Sub(time.Now()).Seconds()/86400)-1
	//fmt.Println("It is", time.Now(), "now:", days_left, "days left")
	fmt.Printf("*** Note:\nIt is %v now: %v days left\n", time.Now(), days_left)
}

func show_help() {
	fmt.Println("Usage:", os.Args[0], "<HOST>:<PORT>")
	os.Exit(0)
}
