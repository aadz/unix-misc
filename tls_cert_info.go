/*
by aadz, 2016
TLS certificate information grabber. Example of run:

$ ./tls_cert_info www.google.ru:443
Connected to www.google.ru:443
*** Certificate info:
Version:        3
Host:           [*.google.com.ru *.google.ru google.com.ru google.ru]
NotBefore:      2016-09-14 08:25:39 +0000 UTC
NotAfter:       2016-12-07 08:19:00 +0000 UTC
*** Fingerprints:
sha1:           d3:fa:53:d1:38:13:d2:14:b5:48:7d:d8:9f:c6:5b:ac:e0:c6:51:d3
sha256:         e3:5e:14:c4:3d:49:20:d1:69:3f:a1:44:bb:f2:e4:d1:a:fa:59:c2:88:35:ff:de:d7:8:bc:b5:cc:22:35:b5
*** Note:
It is 2016-09-23 00:50:16.787572948 +0300 MSK now: 75 validity days left

*/

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
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
		fmt.Printf("Canot connect to %v: %v", ssl_server, err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("Connected to", ssl_server)

	// Show server's certificate info
	crt := conn.ConnectionState().PeerCertificates[0]
	days_left := math.Ceil(crt.NotAfter.Sub(time.Now()).Seconds()/86400) - 1

	// Make fingerprints
	sha1Fingerprint := sha1.Sum(crt.Raw)
	sha256Fingerprint := sha256.Sum256(crt.Raw)

	infoStr := "*** Certificate info:\nVersion:\t%v\nHost:\t\t%v\n"
	infoStr += "NotBefore:\t%v\nNotAfter:\t%v\n"
	infoStr += "*** Fingerprints:\nsha1:\t\t%v\nsha256:\t\t%v\n"
	fmt.Printf(infoStr, crt.Version, crt.DNSNames,
		crt.NotBefore, crt.NotAfter,
		byteSlice2Str(sha1Fingerprint[:]), byteSlice2Str(sha256Fingerprint[:]))
	fmt.Printf("*** Note:\nIt is %v now: %v validity days left\n", time.Now(), days_left)
}

func show_help() {
	fmt.Println("Usage:", os.Args[0], "<HOST>:<PORT>")
	os.Exit(0)
}

// byteSlice2Str converts a slice of bytes to a colon delimited hexs string
func byteSlice2Str(sl []byte) string {
	strArr := make([]string, len(sl))
	for i, b := range sl {
		strArr[i] = fmt.Sprintf("%x", b)
	}
	return strings.Join(strArr, ":")
}
