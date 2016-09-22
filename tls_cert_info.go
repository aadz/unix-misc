// TLS certificate information grabber.
// Usage:
//     tls_cert_info <HOST>:<PORT>
// by aadz, 2016

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
		fmt.Printf("Canot connect to %v: %v\n", ssl_server, err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("Connected to %v\n", ssl_server)

	// Show server's certificate info
	crt := conn.ConnectionState().PeerCertificates[0]
	days_left := math.Ceil(crt.NotAfter.Sub(time.Now()).Seconds()/86400) - 1
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
		strArr[i] = fmt.Sprintf("%0.2x", b)
	}
	return strings.Join(strArr, ":")
}
