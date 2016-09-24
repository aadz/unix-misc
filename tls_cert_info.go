// TLS certificate information grabber.
// Usage:
//     tls_cert_info <HOST>:<PORT>
// by aadz, 2016

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	PROG_NAME = "tls_cert_info"
	VERSION   = "0.8"
)

var (
	cfgValidityDaysOnly bool
	cfgHost             string
	cfgPort             uint
	hostStr, portStr    string
	PKeyPKCS            [4]string  = [4]string{"Unknown", "RSA", "DSA", "ECDSA"}
	SignPKCS            [13]string = [13]string{
		"Unknown",
		"MD2 With RSA",
		"MD5 With RSA",
		"SHA1 With RSA",
		"SHA256 With RSA",
		"SHA384 With RSA",
		"SHA512 With RSA",
		"DSA With SHA1",
		"DSA With SHA256",
		"ECDSA With SHA1",
		"ECDSA With SHA256",
		"ECDSA With SHA384",
		"ECDSA With SHA512",
	}
)

func init() {
	usageStr := "Usage:\t%v [-r] <HOST>[:<PORT>]\n\t%v [-r] -H <HOST> [-P <PORT>]\n\n"
	usageStr += "<HOST> might be a DNS name or an IP address. IPv6 address should be enclosed\n"
	usageStr += "by square brackets.\n\nCommand line parameters:\n"

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usageStr, PROG_NAME, PROG_NAME)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "  -h\tShow this help page.\n")
	}
}

func main() {
	// Parameters check
	commandLineGet()
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(0)
	}

	// Host and port converting to a server string
	if len(cfgHost) == 0 { // <HOST>:<PORT> form used
		hostStr, portStr = normalizeHostStr(os.Args[len(os.Args)-1])
	} else { // -H <HOST> -P <PORT> form used
		hostStr, portStr = normalizeHostStr(cfgHost + ":" + portStr)
	}

	if len(portStr) == 0 { // port was not specified
		// "flag" already checked cfgPort for type of uint
		portStr = strconv.Itoa(int(cfgPort))
	}

	// Connect to server
	serverStr := hostStr + ":" + portStr
	tlsCfg := tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", serverStr, &tlsCfg)
	if err != nil && strings.Contains(err.Error(), "too many colons in address") {
		// try to add [] and set default port
		serverStr = "[" + os.Args[len(os.Args)-1] + "]:443"
		conn, err = tls.Dial("tcp", serverStr, &tlsCfg)
	}
	if err != nil {
		fmt.Printf("Canot connect to %v: %v\n", serverStr, err)
		os.Exit(1)
	}
	defer conn.Close()

	if !cfgValidityDaysOnly {
		fmt.Printf("Connected to %v\n", serverStr)
	}
	showCrtInfo(conn.ConnectionState().PeerCertificates[0])
}

// byteSlice2Str converts a slice of bytes to a colon delimited hexs string
func byteSlice2Str(sl []byte) string {
	strArr := make([]string, len(sl))

	for i, b := range sl {
		strArr[i] = fmt.Sprintf("%0.2x", b)
	}
	return strings.Join(strArr, ":")
}

func commandLineGet() {
	flag.BoolVar(&cfgValidityDaysOnly, "r", false, "Print remaining validity days count only.")
	flag.StringVar(&cfgHost, "H", "", "DNS host name or IP address.")
	flag.UintVar(&cfgPort, "P", 443, "Port.")
	flagVersion := flag.Bool("v", false, "Print version information and exit.")
	flag.Parse()

	if *flagVersion {
		fmt.Println(PROG_NAME, "v.", VERSION, "["+runtime.Version()+" runtime]")
		os.Exit(0)
	}
}

// normalizeHostStr gets a string in form of <HOST>[:<PORT>]
// and returs normalized DNS hostname and port strings
func normalizeHostStr(hName string) (hStr, pStr string) {
	// split host name and port if any
	numArr := strings.Split(hName, ":")
	switch len(numArr) {
	case 1:
		hStr = numArr[0]
	case 2:
		hStr = numArr[0]
		pStr = numArr[1]
	default:
		hStr = strings.Join(numArr[:len(numArr)-1], ":")
		pStr = numArr[len(numArr)-1]
	}

	// Check if host name is not an ASCII string
	// and convert it to punycode if required
	for _, c := range hStr {
		if c > 127 {
			var err error
			hStr, err = idna.ToASCII(hStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot convet %v to punycode\n")
				os.Exit(1)
			}
			break
		}
	}
	return
}

// Show server's certificate info
func showCrtInfo(crt *x509.Certificate) {
	days_left := int(crt.NotAfter.Sub(time.Now()).Seconds() / 86400)

	if cfgValidityDaysOnly {
		fmt.Println(days_left)
		os.Exit(0)
	}

	sha1Fingerprint := sha1.Sum(crt.Raw)
	sha256Fingerprint := sha256.Sum256(crt.Raw)

	infoStr := "*** Certificate info:\nIssuerCN:\t%v\nVersion:\t%v\n"
	infoStr += "SerialNum:\t%x\n"
	infoStr += "PubKey:\t\t%v Encryption\n"
	infoStr += "CrtSign:\t%v Encryption\n"
	infoStr += "NotBefore:\t%v\nNotAfter:\t%v - %v days left\n"
	infoStr += "SubjectCN:\t%v\nDNSNames:\t%v\n"
	infoStr += "*** Fingerprints:\nsha1:\t\t%v\nsha256:\t\t%v\n"
	fmt.Printf(infoStr, crt.Issuer.CommonName, crt.Version,
		crt.SerialNumber,
		PKeyPKCS[crt.PublicKeyAlgorithm],
		SignPKCS[crt.SignatureAlgorithm],
		crt.NotBefore, crt.NotAfter, days_left,
		crt.Subject.CommonName, crt.DNSNames,
		byteSlice2Str(sha1Fingerprint[:]), byteSlice2Str(sha256Fingerprint[:]))
}
