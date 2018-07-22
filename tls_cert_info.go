package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	PROG_NAME = "tls_cert_info"
	VERSION   = "0.9.1"
)

var (
	cfgPemFile          string
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
	usageStr := "Usage:\t%v [-d] <HOST>[:<PORT>]\n\t%v [-d] -H <HOST> [-P <PORT>]\n\t%v -f <filename>\n\n"
	usageStr += "<HOST> might be a DNS name or an IP address. IPv6 address should be enclosed\n"
	usageStr += "by square brackets.\n\nCommand line parameters:\n"

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usageStr, PROG_NAME, PROG_NAME, PROG_NAME)
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

	if len(cfgPemFile) > 0 {
		showPemFile()
	} else {
		showSiteCert()
	}
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
	flag.BoolVar(&cfgValidityDaysOnly, "d", false, "Print remaining validity days count only.")
	flag.StringVar(&cfgPemFile, "f", "", "File containing PEM encoded certificates.")
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
			hStr, err = idna.ToASCII(strings.ToLower(hStr))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot convet %v to punycode: %v\n", hStr, err)
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

	if cfgValidityDaysOnly && len(cfgPemFile) == 0 {
		fmt.Println(days_left)
		os.Exit(0)
	}

	// create certificate expiration info string
	expireStr := "day"
	if days_left != 1 || days_left != -1 {
		expireStr += "s"
	}
	if time.Now().After(crt.NotAfter) {
		expireStr += " have passed from the expiration date!"
	} else {
		expireStr += " left"
	}
	if days_left < 0 {
		days_left *= -1
	}
	expireStr = fmt.Sprintf("%v %v", days_left, expireStr)

	sha1Fingerprint := sha1.Sum(crt.Raw)
	sha256Fingerprint := sha256.Sum256(crt.Raw)
	sha256TbsFingerprint := sha256.Sum256(crt.RawSubjectPublicKeyInfo)
	spki := base64.StdEncoding.EncodeToString(sha256TbsFingerprint[:])

	infoStr := "*** Certificate info:\nIssuerCN:\t%v\nVersion:\t%v\n"
	infoStr += "SerialNum:\t%x\n"
	infoStr += "PubKey:\t\t%v Encryption\n"
	infoStr += "CrtSign:\t%v Encryption\n"
	infoStr += "NotBefore:\t%v\nNotAfter:\t%v - %v\n"
	infoStr += "Subject:\t%v\nDNSNames:\t%v\n"
	infoStr += "*** Fingerprints:\nsha1:\t\t%v\nsha256:\t\t%v\nSPKI:\t\t%v\n"
	fmt.Printf(infoStr, crt.Issuer.CommonName, crt.Version,
		crt.SerialNumber,
		PKeyPKCS[crt.PublicKeyAlgorithm],
		SignPKCS[crt.SignatureAlgorithm],
		crt.NotBefore, crt.NotAfter, expireStr,
		//crt.Subject.CommonName, crt.DNSNames,
		crt.Subject.String(), crt.DNSNames,
		byteSlice2Str(sha1Fingerprint[:]), byteSlice2Str(sha256Fingerprint[:]), spki)
}

func showPemFile() {
	// read PEM certificates from a file
	crtPEM, err := ioutil.ReadFile(cfgPemFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// decode PEM file
	var crtArr []*(pem.Block)
	rest := crtPEM
	for len(rest) > 0 {
		block, r := pem.Decode(rest)
		rest = r
		if block != nil && block.Type == "CERTIFICATE" {
			crtArr = append(crtArr, block)
		}
	}

	for i, _ := range crtArr {
		cert, err := x509.ParseCertificate(crtArr[i].Bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		showCrtInfo(cert)
		if i+1 < len(crtArr) {
			fmt.Println("--")
		}
	}
}

func showSiteCert() {
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
		// try to add '[]' for IPv6 and set default port
		serverStr = "[" + os.Args[len(os.Args)-1] + "]:443"
		conn, err = tls.Dial("tcp", serverStr, &tlsCfg)
	}
	if err != nil {
		fmt.Printf("Cannot connect to %v: %v\n", serverStr, err)
		os.Exit(1)
	}
	defer conn.Close()

	if !cfgValidityDaysOnly {
		fmt.Printf("Connected to %v\n", serverStr)
	}
	showCrtInfo(conn.ConnectionState().PeerCertificates[0])
}
