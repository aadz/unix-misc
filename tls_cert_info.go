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
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	PROG_NAME = "tls_cert_info"
	VERSION   = "0.9.5"
)

var (
	cfgPemFile          string
	cfgHost             string
	hostStr, portStr    string
	cfgConnTimeout      uint
	cfgPort             uint
	cfgValidityDaysOnly bool
	cfgVerbose          bool
	PKeyPKCS            [4]string  = [4]string{"Unknown", "RSA", "DSA", "ECDSA"}
	arrSignPKCS         [17]string = [17]string{
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
		"SHA256 With RSAPSS",
		"SHA384 With RSAPSS",
		"SHA512 With RSAPSS",
		"Pure Ed25519",
	}
	arrExtKeyUsage = [14]string{
		"Any",
		"ServerAuth",
		"ClientAuth",
		"CodeSigning",
		"EmailProtection",
		"IPSECEndSystem",
		"IPSECTunnel",
		"IPSECUser",
		"TimeStamping",
		"OCSPSigning",
		"MicrosoftServerGatedCrypto",
		"NetscapeServerGatedCrypto",
		"MicrosoftCommercialCodeSigning",
		"MicrosoftKernelCodeSigning",
	}
)

func init() {
	crtUsageStr := "Usage:\t%v [-d] <HOST>[:<PORT>]\n\t%v [-d] -H <HOST> [-P <PORT>]\n\t%v -f <filename>\n\n"
	crtUsageStr += "<HOST> might be a DNS name or an IP address. IPv6 address should be enclosed\n"
	crtUsageStr += "by square brackets.\n\nCommand line parameters:\n"

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, crtUsageStr, PROG_NAME, PROG_NAME, PROG_NAME)
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
	flag.BoolVar(&cfgValidityDaysOnly, "d", false, "Print remaining validity days count only")
	flag.StringVar(&cfgPemFile, "f", "", "File containing PEM encoded certificates")
	flag.StringVar(&cfgHost, "H", "", "Host")
	flag.UintVar(&cfgPort, "P", 443, "Port")
	flag.UintVar(&cfgConnTimeout, "t", 10, "Connect timeout, seconds")
	flag.BoolVar(&cfgVerbose, "v", false, "Verbose")
	flagVersion := flag.Bool("V", false, "Print version information and exit")
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
				fmt.Fprintf(os.Stderr, "Cannot convet %s to punycode: %s\n", hStr, err)
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
		return
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

	infoStr := fmt.Sprintf("*** Certificate info:\nIssuerCN:\t%v\n", crt.Issuer.CommonName)
	if cfgVerbose {
		infoStr += fmt.Sprintf("Version:\t%v\n", crt.Version)
		infoStr += fmt.Sprintf("SerialNum:\t%x\n", crt.SerialNumber)
		infoStr += fmt.Sprintf("PubKey:\t\t%v Encryption\n", PKeyPKCS[crt.PublicKeyAlgorithm])
		infoStr += fmt.Sprintf("CrtSign:\t%v Encryption\n", arrSignPKCS[crt.SignatureAlgorithm])
	}
	infoStr += fmt.Sprintf("NotBefore:\t%v\nNotAfter:\t%v - %s\n", crt.NotBefore, crt.NotAfter, expireStr)
	infoStr += fmt.Sprintf("Subject:\t%s\nDNSNames:\t%s\n",
		crt.Subject.String(), strings.Join(crt.DNSNames, " "))
	if cfgVerbose {
		crtUsageStr := crtUsageString(crt)
		if len(crtUsageStr) > 0 {
			crtUsageStr = fmt.Sprintf("Usage:\t\t%s\n", crtUsageStr)
			infoStr += crtUsageStr
		}

		sha1Fingerprint := sha1.Sum(crt.Raw)
		sha256Fingerprint := sha256.Sum256(crt.Raw)
		sha256TbsFingerprint := sha256.Sum256(crt.RawSubjectPublicKeyInfo)
		spki := base64.StdEncoding.EncodeToString(sha256TbsFingerprint[:])
		infoStr += fmt.Sprintf("*** Fingerprints:\nsha1:\t\t%v\nsha256:\t\t%v\nSPKI:\t\t%v\n",
			byteSlice2Str(sha1Fingerprint[:]), byteSlice2Str(sha256Fingerprint[:]), spki)
	}
	fmt.Printf(infoStr)
}

func showPemFile() {
	// read PEM certificates from a file
	crtPEM, err := ioutil.ReadFile(cfgPemFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}

	// decode PEM data
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
			fmt.Fprintf(os.Stderr, "failed to parse certificate: %s\n", err)
		}
		showCrtInfo(cert)

		// In days only mode show days
		// for the first certificate of the PEM file
		if cfgValidityDaysOnly {
			return
		}

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

	dialer := new(net.Dialer)
	dialer.Timeout = time.Duration(cfgConnTimeout) * time.Second
	// Connect to server
	serverStr := hostStr + ":" + portStr
	tlsCfg := tls.Config{InsecureSkipVerify: true}
	//conn, err := tls.Dial("tcp", serverStr, &tlsCfg)
	conn, err := tls.DialWithDialer(dialer, "tcp", serverStr, &tlsCfg)
	if err != nil && strings.Contains(err.Error(), "too many colons in address") {
		// try to add '[]' for IPv6 and set default port
		serverStr = "[" + os.Args[len(os.Args)-1] + "]:443"
		conn, err = tls.Dial("tcp", serverStr, &tlsCfg)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to %s: %s\n", serverStr, err)
		os.Exit(1)
	}
	defer conn.Close()

	if !cfgValidityDaysOnly && cfgVerbose {
		fmt.Printf("*** Connected to %s\n", serverStr)
	}
	showCrtInfo(conn.ConnectionState().PeerCertificates[0])
}

func crtUsageString(cert *x509.Certificate) string {
	res := make([]string, 0, 4)

	ku := cert.KeyUsage
	if ku&x509.KeyUsageDigitalSignature != 0 {
		res = append(res, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		res = append(res, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		res = append(res, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		res = append(res, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		res = append(res, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		res = append(res, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		res = append(res, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		res = append(res, "CRLSign")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		res = append(res, "DecipherOnly")
	}

	if len(cert.ExtKeyUsage) > 0 {
		for _, ext := range cert.ExtKeyUsage {
			res = append(res, fmt.Sprintf("Ext%s", arrExtKeyUsage[ext]))
		}

	}

	return strings.Join(res, " ")
}
