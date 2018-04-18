# Miscellaneous UNIX admin script

* [go-socks.go](#go-socks.go)
* [shasum.go](#shasum)
* [sslcert_enddate_check.sh](#sslcert-enddate-check)
* [tls_cert_info.go](#tls-cert-info)

## go-socks.go
A simple SOCKS5 server.Unfortunately, all usage info in comments and coe for now.

## shasum.go<a name="shasum"></a>
Read Stdin and compute SHA1|SHA256|SHA384|SHA512 digest.

```text
Usage of shasum:
  -1    SHA1 (default true)
  -256
        SHA256
  -384
        SHA384
  -512
        SHA512
  -X    print hex nums in upper case
  -c    as a colon delimited string
  -s    as a space delimited string
```
                                      
## sslcert_enddate_check.sh<a name="sslcert-enddate-check"></a>
Script checks if SSL certificate expired or will expire soon and send notification by email.

## tls_cert_info.go<a name="tls-cert-info"></a>
TLS certificate information grabber supporting IPv6 server addresses as well as UTF domain names.
If you need a local PEM encoded certificates file same info use `-f` command line option. And `-h` for
help as usual.

Example of run:
```text
$ tls_cert_info example.com
Connected to example.com:443
*** Certificate info:
IssuerCN:       DigiCert SHA2 High Assurance Server CA
Version:        3
SerialNum:      e64c5fbc236ade14b172aeb41c78cb0
PubKey:         RSA Encryption
CrtSign:        SHA256 With RSA Encryption
NotBefore:      2015-11-03 00:00:00 +0000 UTC
NotAfter:       2018-11-28 12:00:00 +0000 UTC - 795 days left
SubjectCN:      www.example.org
DNSNames:       [www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net]
*** Fingerprints:
sha1:           25:09:fb:22:f7:67:1a:ea:2d:0a:28:ae:80:51:6f:39:0d:e0:ca:21
sha256:         64:2d:e5:4d:84:c3:04:94:15:7f:53:f6:57:bf:9f:89:b4:ea:6c:8b:16:35:1f:d7:ec:25:8d:55:6f:82:10:40
```
