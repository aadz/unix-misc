# Miscellaneous UNIX admin scripts

* [go-socks](#go-socks)
* [shasum.go](#shasum)
* [sslcert_enddate_check.sh](#sslcert-enddate-check)
* [tls_cert_info.go](#tls-cert-info)

## go-socks
A simple SOCKS5 server written in Go.

## rusage.go
Resoure usage informatioin dump. See `man 2 getrusage` for fields description.

```
# rusage /bin/date
Mon Jun 17 06:11:46 MSK 2019

Utime:                  0.000
Stime:                  0.000
Rtime:                  0.002
Maxrss:                  1932
Ixrss:                      0
Idrss:                      0
Isrss:                      0
Minflt:                    62
Majflt:                     0
Nswap:                      0
Inblock:                    0
Oublock:                    0
Msgsnd:                     0
Msgrcv:                     0
Nsignals:                   0
Nvcsw:                      1
Nivcsw:                     1
```

## shasum.go<a name="shasum"></a>
Read Stdin and compute SHA1|SHA256|SHA384|SHA512 digest of it.

```text
Usage of shasum:
  -1    SHA1 (default true)
  -256
        SHA256
  -384
        SHA384
  -512
        SHA512
  -X    print in upper case
  -c    print as a colon delimited string
  -s    print as a space delimited string
```
                                      
## sslcert_enddate_check.sh<a name="sslcert-enddate-check"></a>
Script checks if SSL certificate expired or will expire soon and send notification by email.

## tls_cert_info.go<a name="tls-cert-info"></a>
TLS certificate information grabber supporting IPv6 server addresses as well as UTF domain names.
If you need a local PEM encoded certificate file info use `-f` command line option. And `-h` for
help as usual.

Example of run:
```text
$ tls_cert_info -v example.com
*** Connected to example.com:443
*** Certificate info:
IssuerCN:       DigiCert SHA2 Secure Server CA
Version:        3
SerialNum:      fd078dd48f1a2bd4d0f2ba96b6038fe
PubKey:         RSA Encryption
CrtSign:        SHA256 With RSA Encryption
NotBefore:      2018-11-28 00:00:00 +0000 UTC
NotAfter:       2020-12-02 12:00:00 +0000 UTC - 187 days left
Subject:        CN=www.example.org,OU=Technology,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
DNSNames:       www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net
Usage:          DigitalSignature KeyEncipherment ExtServerAuth ExtClientAuth
*** Fingerprints:
sha1:           7b:b6:98:38:69:70:36:3d:29:19:cc:57:72:84:69:84:ff:d4:a8:89
sha256:         92:50:71:1c:54:de:54:6f:43:70:e0:c3:d3:a3:ec:45:bc:96:09:2a:25:a4:a7:1a:1a:fa:39:6a:f7:04:7e:b8
SPKI:           i9HalScvf6T/skE3/A7QOq5n5cTYs8UHNOEFCnkguSI=
```

### Install on Linux (64-bit)

```bash
wget https://github.com/aadz/unix-misc/blob/master/packages/tls_cert_info-LinuxAMD64?raw=true \
  -O /usr/local/bin/tls_cert_info
chmod 0755 /usr/local/bin/tls_cert_info
```
