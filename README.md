# Miscellaneous UNIX admin scripts

## sslcert_enddate_check.sh
Script checks if SSL certificate expired or will expire soon and send notification by email

## tls_cert_info.go
TLS certificate information grabber. Example of run:
```
$ ./tls_cert_info www.google.ru:443
Connected to www.google.ru:443
*** Certificate info:
Version:        3
Host:           [*.google.com.ru *.google.ru google.com.ru google.ru]
NotBefore:      2016-09-14 08:25:39 +0000 UTC
NotAfter:       2016-12-07 08:19:00 +0000 UTC
*** Fingerprints:
sha1:           d3:fa:53:d1:38:13:d2:14:b5:48:7d:d8:9f:c6:5b:ac:e0:c6:51:d3
sha256:         e3:5e:14:c4:3d:49:20:d1:69:3f:a1:44:bb:f2:e4:d1:0a:fa:59:c2:88:35:ff:de:d7:08:bc:b5:cc:22:35:b5
*** Note:
It is 2016-09-23 01:21:24.561347678 +0300 MSK now: 75 validity days left
```
