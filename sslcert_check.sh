#!/bin/bash
# by aadz, 2016
# Check if SSL certificate exrired or will expire soon

# Configuration 
CONNECT_TO="$1"	   # In HOST:PORT format
MAIL_TO='ssl-cert' # see /etc/aliases
MIN_DAYS=30	   # send notification if it is less than validity days left

MAIL_APP=/usr/bin/mail
SSL_APP=/usr/bin/openssl

send_warning() {
	#echo "$1"
	echo "$1" | $MAIL_APP -s "$CONNECT_TO - certificate expiration warning" $MAIL_TO
	exit $?
}

# Parameters check
if [ -z "$CONNECT_TO" ]; then
	echo "Usage: $0 HOST:PORT"
	exit 1
else
	CHK_HOST=$( echo "$CONNECT_TO" | /usr/bin/cut -d':' -f1 )
	echo $CHK_HOST | egrep -vq '^[0-9.]+$' &&
	/usr/bin/host $CHK_HOST &>/dev/null ||
	send_warning "Cannot resolve $CHK_HOST"
fi

# get expiration time
CERT_END_DATE=$(
	echo | $SSL_APP s_client -connect $CONNECT_TO 2>/dev/null |
	/usr/bin/awk '/^-+BEGIN CERTIFICATE-+$/ {
		print
		while ($0 !~ /^-+END CERTIFICATE-+$/) {getline; print}
		exit
	}' | $SSL_APP x509 -enddate -noout |
	/usr/bin/cut -d'=' -f2
)
#echo Certificate end date: $CERT_END_DATE

if [ -z "$CERT_END_DATE" ]; then
	send_warning "Cannot get certitcate expiration time for $CONNECT_TO"
else
	CERT_END_SEC=`/bin/date -d "$CERT_END_DATE" '+%s'`
	NOW_SEC=`/bin/date '+%s'`
	DAYS_LEFT=$(( ($CERT_END_SEC - $NOW_SEC) / 86400 ))
	#echo $DAYS_LEFT days left

	if [ $DAYS_LEFT -le $MIN_DAYS ]; then
		send_warning "Certificate is valid until: $CERT_END_DATE ($DAYS_LEFT days left)"
	fi
fi
