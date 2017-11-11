/* 
	Read Stdin and compute SHA1|SHA256|SHA384|SHA512 digest
*/
package main

import (
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

var (
	flag1, flag256, flag384, flag512 bool // hash sizes
	flagColon, flagSpace             bool // print summ as a colon/space delemited string
	flagUpper                        bool // print hex nums in upper case
)

func init() {
	flag.BoolVar(&flag1, "1", true, "SHA1")
	flag.BoolVar(&flag256, "256", false, "SHA256")
	flag.BoolVar(&flag384, "384", false, "SHA384")
	flag.BoolVar(&flag512, "512", false, "SHA512")
	flag.BoolVar(&flagColon, "c", false, "as a colon delimited string")
	flag.BoolVar(&flagSpace, "s", false, "as a space delimited string")
	flag.BoolVar(&flagUpper, "X", false, "print hex nums in upper case")
}

func main() {
	var (
		sumStr    string
		delimiter string
		h         hash.Hash
	)

	// command line flags processing
	flag.Parse()
	if flag512 { // size
		h = sha512.New()
	} else if flag384 {
		h = sha512.New384()
	} else if flag256 {
		h = sha256.New()
	} else {
		h = sha1.New()
	}
	if flagColon { // delimmiter
		delimiter = ":"
	} else if flagSpace {
		delimiter = " "
	} else {
		delimiter = ""
	}

	// create and print checksumm
	//written, err := io.Copy(h, os.Stdin)
	_, err := io.Copy(h, os.Stdin)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	// fmt.Println("***", written, "bytes written.")
	sumStr = byteSlice2Str(h.Sum(nil), delimiter)
	fmt.Println(sumStr)
}

// convert a slice of bytes to a delimited hexs string
func byteSlice2Str(sl []byte, delimiter string) string {
	var format string
	strArr := make([]string, len(sl))

	if flagUpper {
		format = "%0.2X"
	} else {
		format = "%0.2x"
	}
	for i, b := range sl {
		strArr[i] = fmt.Sprintf(format, b)
	}
	return strings.Join(strArr, delimiter)
}
