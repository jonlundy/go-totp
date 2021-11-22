package main

import (
	"github.com/JonLundy/go-totp/pkg/totp"
	"bufio"
	"os"
	"encoding/base32"
	"time"
	"crypto/sha1"
	"fmt"
        "strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	key, _ := reader.ReadString('\n')

	key = strings.ToUpper(strings.Trim(key, "=\n"))

        if i := len(key) % 8; i != 0 {
           key += strings.Repeat("=", 8-i)
        }

        k, _ := base32.StdEncoding.DecodeString(key)

	code, _ := totp.Totp(k, time.Now().Unix(), sha1.New, 6)
	fmt.Print(code)
}

