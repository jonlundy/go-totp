package main

import (
	"github.com/JonLundy/go-totp/totp"
	"bufio"
	"os"
	"encoding/base32"
	"time"
	"crypto/sha1"
	"fmt"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	key, _ := reader.ReadString('\n')

	k, _ := base32.StdEncoding.DecodeString(key)

	code, _ := totp.Totp(k, time.Now().Unix(), sha1.New, 6)
	fmt.Print(code)
}