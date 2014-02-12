package totp

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

var step int64 = 30
var epoch int64 = 0

func Totp(k []byte, t int64, h func() hash.Hash, l int64) (string, error) {

	if l > 9 || l < 1 {
		return "", errors.New("Totp: Length out of range.")
	}

	time := new(bytes.Buffer)

	err := binary.Write(time, binary.BigEndian, (t-epoch)/step)
	if err != nil {
		return "", err
	}

	hash := hmac.New(h, k)
	hash.Write(time.Bytes())
	v := hash.Sum(nil)

	o := v[len(v)-1]&0xf
	c := (int32(v[o]&0x7f)<<24 | int32(v[o+1])<<16 | int32(v[o+2])<<8 | int32(v[o+3])) % 1000000000

	return fmt.Sprintf("%010d", c)[10-l:10], nil
}
