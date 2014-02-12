package totp

import (
  "fmt"
  "time"
  "hash"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
  "encoding/base32"
  "testing"
)

func TestTotp (t *testing.T) {
    var err error
    var totp string

    key, err := base32.StdEncoding.DecodeString("KR5IFRJE7N7NFHH3")

    totp, _ = Totp(key, time.Now().Unix(), sha1.New, 6)
    fmt.Println("Google AUTH: KR5IFRJE7N7NFHH3 TOTP:", totp)

    for i := int64(1); i < 10; i++ {
        totp, err = Totp(key, time.Now().Unix(), sha1.New, i)
        if err != nil {
            t.Error(err)
        }
        if int64(len(totp)) != i {
            t.Error("Length not equal: ", i)
        }
    }

    for _, v := range testvectors {
        totp, err = Totp(genkey(v.l), v.t, v.h, 8)
        if err != nil {
            t.Error(err)
        }
        if totp != v.s {
            t.Error("Wrong Code Generation: Expect:", v.s, " Got: ",totp)
        }

    }

}

func genkey(l int64) []byte {
    s := make([]byte,l)

    for i:=int64(0);i<l;i++ {
        s[i] = byte((i+1)%10+48)
    }
    return s
}

type testvector struct {
    l int64
    t int64
    h func() hash.Hash
    s string
}
var testvectors []testvector = []testvector{{20,          59,   sha1.New, "94287082"},
                                            {32,          59, sha256.New, "46119246"},
                                            {64,          59, sha512.New, "90693936"},
                                            {20,  1111111109,   sha1.New, "07081804"},
                                            {32,  1111111109, sha256.New, "68084774"},
                                            {64,  1111111109, sha512.New, "25091201"},
                                            {20,  1111111111,   sha1.New, "14050471"},
                                            {32,  1111111111, sha256.New, "67062674"},
                                            {64,  1111111111, sha512.New, "99943326"},
                                            {20,  1234567890,   sha1.New, "89005924"},
                                            {32,  1234567890, sha256.New, "91819424"},
                                            {64,  1234567890, sha512.New, "93441116"},
                                            {20,  2000000000,   sha1.New, "69279037"},
                                            {32,  2000000000, sha256.New, "90698825"},
                                            {64,  2000000000, sha512.New, "38618901"},
                                            {20, 20000000000,   sha1.New, "65353130"},
                                            {32, 20000000000, sha256.New, "77737706"},
                                            {64, 20000000000, sha512.New, "47863826"}}
