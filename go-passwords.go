package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/atotto/clipboard"
	"github.com/magiconair/properties"
	"golang.org/x/term"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const initialVector = "eochiefeNg8eb8ba"

func main() {
	isDecode := flag.Bool("decode", false, "decode")
	gen := flag.Bool("gen", false, "gen")
	name := flag.String("name", "", "name")
	flag.Parse()

	pp, err := readPassword("Enter encryption key: ")
	if err != nil {
		log.Fatalln(err)
	}

	if len(pp) >= 16 {
		pp = pp[:16]
	} else {
		pp += strings.Repeat("0", 16-len(pp))
	}

	props := properties.MustLoadFile("./secure.properties", properties.UTF8)
	if *isDecode {
		encryptedPassword, ok := props.Get(*name)
		if !ok {
			log.Fatalf("Cannot find password: %s", *name)
		}

		encryptedData, err := base64.StdEncoding.DecodeString(encryptedPassword)
		if err != nil {
			log.Fatalln(err)
		}

		decryptedText := AESDecrypt(encryptedData, []byte(pp))
		clipboard.WriteAll(string(decryptedText))
	} else {
		var plainText string
		if !*gen {
			plainText, err = readPassword("\nEnter password: ")
			if err != nil {
				log.Fatalf("\n%v\n", err)
			}
			fmt.Println()
		} else {
			cmd := exec.Command("pwgen", "20", "1")
			out, err := cmd.Output()
			if err != nil {
				log.Fatalln(err)
			}

			plainText = string(out)
			clipboard.WriteAll(plainText)
		}

		encryptedData := AESEncrypt(plainText, []byte(pp))
		encryptedString := base64.StdEncoding.EncodeToString(encryptedData)
		props.Set(*name, encryptedString)

		fpath, err := os.Readlink("./secure.properties")
		if err != nil {
			log.Fatalln(err)
		}

		fpath, err = filepath.Abs(fpath)
		if err != nil {
			log.Fatalln(err)
		}

		log.Printf("\nStoring to path: %s\n", fpath)
		f, err := os.OpenFile(fpath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0400)
		if err != nil {
			log.Fatalln(err)
		}
		defer f.Close()

		n, err := props.Write(f, properties.UTF8)
		if err != nil {
			log.Fatalln(err)
		}

		log.Printf("Store bytes: %d\n", n)
	}
}

func readPassword(text string) (string, error) {
	fmt.Print(text)
	bytePassword, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return "", err
	}

	password := string(bytePassword)
	return strings.TrimSpace(password), nil
}

func AESEncrypt(src string, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if src == "" {
		fmt.Println("plain content empty")
	}
	ecb := cipher.NewCBCEncrypter(block, []byte(initialVector))
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return crypted
}

func AESDecrypt(crypt []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if len(crypt) == 0 {
		fmt.Println("plain content empty")
	}
	ecb := cipher.NewCBCDecrypter(block, []byte(initialVector))
	decrypted := make([]byte, len(crypt))
	ecb.CryptBlocks(decrypted, crypt)

	return PKCS5Trimming(decrypted)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
