/*
    Author: Pavel Abramov
    Examples taken from golang docs and Mozilla's
    nodejs clientside session library
*/

package sessioncookie

import (
    "io"
    "time"
    "errors"
    "strings"
    "crypto/aes"
    "crypto/rand"
    "crypto/hmac"
    "crypto/cipher"
    "crypto/sha256"
    "encoding/base64"
)


func concatValue(hash_mac string, timestamp string, data string, sep string) string {
    if sep == "" {
        sep = "."
    }
    return hash_mac + sep+ timestamp + sep + data
}


func encryptData(secret_key []byte, data []byte) ([]byte, error)  {
    // add padding to block size
    remainder := len(data) % aes.BlockSize
    if remainder != 0 {
        padding_length := aes.BlockSize - remainder
        padding := ""
        for i := 0; i < padding_length; i++ {
            padding += "="
        }
        data = append(data, padding...)
    }

    block, err := aes.NewCipher(secret_key)
    if err != nil {
        return []byte{}, err
    }

    // empty array of size block + data
    ciphertext := make([]byte, aes.BlockSize+len(data))

    // iv is appended to ciphertext
    iv := ciphertext[:aes.BlockSize]

    // reads from rand.Reader global singleton PRNG into iv
    _, err = io.ReadFull(rand.Reader, iv)
    if err != nil {
        return []byte{}, err
    }

    // data is encrypted
    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[aes.BlockSize:], data)

    return ciphertext, nil
}


func decryptData(secret_key []byte, encrypted_data []byte) (string, error) {
    block, err := aes.NewCipher(secret_key)
    if err != nil {
        return "", err
    }

    if len(encrypted_data) < aes.BlockSize {
        return "", errors.New("encrypted data is less than BlockSize")
    }

    iv := encrypted_data[:aes.BlockSize]
    data := encrypted_data[aes.BlockSize:]

    if len(data) % aes.BlockSize != 0 {
        return "", errors.New("encrypted data is not a multiple of block size")
    }

    mode := cipher.NewCBCDecrypter(block, iv)

    mode.CryptBlocks(data, data)

    // remove padding
    trimmed_data := strings.TrimRight(string(data), "=")

    return trimmed_data, nil
}


func generateHMAC(secret_key []byte, timestamp []byte, encrypted_data []byte) []byte {
    message := append(timestamp, encrypted_data...)

    // create hash mac
    hash_mac := hmac.New(sha256.New, secret_key)
    hash_mac.Write(message)

    // return byte array
    return hash_mac.Sum(nil)
}


func EncryptCookieValue(secret_key []byte, plaintext_data []byte, sep string) (string, error) {
    // generate timestamp
    now := time.Now()
    timestamp := []byte(now.Format(time.UnixDate))
    encoded_timestamp := base64.URLEncoding.EncodeToString(timestamp)

    // generate data blob
    encrypted_data, err := encryptData(secret_key, plaintext_data)
    if err != nil {
        return "", err
    }

    encoded_data := base64.URLEncoding.EncodeToString(encrypted_data)

    // generate data blob
    // generate hmac
    hash_mac := generateHMAC(secret_key, timestamp, encrypted_data)
    encoded_hash_mac := base64.URLEncoding.EncodeToString(hash_mac)

    // return encoded values
    return concatValue(encoded_hash_mac, encoded_timestamp, encoded_data, sep), nil
}


func DecryptCookieValue(secret_key []byte, cookie_value string, sep string) (string, error) {
    if sep == "" {
        sep = "."
    }

    // extract value
    value := strings.Split(cookie_value, sep)
    encoded_hash_mac := value[0]
    encoded_timestamp := value[1]
    encoded_data := value[2]

    //decode
    encrypted_data, err := base64.URLEncoding.DecodeString(encoded_data)
    if err != nil {
        return "", err
    }

    timestamp, err := base64.URLEncoding.DecodeString(encoded_timestamp)
    if err != nil {
        return "", err
    }

    returned_hmac, err := base64.URLEncoding.DecodeString(encoded_hash_mac)
    if err != nil {
        return "", err
    }

    // compute and compare
    computed_hmac := generateHMAC(secret_key, timestamp, encrypted_data)

    if !hmac.Equal(returned_hmac, computed_hmac) {
        return "", errors.New("Returned HMAC does not match")
    }

    // hmac matches, now decrypt data.
    data, err := decryptData(secret_key, encrypted_data)
    if err != nil {
        return "", err
    }

    return string(data), nil
}
