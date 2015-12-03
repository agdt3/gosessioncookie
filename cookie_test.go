package sessioncookie

import (
    "time"
    "testing"
    "crypto/hmac"
    "encoding/json"
)


type SessionValue struct {
    Id int
    Username string
}


const (
    sep = "||"
)


func setUp() ([]byte, SessionValue, []byte) {
    key := make([]byte, 32)
    value := SessionValue{1, "asdf son of asdf"}
    now := time.Now().Format(time.UnixDate)
    timestamp := []byte(now)
    return key, value, timestamp
}


func TestEncryptionDecryption (t *testing.T) {
    secret_key, value, _ := setUp()
    plaintext, _ := json.Marshal(value)

    encrypted_value, _ := EncryptCookieValue(secret_key, plaintext, sep)
    returned_value, _ := DecryptCookieValue(secret_key, encrypted_value, sep)

    if string(plaintext) != returned_value {
        t.Error("encrypted value does not match decrypted value")
    }
}


func TestEncryptDecryptData (t *testing.T) {
    secret_key, value, _ := setUp()
    plaintext, _ := json.Marshal(value)

    encrypted_data, _ := encryptData(secret_key, plaintext)
    decrypted_data, _ := decryptData(secret_key, encrypted_data)

    if string(encrypted_data) == decrypted_data {
        t.Error("encrypted data should not match decrypted data")
    }

    if decrypted_data != string(plaintext) {
        t.Error("decrypted data does not match plaintext")
    }
}


func TestRepeatedEncryption (t *testing.T) {
    secret_key, value, _ := setUp()
    plaintext, _ := json.Marshal(value)

    encrypted_data1, _ := encryptData(secret_key, plaintext)
    encrypted_data2, _ := encryptData(secret_key, plaintext)

    if string(encrypted_data1) == string(encrypted_data2) {
        t.Error("Encryption IV should modify encrypted output")
    }
}


func TestGenerateHMAC (t *testing.T) {
    secret_key, value, timestamp := setUp()
    plaintext, _ := json.Marshal(value)

    encrypted_data, _ := encryptData(secret_key, plaintext)
    hash_mac1 := generateHMAC(secret_key, timestamp, encrypted_data)
    hash_mac2 := generateHMAC(secret_key, timestamp, encrypted_data)
    if !hmac.Equal(hash_mac1, hash_mac2) {
        t.Error("Same values should generate the same hmac signature")
    }
}


func TestCompareHMACTimestamp (t *testing.T) {
    /*
        Changing timestamp should fail
        a comparison between generated HMAC signatures
    */

    secret_key, value, timestamp1 := setUp()
    plaintext, _ := json.Marshal(value)

    ts := time.Now().Add(time.Duration(time.Second))
    sts := ts.Format(time.UnixDate)
    timestamp2 := []byte(sts)

    if string(timestamp1) == string(timestamp2) {
        t.Error("Timestamps should be different")
    }

    encrypted_data, _ := encryptData(secret_key, plaintext)
    hash_mac1 := generateHMAC(secret_key, timestamp1, encrypted_data)
    hash_mac2 := generateHMAC(secret_key, timestamp2, encrypted_data)

    if hmac.Equal(hash_mac1, hash_mac2) {
        t.Error("Different timestamps should generate different hmac signature")
    }
}


func TestCompareHMACData (t *testing.T) {
    /*
        Changing encrypted data should fail
        a comparison between generated HMAC signatures
    */

    secret_key, value1, timestamp := setUp()
    plaintext1, _ := json.Marshal(value1)

    value2 := SessionValue{2, "asdf son of asdf"}
    plaintext2, _ := json.Marshal(value2)

    if string(plaintext1) == string(plaintext2) {
        t.Error("Data should be different")
    }

    encrypted_data1, _ := encryptData(secret_key, plaintext1)
    encrypted_data2, _ := encryptData(secret_key, plaintext2)

    hash_mac1 := generateHMAC(secret_key, timestamp, encrypted_data1)
    hash_mac2 := generateHMAC(secret_key, timestamp, encrypted_data2)

    if hmac.Equal(hash_mac1, hash_mac2) {
        t.Error("Different data should generate different hmac signature")
    }
}
