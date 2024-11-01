import CryptoJS from 'crypto-js';

// Secret key
export const key = "YourEncryptionKey";

// Function to encrypt plaintext
export const encrypt = (plainText, key) => {
    // Generate a 256-bit key using SHA256 hash
    const hashedKey = CryptoJS.SHA256(key).toString(CryptoJS.enc.Hex);

    // Generate a random 16-byte IV
    const iv = CryptoJS.lib.WordArray.random(16);

    // Encrypt with AES
    const encrypted = CryptoJS.AES.encrypt(plainText, CryptoJS.enc.Hex.parse(hashedKey), {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
    });

    // Combine IV and ciphertext, then encode in Base64
    return CryptoJS.enc.Base64.stringify(iv.concat(encrypted.ciphertext));
};


// Function to decrypt ciphertext
export const decrypt = (cipherText, key) => {
    // Decode the base64-encoded cipherText
    const fullCipher = CryptoJS.enc.Base64.parse(cipherText);

    // Extract IV from the first 16 bytes (128 bits / 8 = 16 bytes)
    const iv = CryptoJS.lib.WordArray.create(fullCipher.words.slice(0, 4), 16);

    // Extract the actual ciphertext without the IV
    const actualCipherText = CryptoJS.lib.WordArray.create(
        fullCipher.words.slice(4),
        fullCipher.sigBytes - 16
    );

    // Generate the hashed key as a WordArray
    const hashedKey = CryptoJS.SHA256(key);

    // Decrypt with AES using CBC mode and PKCS7 padding
    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: actualCipherText },
        hashedKey,
        {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
        }
    );

    // Convert decrypted data to UTF-8 string
    const data = decrypted.toString(CryptoJS.enc.Utf8);

    return data;
};