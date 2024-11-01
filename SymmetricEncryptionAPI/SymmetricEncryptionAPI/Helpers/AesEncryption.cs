using System.Security.Cryptography;
using System.Text;

namespace SymmetricEncryptionAPI.Helpers
{
    public class AesEncryption
    {
        private readonly byte[] _key;

        public AesEncryption(string key)
        {
            // Generate a 256-bit key from the given string using SHA256
            using (var sha256 = SHA256.Create())
            {
                _key = sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            }
        }

        public string Encrypt(string plainText)
        {
            // Generate a unique IV for each encryption
            using (var aes = Aes.Create())
            {
                aes.Key = _key;
                aes.GenerateIV(); // Create a random IV
                var iv = aes.IV;

                using (var encryptor = aes.CreateEncryptor(aes.Key, iv))
                using (var msEncrypt = new MemoryStream())
                {
                    // Prepend IV to the memory stream
                    msEncrypt.Write(iv, 0, iv.Length);

                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        public string Decrypt(string cipherText)
        {
            try
            {
                // Decode the base64-encoded cipherText
                var fullCipher = Convert.FromBase64String(cipherText);

                // Extract IV from the first 16 bytes of fullCipher
                var iv = new byte[16];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);

                // Extract the actual ciphertext (without the IV)
                var actualCipherText = new byte[fullCipher.Length - iv.Length];
                Array.Copy(fullCipher, iv.Length, actualCipherText, 0, actualCipherText.Length);

                using (var aes = Aes.Create())
                {
                    aes.Key = _key;
                    aes.IV = iv;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    using (var msDecrypt = new MemoryStream(actualCipherText))
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {
                        // Read and return the decrypted plaintext
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
            catch (CryptographicException ex)
            {
                // Log the specific padding error for debugging
                Console.WriteLine("Decryption failed: Padding is invalid and cannot be removed.");
                throw new InvalidOperationException("Decryption failed. Ensure encryption and decryption configurations match.", ex);
            }
        }

    }
}
