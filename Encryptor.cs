using System;
using System.IO;
using System.Security.Cryptography;

namespace SafeFolder{
    public static class Encryptor{
        internal static void AesFileEncrypt(string inputFile, string outputFile, byte[] key,byte[] iv){
            var cryptFile = outputFile ?? throw new ArgumentNullException(nameof(outputFile));
            using var fsCrypt = new FileStream(cryptFile, FileMode.Create);

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            using var cs = new CryptoStream(fsCrypt,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write);

            using var fsIn = new FileStream(inputFile, FileMode.Open);

            int data;
            while ((data = fsIn.ReadByte()) != -1)
                cs.WriteByte((byte)data);
        }

        internal static void AesFileDecrypt(string inputFile, string outputFile, byte[] key,byte[] iv){
            using var fsCrypt = new FileStream(inputFile, FileMode.Open);

            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            using var cs = new CryptoStream(fsCrypt,
                aes.CreateDecryptor(),
                CryptoStreamMode.Read);

            using var fsOut = new FileStream(outputFile, FileMode.Create);

            int data;
            while ((data = cs.ReadByte()) != -1)
                fsOut.WriteByte((byte)data);
        }
        
        public static string AesEncryptString(string plainText, byte[] key, byte[] iv)
        {
            // Check arguments.
            if (plainText is not { Length: > 0 })
                throw new ArgumentNullException(nameof(plainText));
            if (key is not { Length: > 0 })
                throw new ArgumentNullException(nameof(key));
            if (iv is not { Length: > 0 })
                throw new ArgumentNullException(nameof(iv));

            // Create an AesManaged object
            // with the specified key and IV.
            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;

            // Create an encryptor to perform the stream transform.
            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using var swEncrypt = new StreamWriter(csEncrypt);
            //Write all data to the stream.
            swEncrypt.Write(plainText);
            var encrypted = msEncrypt.ToArray();

            // Return the encrypted bytes from the memory stream.
            return Convert.ToBase64String(encrypted);
        }

        public static string AesDecryptString(string cipherText, byte[] key, byte[] iv)
        {
            // Check arguments.
            if (cipherText is not { Length: > 0 })
                throw new ArgumentNullException(nameof(cipherText));
            if (key is not { Length: > 0 })
                throw new ArgumentNullException(nameof(key));
            if (iv is not { Length: > 0 }) //black magic
                throw new ArgumentNullException(nameof(iv));

            // Declare the string used to hold
            // the decrypted text.

            // Create an AesManaged object
            // with the specified key and IV.
            // was using AesManaged aesAlg = new AesManaged();
            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;

            // Create a decryptor to perform the stream transform.
            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            var cipherTextBytes = Convert.FromBase64String(cipherText);

            // Create the streams used for decryption.
            using var msDecrypt = new MemoryStream(cipherTextBytes);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            // Read the decrypted bytes from the decrypting stream
            // and place them in a string.
            var plaintext = srDecrypt.ReadToEnd();

            return plaintext;
        }

    }
}