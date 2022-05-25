using System;
using System.IO;
using System.Security.Cryptography;

namespace SafeFolder{
    public static class Encryptor
    {
        private const int _keySize = 256;
        private const int _blockSize = 128;
        private const PaddingMode _paddingMode = PaddingMode.None;
        private const CipherMode _cipherMode = CipherMode.CBC;

        internal static MemoryStream AesStreamEncrypt(Stream inStream, byte[] key, byte[] iv){
            // validate parameters
            if (inStream == null)
                throw new ArgumentNullException(nameof(inStream));
            
            var bufferStream = new MemoryStream();

            using var aes = Aes.Create();
            aes.KeySize = _keySize;
            aes.BlockSize = _blockSize;
            aes.Padding = _paddingMode;
            aes.Mode = _cipherMode;
            aes.Key = key;
            aes.IV = iv;

            using var cs = new CryptoStream(bufferStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            
            Span<byte> buffer = stackalloc byte[1024];
            while (inStream.Read(buffer) > 0)
                cs.Write(buffer);

            // seek back to the beginning
            bufferStream.Seek(0, SeekOrigin.Begin);
            var ms = new MemoryStream();
            bufferStream.CopyTo(ms);
            ms.Seek(0, SeekOrigin.Begin);
            return ms;
        }

        internal static MemoryStream AesStreamDecrypt(Stream inStream, byte[] key,byte[] iv){
            // check for arguments
            if (inStream == null)
                throw new ArgumentNullException(nameof(inStream));

            var outputStream = new MemoryStream();
            using var aes = Aes.Create();
            aes.KeySize = _keySize;
            aes.BlockSize = _blockSize;
            aes.Padding = _paddingMode;
            aes.Mode = _cipherMode;
            aes.Key = key;
            aes.IV = iv;
            
            using var cs = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            Span<byte> buffer = stackalloc byte[1024];
            // int bytesRead;
            // while ( (bytesRead = cs.Read(buffer.ToArray(),0,buffer.Length)) > 0)
            //     outputStream.Write(buffer.ToArray(),0, bytesRead);
            
            //single byte read
            int data;
            while ((data=cs.ReadByte()) != -1)
                outputStream.WriteByte((byte)data);
            
            // seek back to the beginning
            outputStream.Seek(0, SeekOrigin.Begin);
            return outputStream;

            /*if(inStream == null)
                throw new ArgumentNullException(nameof(inStream));

            var ms = new MemoryStream();
            
            using var aes = Aes.Create();
            aes.KeySize = _keySize;
            aes.BlockSize = _blockSize;
            aes.Padding = _paddingMode;
            aes.Mode = _cipherMode;
            aes.Key = key;
            aes.IV = iv;

            using var cs = new CryptoStream(inStream,
                aes.CreateDecryptor(),
                CryptoStreamMode.Read);

            Span<byte> buffer = stackalloc byte[1024];
            int read;
            while ((read=cs.Read(buffer)) > 0)
                ms.Write(buffer);

            // seek back to the beginning
            ms.Seek(0, SeekOrigin.Begin);
            return ms;*/
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