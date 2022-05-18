using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Linq;

namespace SafeFolder{
    public static class Encryptor{
        internal static void AESFileEncrypt(string inputFile, string outputFile, byte[] key,byte[] iv){
            var cryptFile = outputFile ?? throw new ArgumentNullException(nameof(outputFile));
            using var fsCrypt = new FileStream(cryptFile, FileMode.Create);

            using var AES = Aes.Create();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Key = key;
            AES.IV = iv;
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CBC;

            using var cs = new CryptoStream(fsCrypt,
                AES.CreateEncryptor(),
                CryptoStreamMode.Write);

            using var fsIn = new FileStream(inputFile, FileMode.Open);

            int data;
            while ((data = fsIn.ReadByte()) != -1)
                cs.WriteByte((byte)data);
        }

        internal static void AESFileDecrypt(string inputFile, string outputFile, byte[] key,byte[] iv){
            using var fsCrypt = new FileStream(inputFile, FileMode.Open);

            using var AES = Aes.Create();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Key = key;
            AES.IV = iv;
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CBC;

            using var cs = new CryptoStream(fsCrypt,
                AES.CreateDecryptor(),
                CryptoStreamMode.Read);

            using var fsOut = new FileStream(outputFile, FileMode.Create);

            int data;
            while ((data = cs.ReadByte()) != -1)
                fsOut.WriteByte((byte)data);
        }
    }
}