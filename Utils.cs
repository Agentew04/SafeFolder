using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SafeFolder
{
    public static class Utils{

        #region IO

        /// <summary>
        /// Shows a prompt and gets a string from the user(formatted with *).
        /// </summary>
        /// <param name="prompt">The text to be shown</param>
        /// <returns>The input the user typed</returns>
        public static string GetPasswordInput(string prompt = "")
        {
            Console.Write(prompt);
            var password = "";
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key != ConsoleKey.Backspace || password.Length <= 0) continue;
                    password = password[..^1]; // black magic, but it works
                    Console.Write("\b \b");
                }
            }
            while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return password;
        }

        /// <summary>
        /// Shows the splash screen.
        /// </summary>
        public static void ShowSplashScreen()
        {
            Console.WriteLine(@"
=============================================

            Welcome to SafeFolder
                   v0.1.0

=============================================
");
        }

        /// <summary>
        /// Writes a line to the console, with a color.
        /// </summary>
        /// <param name="message">The message, if not ends with \n, \n will be appended</param>
        /// <param name="color">The color to write the message</param>
        public static void WriteLine(string message, ConsoleColor color = ConsoleColor.White)
        {
            Console.ForegroundColor = color;
            if(!message.EndsWith("\n"))
                message+= "\n";
            Console.Write(message);
            Console.ResetColor();
        }
        
        #endregion

        #region Binary

        /// <summary>
        /// Writes a GUID bytes to a binary stream
        /// </summary>
        /// <param name="stream">The binary stream</param>
        /// <param name="guid">The <see cref="Guid"/> to be written</param>
        private static void Write(this BinaryWriter stream, Guid guid) => stream.Write(guid.ToByteArray());

        /// <summary>
        /// Reads a guid from a binary stream
        /// </summary>
        /// <param name="stream">The binary stream</param>
        /// <returns>The guid that has been read</returns>
        private static Guid ReadGuid(this BinaryReader stream) => new(stream.ReadBytes(16));
            
        /// <summary>
        /// Writes the file header to the stream
        /// </summary>
        /// <param name="writer">The binaryWrite object</param>
        /// <param name="header">The header object</param>
        public static void Write(this BinaryWriter writer, Header header)
        {
            writer.Write(header.Hash);
            writer.Write(header.IsFolder);
            writer.Write(header.Name);
            writer.Write(header.Guid);
            writer.Write(header.IvLength);
            writer.Write(header.Iv);
        }
        
        /// <summary>
        /// Reads a header from a binary stream
        /// </summary>
        /// <param name="reader">the stream</param>
        /// <returns>The header file that has been read</returns>
        public static Header ReadHeader(this BinaryReader reader)
        {
            var header = new Header
            {
                Hash = reader.ReadString(),
                IsFolder = reader.ReadBoolean(),
                Name = reader.ReadString(),
                Guid = reader.ReadGuid(),
                IvLength = reader.ReadInt32(),
            };
            header.Iv = reader.ReadBytes(header.IvLength);
            return header;
        }
        
        #endregion
        
        #region Cryptography
        public static string HashBytes(byte[] bytes)
        {
            using var sha = SHA512.Create();
            return Convert.ToHexString(sha.ComputeHash(bytes));
        }

        /// <summary>
        /// Creates a key based on one or two strings. String -> Byte[] uses UTF8
        /// </summary>
        /// <param name="input">The main input</param>
        /// <param name="salt">The salt used. If <see langword="null"/>, the salt will be a empty array</param>
        /// <returns>The Key derived</returns>
        public static byte[] DeriveKeyFromString(string input, string salt = null)
        {
            //get input bytes
            var inputBytes = Encoding.UTF8.GetBytes(input);
            var saltBytes = salt != null ? Encoding.UTF8.GetBytes(salt) : new byte[16];
            // Generate the hash
            Rfc2898DeriveBytes pbkdf2 = new(inputBytes, saltBytes, iterations: 5000, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(32); //32 bytes length is 256 bits
        }

        /// <summary>
        /// Generates a random iv for AES
        /// </summary>
        /// <returns>The IV that has been generated</returns>
        public static byte[] GenerateIv()
        {
            //generate random IV
            using var aes = Aes.Create();
            return aes.IV;
        }
        public static string GetHash(string str){
            return BCrypt.Net.BCrypt.HashPassword(str);
        }        
        public static bool CheckHash(string password, string hash){
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        #endregion
        
    }
}
