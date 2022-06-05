using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using PerrysNetConsole;

namespace SafeFolder
{
    public static class Utils{

        #region IO

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

        /// <summary>
        /// Deletes a file in a secure way by overwriting it with
        /// random garbage data n times.
        /// </summary>
        /// <param name="filename">Full path of the file to be deleted</param>
        public static void WipeFile(string filename, Progress prog)
        {
            try
            {
                if (!File.Exists(filename)) return;
                // Set the files attributes to normal in case it's read-only.
                File.SetAttributes(filename, FileAttributes.Normal);

                // Calculate the total number of sectors in the file.
                var sectors = (int)Math.Ceiling(new FileInfo(filename).Length/512.0);
                    
                // Create a dummy-buffer the size of a sector.
                var buffer = new byte[512];

                // Open a FileStream to the file.
                var inputStream = new FileStream(filename, FileMode.Open);

                // Loop all sectors
                for (var i = 0; i < sectors; i++)
                {
                    // write zeros
                    inputStream.Write(buffer, 0, buffer.Length);
                }
                // truncate file
                inputStream.SetLength(0);
                // Close the stream.
                inputStream.Close();

                // wipe dates
                var dt = new DateTime(2037, 1, 1, 0, 0, 0);
                File.SetCreationTime(filename, dt);
                File.SetLastAccessTime(filename, dt);
                File.SetLastWriteTime(filename, dt);

                File.SetCreationTimeUtc(filename, dt);
                File.SetLastAccessTimeUtc(filename, dt);
                File.SetLastWriteTimeUtc(filename, dt);

                // Finally, delete the file
                File.Delete(filename);
            }
            catch(Exception e)
            {
                prog.Message(Message.LEVEL.ERROR, "Error wiping file: " + e.Message);
            }
        }
        
        #endregion
        
    }
}
