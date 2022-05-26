using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
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
 - 1. Encrypt Files
 - 2. Decrypt Files
");
        }
        
        /// <summary>
        /// Shows the app corrupt message and reinstall the app.
        /// </summary>
        /// <returns></returns>
        public static bool ShowCorrupt()
        {
            Console.WriteLine(@"
=============================================
                
             _  
           .' ) 
 ,.--.    / .'          Installation is corrupted
//    \  / /    
\\    / / /     
 `'--' . '      
 ,.--. | |      
//    \' '      
\\    / \ \             Try reinstalling SafeFolder
 `'--'   \ \    
          \ '.  
           '._)
   

=============================================
");
            WriteLine("Press any key to Reinstall...", ConsoleColor.Yellow);
            Console.ReadKey(true);
            var canProceed = Installer.Install();
            if(!canProceed) {
                Utils.WriteLine("SafeFolder installation failed.", ConsoleColor.Red);
                Utils.WriteLine("Press any key to close...", ConsoleColor.Red);
                return false;
            }
            return true;
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
        /// Writes a list of strings to a binary stream(writable)
        /// </summary>
        /// <param name="stream">The binaryWriter object</param>
        /// <param name="strings">The list containing the strings</param>
        public static void Write(this BinaryWriter stream, IEnumerable<string> strings)
        {
            // Write the number of strings
            var stringsList = strings.ToList();
            stream.Write(stringsList.Count);
            
            // Write each string
            foreach (var str in stringsList)
            {
                stream.Write(str);
            }
        }

        /// <summary>
        /// Reads a list of strings written by <see cref="Write"/>
        /// </summary>
        /// <param name="stream">The stream containing the data</param>
        /// <returns>An IEnumerable with the strings read</returns>
        private static IEnumerable<string> ReadStrings(this BinaryReader stream)
        {
            var strings = new List<string>();
            // Read the number of strings
            var count = stream.ReadInt32();
            
            // Read each string
            for (var i = 0; i < count; i++)
            {
                strings.Add(stream.ReadString());
            }

            return strings;
        }

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
                Name = reader.ReadString(),
                Guid = reader.ReadGuid(),
                IvLength = reader.ReadInt32(),
            };
            header.Iv = reader.ReadBytes(header.IvLength);
            return header;
        }
        
        #endregion

        #region  safeFile
        
        private static readonly string _currentPath = Environment.CurrentDirectory;
        private static readonly string _safeFilePath = $"{_currentPath}/.safe";
        
        public static bool GetStateFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            var state = binaryReader.ReadBoolean();
            return state;
        }
        public static void SetStateToSafeFile(bool state)
        {
            using var binaryWriter = new BinaryWriter(File.OpenWrite(_safeFilePath));
            binaryWriter.Write(state);
        }
        
        public static string GetHashFromSafeFile()
        {
            try {
                using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
                _ = binaryReader.ReadBoolean();
                var hash = binaryReader.ReadString();
                return hash;
            } catch (Exception) {
                return "";
            }
        }

        public static IEnumerable<string> GetFilesFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            _ = binaryReader.ReadBoolean();
            _ = binaryReader.ReadString();
            var files = binaryReader.ReadStrings();
            return files;
        }

        public static void SetFilesToSafeFile()
        {
            var hash = GetHashFromSafeFile();
            var iv = Utils.GenerateIv();

            using var binaryWriter = new BinaryWriter(File.OpenWrite(_safeFilePath));
            binaryWriter.Write(false);
            binaryWriter.Write(hash);
            binaryWriter.Write(Installer.GetFiles());
            binaryWriter.Write(Installer.GetFolders());
            binaryWriter.Write(iv.Length);
            binaryWriter.Write(iv);
        }
        
        public static IEnumerable<string> GetFoldersFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            _ = binaryReader.ReadBoolean();
            _ = binaryReader.ReadString();
            _ = binaryReader.ReadStrings();
            var folders = binaryReader.ReadStrings();
            return folders;
        }
        
        public static byte[] GetIvFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            _ = binaryReader.ReadBoolean();
            _ = binaryReader.ReadString();
            _ = binaryReader.ReadStrings();
            _ = binaryReader.ReadStrings();
            var length = binaryReader.ReadInt32();
            var iv = binaryReader.ReadBytes(length);
            return iv;
        }

        
        #endregion
        
        #region Cryptography

        public static string HashFile(string path){
            //hash file
            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            var hashBytes = sha.ComputeHash(fs);
            var hash = Convert.ToBase64String(hashBytes);

            return hash;
        }

        public static byte[] HashBytes(byte[] bytes, HashAlgorithm hashAlgorithm) => hashAlgorithm.ComputeHash(bytes);
        public static string HashBytes(byte[] bytes)
        {
            using var sha = SHA512.Create();
            return Convert.ToHexString(sha.ComputeHash(bytes));
        }
        
        public static byte[] CreateKey(string hash, string password) => Convert.FromHexString(RawHash(hash + password));

        /// <summary>
        /// Creates a key based on one or two strings. String -> Byte[] uses UTF8
        /// </summary>
        /// <param name="input">The main input</param>
        /// <param name="salt">The salt used. If <see langword="null"/>, the salt will be a empty array</param>
        /// <returns>The Key derived</returns>
        public static byte[] DeriveKeyFromString(string input, string? salt = null)
        {
            //get input bytes
            byte[] inputbytes = Encoding.UTF8.GetBytes(input);
            byte[] saltbytes;
            if (salt != null) saltbytes = Encoding.UTF8.GetBytes(salt);
            else saltbytes = new byte[16];
            // Generate the hash
            Rfc2898DeriveBytes pbkdf2 = new(inputbytes, saltbytes, iterations: 5000, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(32); //32 bytes length is 256 bits
        }

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
        private static string RawHash(string s){
            //sha256
            var sha256 = SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(s);
            var hash = sha256.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        #endregion
        
    }
}
