using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace SafeFolder
{
    public static class Utils{

        #region IO

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

        public static void ShowSplashScreen()
        {
            Console.WriteLine(@"
=============================================

            Welcome to SafeFolder
                   v0.1.0

=============================================
");
        }
        
        public static void ShowCorrupt()
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
            Thread.Sleep(5000);
        }
        
        #endregion

        #region Binary

        public static void Write(this BinaryWriter stream, IEnumerable<string> strings)
        {
            // Write the number of strings
            stream.Write(strings.Count());
            
            // Write each string
            foreach (var str in strings)
            {
                stream.Write(str);
            }
        }

        public static IEnumerable<string> ReadStrings(this BinaryReader stream)
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

        #endregion

        #region  safeFile
        
        private static readonly string _currentPath = Environment.CurrentDirectory;
        private static readonly string _safeFilePath = $"{_currentPath}\\.safe";
        
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
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            _ = binaryReader.ReadBoolean();
            var hash = binaryReader.ReadString();
            return hash;
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
            var iv = Utils.GenerateIV();

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
        
        public static byte[] GetIVFromSafeFile()
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
            string hash = "";
            using(FileStream fs = File.OpenRead(path)){
                using(SHA256 sha = SHA256.Create()){
                    byte[] hashbytes = sha.ComputeHash(fs);
                    hash = Convert.ToBase64String(hashbytes);
                }
            }
            return hash;
        }
        
        public static byte[] CreateKey(string hash, string password) => Convert.FromHexString(RawHash(hash + password));

        public static byte[] GenerateIV()
        {
            //generate random IV
            using var aes = Aes.Create();
            return aes.IV;
        }

        public static string GetHash(string str){
            return BCrypt.Net.BCrypt.HashPassword(str);
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
