using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
        
        public static byte[] CreateKey(string hash, string password) => Convert.FromHexString(RawHash(hash + password));

        public static byte[] GenerateIv()
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
