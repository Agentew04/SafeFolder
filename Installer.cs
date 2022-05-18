using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SafeFolder
{
    public static class Installer{
        
        private static readonly string _currentPath = Environment.CurrentDirectory;
        private static readonly string _safeFilePath = $"{_currentPath}\\.safe";
        public static bool IsInstalled() => File.Exists(_safeFilePath);

        public static void Install()
        {
            // file will be binary
            using var binaryWriter = new BinaryWriter(File.Open(_safeFilePath, FileMode.Create));

            // prompt for password
            var pwd = Utils.GetPasswordInput("Enter password: ");
            var rePwd = Utils.GetPasswordInput("Re-enter password: ");
            
            if (pwd != rePwd)
            {
                Console.WriteLine("Passwords do not match, exiting");
                return;
            }

            var pwdHash = Utils.GetHash(pwd);
            var finalHash = Utils.GetHash(pwdHash + pwd);
            
            // write current state
            binaryWriter.Write(false);
            
            // write finalHash to safeFile
            binaryWriter.Write(finalHash);

            var files = GetFiles();
            var folders = GetFolders();
            
            binaryWriter.Write(files);
            binaryWriter.Write(folders);

            var iv = Utils.GenerateIV();
            binaryWriter.Write(iv.Length);
            binaryWriter.Write(iv);
            
            Console.WriteLine("Safe Folder Installed!");
        }

        private static IEnumerable<string> GetFiles() => Directory.GetFiles(_currentPath)
            .Where(x=> !x.EndsWith(".safe") || !x.EndsWith(".exe"));

        private static IEnumerable<string> GetFolders() => Directory.GetDirectories(_currentPath);
    }
}