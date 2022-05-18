using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Diagnostics;

namespace SafeFolder
{
    public static class Installer{
        
        private static readonly string _currentPath = Environment.CurrentDirectory;
        private static readonly string _safeFolderName = Process.GetCurrentProcess().ProcessName;
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

            File.SetAttributes(_safeFilePath, FileAttributes.Hidden);

            Console.WriteLine("Safe Folder Installed!");
        }

        public static IEnumerable<string> GetFiles() => Directory.GetFiles(_currentPath)
            .Where(f => !f.EndsWith(".safe") && !f.EndsWith($"{_safeFolderName}.exe"));

        public static IEnumerable<string> GetFolders() => Directory.GetDirectories(_currentPath);
    }
}