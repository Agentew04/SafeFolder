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
        private static readonly string _safeFilePath = $"{_currentPath}/.safe";
        public static bool IsInstalled() => File.Exists(_safeFilePath);

        public static bool Install()
        {
            // delete old safe
            if (File.Exists(_safeFilePath)) File.Delete(_safeFilePath);
            // file will be binary
            using var binaryWriter = new BinaryWriter(File.Open(_safeFilePath, FileMode.Create));

            // prompt for password
            var pwd = Utils.GetPasswordInput("Enter password: ");
            var rePwd = Utils.GetPasswordInput("Re-enter password: ");
            
            if (pwd != rePwd)
            {
                Utils.WriteLine("Passwords do not match, exiting", ConsoleColor.Red);
                return false;
            }

            var pwdHash = Utils.GetHash(pwd);
            // var finalHash = Utils.GetHash(pwdHash + pwd);
            
            // write current state
            binaryWriter.Write(false);
            
            // write finalHash to safeFile
            binaryWriter.Write(pwdHash);

            var files = GetFiles();
            var folders = GetFolders();
            
            binaryWriter.Write(files);
            binaryWriter.Write(folders);

            var iv = Utils.GenerateIv();
            binaryWriter.Write(iv.Length);
            binaryWriter.Write(iv);

            File.SetAttributes(_safeFilePath, FileAttributes.Hidden);

            Console.WriteLine("Safe Folder Installed!");
            return true;
        }

        public static IEnumerable<string> GetFiles() => Directory.GetFiles(_currentPath)
            .Where(f => !f.EndsWith(".safe") && !f.EndsWith(_safeFolderName) && !f.EndsWith($"{_safeFolderName}.exe"));

        public static IEnumerable<string> GetFolders() => Directory.GetDirectories(_currentPath);
    }
}