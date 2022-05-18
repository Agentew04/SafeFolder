using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SafeFolder;

public class Program
{
    private static void Main(string[] args)
    {   
        // get if .safe file is installed
        if (!Installer.IsInstalled())
        {
            Console.WriteLine("SafeFolder is not installed. Installing now.");
            Installer.Install();
        }
        Utils.ShowSplashScreen();
            
        var pwd = Utils.GetPasswordInput("Enter password: ");

        var hashFile = Utils.GetHashFromSafeFile();
        if (string.IsNullOrWhiteSpace(hashFile))
        {
            Utils.ShowCorrupt();
            return;
        }
            
        var pwdHash = Utils.GetHash(pwd);
        var finalHash = Utils.GetHash(pwdHash + pwd);
            
        var isValid = finalHash == hashFile;
        if(!isValid){
            Console.WriteLine("Wrong password.");
            var maxTry = 2; // 3 but user already used once
            var tryCount = 0;
            while (tryCount < maxTry)
            {
                pwd = Utils.GetPasswordInput("Enter password: ");
                pwdHash = Utils.GetHash(pwd);
                finalHash = Utils.GetHash(pwdHash + pwd);
                isValid = finalHash == hashFile;
                if (isValid) break;
                tryCount++;
            }
        }
            
        if (!isValid)
        {
            Utils.ShowCorrupt();
            return;
        }
            
        // here we go
        //from here, the password is correct

        var state = Utils.GetStateFromSafeFile();
        var key = Utils.CreateKey(hashFile, pwd);
        if (!state)
        {
            // have to encrypt
            Console.WriteLine("Encrypting files...");
            Utils.SetFilesToSafeFile();
            Engine.PackFiles(key);
            Engine.PackFolders(key);
            Utils.SetStateToSafeFile(true); 
        }
        else
        {
            // have to decrypt
            Console.WriteLine("Decrypting files...");
            Engine.UnpackFiles(key);
            Engine.UnpackFolders(key);
            Utils.SetStateToSafeFile(false);
        }
        Console.WriteLine("Done!");
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }
}