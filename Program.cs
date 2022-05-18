using System;
using System.Threading.Tasks;

namespace SafeFolder;

public static class Program
{
    private static async Task Main()
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
            
        var isValid = BCrypt.Net.BCrypt.Verify(pwd, hashFile);
        if(!isValid){
            Console.WriteLine("Wrong password.");
            const int maxTry = 2; // 3 but user already used once
            var tryCount = 0;
            while (tryCount < maxTry)
            {
                pwd = Utils.GetPasswordInput("Enter password: ");
                // pwdHash = Utils.GetHash(pwd);
                // finalHash = Utils.GetHash(pwdHash + pwd);
                isValid = BCrypt.Net.BCrypt.Verify(pwd, hashFile);
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
            await Engine.PackFiles(key);
            await Engine.PackFolders(key);
            Utils.SetStateToSafeFile(true); 
        }
        else
        {
            // have to decrypt
            Console.WriteLine("Decrypting files...");
            await Engine.UnpackFiles(key);
            await Engine.UnpackFolders(key);
            Utils.SetStateToSafeFile(false);
        }
        Console.WriteLine("Done!");
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }
}