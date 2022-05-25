using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace SafeFolder;

public static class Program
{
    private static async Task Main()
    {   
        // get if .safe file is installed
        if (!Installer.IsInstalled())
        {
            Utils.WriteLine("SafeFolder is not installed. Installing now.", ConsoleColor.Yellow);
            var canProceed = Installer.Install();
            if(!canProceed) {
                Utils.WriteLine("SafeFolder installation failed.", ConsoleColor.Red);
                Utils.WriteLine("Press any key to close...", ConsoleColor.Red);
                return;
            }
        }
        var hashFile = Utils.GetHashFromSafeFile();

        if (string.IsNullOrWhiteSpace(hashFile))
        {
            if (!Utils.ShowCorrupt()) return;
            hashFile = Utils.GetHashFromSafeFile();
        }

        Utils.ShowSplashScreen();
        
        var pwd = Utils.GetPasswordInput("Enter password: ");
            
        var isValid = BCrypt.Net.BCrypt.Verify(pwd, hashFile);
        if(!isValid){
            Utils.WriteLine("Invalid password.", ConsoleColor.Red);

            const int maxTry = 2; // 3 but user already used once
            var tryCount = 0;
            while (tryCount < maxTry)
            {
                pwd = Utils.GetPasswordInput("Enter password: ");
                // pwdHash = Utils.GetHash(pwd);
                // finalHash = Utils.GetHash(pwdHash + pwd);
                isValid = BCrypt.Net.BCrypt.Verify(pwd, hashFile);
                if (isValid) break;
                Utils.WriteLine("Invalid password.", ConsoleColor.Red);
                tryCount++;
            }
        }
            
        if (!isValid)
        {
            Utils.WriteLine("Too many invalid password attempts. Press any key to close.", ConsoleColor.Red);
            Console.ReadKey(true);
            return;
        }
            
        // here we go
        //from here, the password is correct
        
        var stopWatch = new Stopwatch();
        stopWatch.Start();

        var state = Utils.GetStateFromSafeFile();
        var key = Utils.CreateKey(hashFile, pwd);
        if (!state)
        {
            // have to encrypt
            Utils.WriteLine("Encrypting files...", ConsoleColor.Green);
            Utils.SetFilesToSafeFile();
            await Engine.PackFiles(key, hashFile);
            await Engine.PackFolders(key);

            Utils.SetStateToSafeFile(true); 
        }
        else{
            // have to decrypt
            Utils.WriteLine("Decrypting files...", ConsoleColor.Green);
            Engine.UnpackFiles(key, hashFile);
            Engine.UnpackFolders(key);

            Utils.SetStateToSafeFile(false);
        }
        stopWatch.Stop();
        var ms = stopWatch.Elapsed.Milliseconds;
        var s = stopWatch.Elapsed.Seconds;
        var m = stopWatch.Elapsed.Minutes;

        Utils.WriteLine($"Done in {m}:{s}:{ms}!", ConsoleColor.Green);
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }
}