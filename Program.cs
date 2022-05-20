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
                Utils.WriteLine("SafeFolder installation failed. Exiting.", ConsoleColor.Red);
                return;
            }
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
        var isSuccess = true;
        if (!state)
        {
            // have to encrypt
            Utils.WriteLine("Encrypting files...", ConsoleColor.Green);
            Utils.SetFilesToSafeFile();
            try{
                await Engine.PackFiles(key);
                await Engine.PackFolders(key);
            }
            catch (Exception){
                Utils.WriteLine("Encryption failed. Press any key to close.", ConsoleColor.Red);
                isSuccess = false;
            }

            Utils.SetStateToSafeFile(true); 
        }
        else{
            // have to decrypt
            Utils.WriteLine("Decrypting files...", ConsoleColor.Green);
            try
            {
                await Engine.UnpackFiles(key);
                await Engine.UnpackFolders(key);
            }catch(Exception){
                Utils.WriteLine("Decryption failed. Press any key to close.", ConsoleColor.Red);
                isSuccess = false;
            }

            Utils.SetStateToSafeFile(false);
        }
        stopWatch.Stop();
        var ms = stopWatch.Elapsed.Milliseconds;
        var s = stopWatch.Elapsed.Seconds;
        var m = stopWatch.Elapsed.Minutes;

        if(isSuccess) Utils.WriteLine($"Done in {m}:{s}:{ms}!", ConsoleColor.Green);
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }
}