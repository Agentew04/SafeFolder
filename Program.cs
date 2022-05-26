using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace SafeFolder;

public static class Program
{
    private static async Task Main()
    {   
        Utils.ShowSplashScreen();
        var state = Console.ReadLine();
        var stopWatch = new Stopwatch();

        var pwd = Utils.GetPasswordInput("Enter password: ");
        var pwd2 = Utils.GetPasswordInput("Re-Enter password: ");
        if (pwd != pwd2) throw new Exception("Passwords do not match");
        var pwdHash = Utils.GetHash(pwd);
        // TODO check this
        var key = Utils.DeriveKeyFromString(pwd);
        if (state == "1"){
            // have to encrypt
            stopWatch.Start();
            Utils.WriteLine("Encrypting files...", ConsoleColor.Green);
            await Engine.PackFiles(key, pwdHash);
            // await Engine.PackFolders(key);
        }
        else{
            // have to decrypt
            stopWatch.Start();
            Utils.WriteLine("Decrypting files...", ConsoleColor.Green);
            Engine.UnpackFiles(key, pwdHash, pwd);
            // Engine.UnpackFolders(key);
        }
        stopWatch.Stop();
        var ms = (stopWatch.Elapsed.Milliseconds).ToString("D3");
        var s = (stopWatch.Elapsed.Seconds).ToString("D2");
        var m = (stopWatch.Elapsed.Minutes).ToString("D2");

        Utils.WriteLine($"Done in {m}:{s}:{ms}!", ConsoleColor.Green);
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }
}