using PerrysNetConsole;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Prompt = Sharprompt.Prompt;

namespace SafeFolder;

public static class Program
{
    private static async Task Main()
    {   
        var method = false;
        var traces = false;

        Utils.ShowSplashScreen();

        var state = Prompt.Select("What do you want", new[] { "Encrypt Files", "Decrypt Files", "Info about program" });
        switch (state)
        {
            case "Info about program":
                Utils.WriteLine("SafeFolder alpha version\n");
                Utils.ShowInfoScreen();
                Console.WriteLine("Press any key to close the program.");
                Console.ReadKey();
                return;
            case "Encrypt Files":
                method = Prompt.Confirm("Encrypt files in memory? (Fast, but demands more ram)");
                traces = Prompt.Confirm("Clear traces? (Very Slow, but more secure)");
                break;
            case "Decrypt Files":
                method = Prompt.Confirm("Decrypt files in memory? (Fast, but demands more ram)");
                traces = Prompt.Confirm("Clear traces? (Very Slow, but more secure)");
                break;
        }

        var stopWatch = new Stopwatch();
        var prog = new Progress();

        var pwd = Prompt.Password("Enter password", placeholder: "Take Care With CAPS-LOCK", validators: new[] { Sharprompt.Validators.Required(), Sharprompt.Validators.MinLength(4) });
        var pwd2 = Prompt.Password("Re-Enter password", placeholder: "Take Care With CAPS-LOCK", validators: new[] { Sharprompt.Validators.Required(), Sharprompt.Validators.MinLength(4) });
        if (pwd != pwd2) throw new Exception("Passwords do not match");

        var key = Utils.DeriveKeyFromString(pwd);
        var pwdHash = Utils.GetHash(Utils.HashBytes(key));
        switch (state)
        {
            case "Encrypt Files":
                // have to encrypt
                prog.Start();
                prog.Message(Message.LEVEL.INFO, "Encrypting files...");
                stopWatch.Start();
                await Engine.PackFiles(key, pwdHash, prog, method, traces);
                break;
            case "Decrypt Files":
                // have to decrypt
                prog.Start();
                prog.Message(Message.LEVEL.INFO, "Decrypting files...");
                stopWatch.Start();
                await Engine.UnpackFiles(key, pwdHash, prog, method, traces);
                break;
        }

        stopWatch.Stop();
        var ms = stopWatch.Elapsed.Milliseconds.ToString("D3");
        var s = stopWatch.Elapsed.Seconds.ToString("D2");
        var m = stopWatch.Elapsed.Minutes.ToString("D2");

        // Utils.WriteLine($"Done in {m}:{s}:{ms}!", ConsoleColor.Green);
        prog.Message(Message.LEVEL.SUCCESS, $"Done in {m}:{s}:{ms}!");
        prog.Update(100);
        prog.Stop();
        CoEx.WriteLine();
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }
}