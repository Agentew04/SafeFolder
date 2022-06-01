using PerrysNetConsole;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace SafeFolder;

public static class Program
{
    private static async Task Main()
    {   
        Utils.ShowSplashScreen();
        Prompt prompt = new Prompt()
            {
                AllowEmpty = false,
                Prefix = "Choose your choice",
                ValidateChoices = true,
                ChoicesText = new () {
                    { "1", "Encrypt Files" },
                    { "2", "Encrypt Files and Clear Traces (Very Slow)"},
                    { "3", "Decrypt Files" },
                    { "4", "Info about program" }
                }
            };

        var state = prompt.DoPrompt();
        var stopWatch = new Stopwatch();
        Progress prog = new Progress();

        var pwd = Utils.GetPasswordInput("Enter password: ");
        var pwd2 = Utils.GetPasswordInput("Re-Enter password: ");
        if (pwd != pwd2) throw new Exception("Passwords do not match");

        var key = Utils.DeriveKeyFromString(pwd);
        var pwdHash = Utils.GetHash(Utils.HashBytes(key));
        if (state == "1"){
            // have to encrypt
            prog.Start();
            prog.Message(Message.LEVEL.INFO, "Encrypting files...");
            stopWatch.Start();
            await Engine.PackFiles(key, pwdHash, prog);
        }else if (state == "2"){
            // have to encrypt
            prog.Start();
            prog.Message(Message.LEVEL.INFO, "Encrypting files...");
            stopWatch.Start();
            await Engine.PackFiles(key, pwdHash, prog);
        }else if (state == "3"){
            // have to decrypt
            prog.Start();
            prog.Message(Message.LEVEL.INFO, "Decrypting files...");
            stopWatch.Start();
            await Engine.UnpackFiles(key, pwdHash, prog);
        }else if (state == "4"){
            Utils.WriteLine("SafeFolder");
        }
        stopWatch.Stop();
        var ms = (stopWatch.Elapsed.Milliseconds).ToString("D3");
        var s = (stopWatch.Elapsed.Seconds).ToString("D2");
        var m = (stopWatch.Elapsed.Minutes).ToString("D2");

        // Utils.WriteLine($"Done in {m}:{s}:{ms}!", ConsoleColor.Green);
        prog.Message(Message.LEVEL.SUCCESS, $"Done in {m}:{s}:{ms}!");
        prog.Update(100);
        prog.Stop();
        CoEx.WriteLine();
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }
}