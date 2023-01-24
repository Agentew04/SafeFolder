using PerrysNetConsole;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Prompt = Sharprompt.Prompt;

namespace SafeFolder;

public static class Program
{
    private struct ProgramOptions {
        public string FolderPath { get; init; }
        public bool HelpRequested { get; init; }
        public bool VersionRequested { get; init; }
        public bool InMemory { get; init; }
        public bool ClearTraces { get; init; }
        public bool Encrypt { get; init; }
        public bool Decrypt { get; init; }
        public string? Password { get; init; }
        public int Verbosity { get; init; }
    }

    private static Dictionary<string, Flag> flags = new() {
        { "nogui", new Flag("nogui", "n") },
        { "help", new Flag("help", "h") },
        { "version", new Flag("version", "v") },
        { "memory", new Flag("inmemory", "m") },
        { "clear", new Flag("cleartraces", "c") },
        { "encrypt", new Flag("encrypt", "e") },
        { "decrypt", new Flag("decrypt", "d") },
        { "password", new Flag("password", "p", true) },
        { "verbosity", new Flag("verbosity", "V", true) }
    };
    
    private static async Task Main(string[] args) {
        bool isNoGui = Flag.HasFlag(args, flags["nogui"]);
        bool helpRequested = Flag.HasFlag(args, flags["help"]);
        bool versionRequested = Flag.HasFlag(args, flags["version"]);
        bool inMemory = Flag.HasFlag(args, flags["memory"]);
        bool clearTraces = Flag.HasFlag(args, flags["clear"]);
        bool encrypt = Flag.HasFlag(args, flags["encrypt"]);
        bool decrypt = Flag.HasFlag(args, flags["decrypt"]);

        bool pwdIncluded = Flag.TryGetFlagValue(args, flags["password"], out string password);
        bool verbIncluded = Flag.TryGetFlagValue(args, flags["verbosity"], out string verbosity);

        var strays = Flag.GetStrayArgs(args, flags.Values);
        string folderPath = strays.Count > 0 ? 
            strays.ElementAt(0) : 
            Directory.GetCurrentDirectory(); 
        

        // pack flags information on one struct
        ProgramOptions opt = new() {
            FolderPath = folderPath,
            HelpRequested = helpRequested,
            VersionRequested = versionRequested,
            InMemory = inMemory,
            ClearTraces = clearTraces,
            Encrypt = encrypt,
            Decrypt = decrypt,
            Password = pwdIncluded ? password : null,
            Verbosity = !verbIncluded ? 0 : int.Parse(verbosity)
        };
        

        if (isNoGui || helpRequested || versionRequested)
            await StartCli(opt);
        else
            await StartInteractive();
    }

    private static async Task StartInteractive() {
        var method = false;
        var traces = false;
        
        Utils.ShowSplashScreen();

        string? state = Prompt.Select("What do you want", new[] { "Encrypt Files", "Decrypt Files", "Info about program" });
        switch (state)
        {
            case "Info about program":
                Utils.WriteLine("SafeFolder\n");
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
        if (pwd != pwd2) 
            throw new Exception("Passwords do not match");

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

        prog.Message(Message.LEVEL.SUCCESS, $"Done in {m}:{s}:{ms}!");
        prog.Update(100);
        prog.Stop();
        CoEx.WriteLine();
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }
    
    private static async Task<bool> StartCli(ProgramOptions opt) {
        if (opt.HelpRequested) {
            Utils.ShowInfoScreen();
            return true;
        }
        
        if (opt.VersionRequested) {
            string version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "Unknown";
            Utils.WriteLine($"Current SafeFolder version: {version}", version == "Unknown" ? ConsoleColor.Red : ConsoleColor.Green);
            return true;
        }
        
        switch (opt) {
            case { Decrypt: false, Encrypt: false }:
                Utils.WriteLine("You must specify either --encrypt(-e) or --decrypt(-d)", ConsoleColor.Red);
                return false;
            case { Decrypt: true, Encrypt: true }:
                Utils.WriteLine("You can't specify both --encrypt(-e) and --decrypt(-d)", ConsoleColor.Red);
                return false;
        }

        if(opt.Password == null) {
            Utils.WriteLine("You must specify a password using '--password <PASSWORD>' or '-p <PASSWORD>'", ConsoleColor.Red);
            return false;
        }
        
        if(opt.Password.Length < 4) {
            Utils.WriteLine("Password must be at least 4 characters long", ConsoleColor.Red);
            return false;
        }
        
        bool verbose = opt.Verbosity > 0;
        Stopwatch stopWatch = new();
        stopWatch.Start();
        
        byte[] key = Utils.DeriveKeyFromString(opt.Password);
        string pwdHash = Utils.GetHash(Utils.HashBytes(key));
        
        Directory.SetCurrentDirectory(opt.FolderPath);
        
        if(verbose)
            Utils.WriteLine($"{(opt.Encrypt ? "Encrypting" : "Decrypting")} files now");
        if (opt.Encrypt) {
            await Engine.PackFiles(key, pwdHash, null, opt.InMemory, opt.ClearTraces);
        }else {
            await Engine.UnpackFiles(key, pwdHash, null, opt.InMemory, opt.ClearTraces);
        }

        stopWatch.Stop();
        var ms = stopWatch.Elapsed.Milliseconds.ToString("D3");
        var s = stopWatch.Elapsed.Seconds.ToString("D2");
        var m = stopWatch.Elapsed.Minutes.ToString("D2");
        if (verbose) 
            Utils.WriteLine($"Done in {m}:{s}:{ms}!");
        return true;
    }
}