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
        public string? BlacklistFiles { get; init; }
        public bool HelpRequested { get; init; }
        public bool VersionRequested { get; init; }
        public bool InMemory { get; init; }
        public bool ClearTraces { get; init; }
        public bool Encrypt { get; init; }
        public bool Decrypt { get; init; }
        public string? Password { get; init; }
        public bool Verbose { get; init; }
    }

    private static readonly Dictionary<string, Flag> _flags = new() {
        { "nogui", new Flag("nogui", "n") },
        { "blacklist", new Flag("blacklist", "b", true) },
        { "help", new Flag("help", "h") },
        { "version", new Flag("version", "v") },
        { "memory", new Flag("inmemory", "m") },
        { "clear", new Flag("cleartraces", "c") },
        { "encrypt", new Flag("encrypt", "e") },
        { "decrypt", new Flag("decrypt", "d") },
        { "password", new Flag("password", "p", true) },
        { "verbosity", new Flag("verbosity", "V") }
    };
    
    private static async Task Main(string[] args) {
        bool isNoGui = Flag.HasFlag(args, _flags["nogui"]);
        bool helpRequested = Flag.HasFlag(args, _flags["help"]);
        bool versionRequested = Flag.HasFlag(args, _flags["version"]);
        bool inMemory = Flag.HasFlag(args, _flags["memory"]);
        bool clearTraces = Flag.HasFlag(args, _flags["clear"]);
        bool encrypt = Flag.HasFlag(args, _flags["encrypt"]);
        bool decrypt = Flag.HasFlag(args, _flags["decrypt"]);
        bool verbose = Flag.HasFlag(args, _flags["verbosity"]);

        bool pwdIncluded = Flag.TryGetFlagValue(args, _flags["password"], out string password);
        bool blacklistIncluded = Flag.TryGetFlagValue(args, _flags["blacklist"], out string blacklist);

        List<string> folderPaths = Flag.GetStrayArgs(args, _flags.Values); 
        if(folderPaths.Count == 0)
            folderPaths.Add(Directory.GetCurrentDirectory());
        
        foreach (string folderPath in folderPaths) {
            // pack flags information on one struct
            ProgramOptions opt = new() {
                FolderPath = folderPath,
                BlacklistFiles = blacklistIncluded ? blacklist : null,
                HelpRequested = helpRequested,
                VersionRequested = versionRequested,
                InMemory = inMemory,
                ClearTraces = clearTraces,
                Encrypt = encrypt,
                Decrypt = decrypt,
                Password = pwdIncluded ? password : null,
                Verbose = verbose
            };


            if (isNoGui || helpRequested || versionRequested)
                await StartCli(opt);
            else
                await StartInteractive();
        }
    }

    private static async Task StartInteractive() {
        var method = false;
        var traces = false;
        
        Utils.ShowSplashScreen();

        string? state = Prompt.Select("What do you want", new[] { "Encrypt Files", 
            "Decrypt Files", 
            "Info about program",
            "Exit"
        });
        switch (state)
        {
            case "Info about program":
                Utils.WriteLine("SafeFolder\n");
                Utils.ShowInfoScreen();
                Console.WriteLine("Press any key to close the program.");
                Console.ReadKey();
                return;
            case "Exit":
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

        Progress progressBar = new();

        string? pwd = Prompt.Password("Enter password", placeholder: "Take Care With CAPS-LOCK", validators: new[] { Sharprompt.Validators.Required(), Sharprompt.Validators.MinLength(4) });
        string? pwd2 = Prompt.Password("Re-Enter password", placeholder: "Take Care With CAPS-LOCK", validators: new[] { Sharprompt.Validators.Required(), Sharprompt.Validators.MinLength(4) });
        if (pwd != pwd2) 
            throw new Exception("Passwords do not match");

        var key = Utils.DeriveKeyFromString(pwd);
        var pwdHash = Utils.GetHash(Utils.HashBytes(key));
        
        Engine engine = new(new EngineConfiguration {
            ProgressBar = progressBar
        });
        
        switch (state) {
            case "Encrypt Files":
                // have to encrypt
                progressBar.Start();
                progressBar.Message(Message.LEVEL.INFO, "Encrypting files...");
                await engine.PackFiles(key, pwdHash, method, traces);
                break;
            case "Decrypt Files":
                // have to decrypt
                progressBar.Start();
                progressBar.Message(Message.LEVEL.INFO, "Decrypting files...");
                await engine.UnpackFiles(key, pwdHash, method, traces);
                break;
        }
        
        progressBar.Message(Message.LEVEL.SUCCESS, $"Done in {engine.Elapsed:mm\\:ss\\:fff}!");
        progressBar.Update(100);
        progressBar.Stop();
        CoEx.WriteLine();
        Console.WriteLine("Press any key to close the program.");
        Console.ReadKey();
    }

    private static bool CheckForInputError(ProgramOptions opt) {
        switch (opt) {
            case { Decrypt: false, Encrypt: false }:
                Utils.WriteLine("You must specify either --encrypt(-e) or --decrypt(-d)", ConsoleColor.Red);
                return true;
            case { Decrypt: true, Encrypt: true }:
                Utils.WriteLine("You can't specify both --encrypt(-e) and --decrypt(-d)", ConsoleColor.Red);
                return true;
        }
        
        if(opt.Password == null) {
            Utils.WriteLine("You must specify a password using '--password <PASSWORD>' or '-p <PASSWORD>'", ConsoleColor.Red);
            return true;
        }

        if (opt.Password.Length >= 4) return false;
        Utils.WriteLine("Password must be at least 4 characters long", ConsoleColor.Red);
        return true;

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

        bool error = CheckForInputError(opt); // returns true on error, false on success
        if (error) 
            return false;

        byte[] key = Utils.DeriveKeyFromString(opt.Password!);
        string pwdHash = Utils.GetHash(Utils.HashBytes(key));
        
        Directory.SetCurrentDirectory(opt.FolderPath);

        Engine engine = new(new EngineConfiguration {
            ProgressBar = null,
            FolderPath = opt.FolderPath,
            Blacklist = opt.BlacklistFiles ?? ""
        });
        
        if(opt.Verbose)
            Utils.WriteLine($"{(opt.Encrypt ? "Encrypting" : "Decrypting")} files now");
        
        if (opt.Encrypt) {
            await engine.PackFiles(key, pwdHash, opt.InMemory, opt.ClearTraces);
        }else {
            await engine.UnpackFiles(key, pwdHash, opt.InMemory, opt.ClearTraces);
        }

        
        if (opt.Verbose) 
            Utils.WriteLine($"Done in {engine.Elapsed:mm\\:ss\\:fff}!");
        return true;
    }
    
    
}