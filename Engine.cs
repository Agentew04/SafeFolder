﻿using PerrysNetConsole;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.IO.Compression;
using System.Text.RegularExpressions;

namespace SafeFolder;

public class Engine {
    private const int KeySize = 256;
    private const int BlockSize = 128;
    private const PaddingMode PaddingMode = System.Security.Cryptography.PaddingMode.PKCS7;
    private const CipherMode CipherMode = System.Security.Cryptography.CipherMode.CBC;
    
    private static readonly string _safeFolderName = Process.GetCurrentProcess().ProcessName;

    private readonly string _folderPath;
    private readonly Progress? _progress;
    private readonly Stopwatch _clock = new();
    private readonly List<Regex> _blacklist = new();
    private readonly bool _useRam;
    private readonly bool _clearTraces;

    public TimeSpan Elapsed => _clock.Elapsed; 
    
    # region Constructor

    public Engine(EngineConfiguration configuration) {
        _folderPath = configuration.FolderPath;
        _progress = configuration.ProgressBar;
        _useRam = configuration.UseRam;
        _clearTraces = configuration.ClearTraces;

        if (string.IsNullOrWhiteSpace(configuration.Blacklist)) 
            return;
        string[] regexes = configuration.Blacklist.Split(';');
        foreach (string regex in regexes) {
            _blacklist.Add(new Regex(regex + "$"));
        }
    }
    
    #endregion

    /// <summary>
    /// Returns a built header. Must set <see cref="Header.Hash"/> and <see cref="Header.Name"/>.
    /// </summary>
    /// <returns></returns>
    private static (Header,string) GenerateHeader(bool isFolder) {
        byte[] iv = Utils.GenerateIv();
        Guid guid = Guid.NewGuid();
        string encFile = guid.ToString().Replace("-", "") + ".enc";
        Header header = new Header{
            IsFolder = isFolder,
            Guid = guid,
            IvLength = iv.Length,
            Iv = iv
        };
        return (header, encFile);
    }

    #region Files

    private static void PackSingleFile(byte[] key, string pwdHash, string file) {

        (Header header, string encFile) = GenerateHeader(false);
        header.Hash = pwdHash;
        header.Name = file;

        #region stream init
        using var outStream = File.Create(encFile);
        using var inStream = File.OpenRead(file);
        using var bw = new BinaryWriter(outStream);
        bw.Write(header, key);
        #endregion

        #region cryptography
        using var aes = Aes.Create();
        aes.KeySize = KeySize;
        aes.BlockSize = BlockSize;
        aes.Padding = PaddingMode;
        aes.Mode = CipherMode;
        aes.Key = key;
        aes.IV = header.Iv;
        
        using var cryptoStream = new CryptoStream(outStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
        Span<byte> buffer = stackalloc byte[1024];
        int bytesRead;
        while ( (bytesRead= inStream.Read(buffer)) > 0) {
            cryptoStream.Write(buffer[..bytesRead]);
        }

        #endregion
    }
    private void PackSingleFolder(byte[] key, string pwdHash, string folder) {
        if (_useRam){
            DirectoryInfo dirInfo = new(folder);
            using MemoryStream ms = new();
            using Ionic.Zip.ZipFile zip = new(encoding: System.Text.Encoding.UTF8);

            zip.AddDirectory(folder, dirInfo.Name);
            zip.Save(ms);
            ms.Seek(0, SeekOrigin.Begin);
            
            (Header header, string encFile) = GenerateHeader(true);
            header.Hash = pwdHash;
            header.Name = dirInfo.Name;
            
            #region stream init
            using var outStream = File.Create(encFile);
            using var bw = new BinaryWriter(outStream);
            bw.Write(header, key);
            #endregion

            #region cryptography
            using var aes = Aes.Create();
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;
            aes.Padding = PaddingMode;
            aes.Mode = CipherMode;
            aes.Key = key;
            aes.IV = header.Iv;
            
            using CryptoStream cryptoStream = new(outStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            Span<byte> buffer = stackalloc byte[1024];
            int bytesRead;
            while (( bytesRead= ms.Read(buffer) ) > 0)
            {
                cryptoStream.Write(buffer[..bytesRead]);
            }

            #endregion
        }else{
            var dirInfo = new DirectoryInfo(folder);
            var zipName = $"./{dirInfo.Name}.zip";
            ZipFile.CreateFromDirectory(dirInfo.FullName, zipName, CompressionLevel.Fastest, true);

            var iv = Utils.GenerateIv();
            var guid = Guid.NewGuid();
            var encFile = guid.ToString().Replace("-", "") + ".enc";
            var header = new Header{
                IsFolder = true,
                Guid = guid,
                Hash = pwdHash,
                Name = dirInfo.Name,
                IvLength = iv.Length,
                Iv = iv
            };

            using var outStream = File.Create(encFile);
            using var inStream = File.OpenRead(zipName);
            using var bw = new BinaryWriter(outStream);

            bw.Write(header, key);

            using var aes = Aes.Create();
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;
            aes.Padding = PaddingMode;
            aes.Mode = CipherMode;
            aes.Key = key;
            aes.IV = iv;
            
            using var cryptoStream = new CryptoStream(outStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            Span<byte> buffer = stackalloc byte[1024];
            int bytesRead;
            while ( (bytesRead= inStream.Read(buffer)) > 0)
            {
                cryptoStream.Write(buffer[..bytesRead]);
            }
        }
    }

    private static double PercentPerItem(int totalItems) {
        if (totalItems <= 0) {
            return 1;
        }
        return 100 / (double)totalItems;

    }
    
    #pragma warning disable CS8602
    public async Task PackFiles(byte[] key, string pwdHash) {
        _clock.Restart();
        bool verbose = _progress is not null;
        List<string> files = Directory.EnumerateFiles(_folderPath)
            .Where(f => !Path.GetFileName(f).Contains(_safeFolderName)) // is not executable
            .Where(f => !f.EndsWith(".enc"))
#if DEBUG
            .Where(f => !(f.EndsWith(".pdb"))
#endif
            .Where(file => !_blacklist.Any(regex => regex.Match(file).Success))
            .ToList();
        
        List<string> folders = Directory.GetDirectories(_folderPath)
            .Where(folder => !_blacklist.Any(regex => regex.Match(folder).Success))
            .ToList();

        double progressPerItem = PercentPerItem(files.Count + folders.Count);

        // encrypt files
        await Parallel.ForEachAsync(files, (file, _) =>
        {
            try{
                PackSingleFile(key, pwdHash, Path.GetFileName(file));
                _progress?.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(file)} encrypted successfully");
                Utils.WipePath(file, _clearTraces);
                if(verbose) _progress.Percentage += progressPerItem;
            }catch (Exception e) {
                _progress?.Message(Message.LEVEL.ERROR, $"{e.Message}");
                _progress?.Stop();
                Console.WriteLine(e);
            }

            return ValueTask.CompletedTask;
        });

        // encrypt folders
        await Parallel.ForEachAsync(folders, (folder, _) =>
        {
            try{
                PackSingleFolder(key, pwdHash, Path.GetFileName(folder));
                _progress?.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(folder)} encrypted successfully");
                Utils.WipePath(folder, _clearTraces);
                Utils.WipePath($"{folder}.zip", _clearTraces);
                if(_progress is not null)
                    _progress.Percentage += progressPerItem;
            }catch (Exception e)
            {
                _progress?.Message(Message.LEVEL.ERROR, $"{e.Message}");
                _progress?.Stop();
                Console.WriteLine(e);
            }

            return ValueTask.CompletedTask;
        });
        _clock.Stop();
    }

    private void UnpackSingleFile(Header header, byte[] key, Stream dataStream) {
        using FileStream outStream = File.Create(header.Name);
        using Aes aes = Aes.Create();
        aes.KeySize = KeySize;
        aes.BlockSize = BlockSize;
        aes.Padding = PaddingMode;
        aes.Mode = CipherMode;
        aes.Key = key;
        aes.IV = header.Iv;

        using CryptoStream cryptoStream = new(dataStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
        Span<byte> buffer = stackalloc byte[1024];
        int bytesRead;
        while ((bytesRead = cryptoStream.Read(buffer)) > 0)
            outStream.Write(buffer[..bytesRead]);

        dataStream.Close();
    }

    private void UnpackSingleFolder(Header header, byte[] key, Stream dataStream) {
        Stream outStream;
        if (_useRam)
            outStream = new MemoryStream();
        else
            outStream = File.Create($"{header.Name}.zip");
        using Aes aes = Aes.Create();
        aes.KeySize = KeySize;
        aes.BlockSize = BlockSize;
        aes.Padding = PaddingMode;
        aes.Mode = CipherMode;
        aes.Key = key;
        aes.IV = header.Iv;

        using CryptoStream cryptoStream = new(dataStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
        Span<byte> buffer = stackalloc byte[1024];
        int bytesRead;
        while ((bytesRead = cryptoStream.Read(buffer)) > 0)
            outStream.Write(buffer[..bytesRead]);

        if (_useRam) {
            outStream.Seek(0, SeekOrigin.Begin);
            using Ionic.Zip.ZipFile? zip = Ionic.Zip.ZipFile.Read(outStream);
            zip.ExtractAll(_folderPath , Ionic.Zip.ExtractExistingFileAction.OverwriteSilently);
        }else {
            dataStream.Close();
            outStream.Close();
            ZipFile.ExtractToDirectory($"{header.Name}.zip", "./");
            Utils.WipePath($"{header.Name}.zip", _clearTraces);
        }
    }
    
    private void UnpackObject(byte[] key, string file) {
        #region header
        Guid guidFileName = Guid.Parse(Path.GetFileName(file).Replace(".enc", ""));
        using FileStream inStream = new(file, FileMode.Open, FileAccess.Read);
        using BinaryReader br = new(inStream);
        Header header = br.ReadHeader(key);
        if(header.Guid != guidFileName || !Utils.CheckHash(Utils.HashBytes(key), header.Hash))
        {
            _progress?.Message(Message.LEVEL.WARN, $"Wrong password or file corrupted ({Path.GetFileName(file)})");
            return;
        }

        #endregion

        #region criptography
        
        if (!header.IsFolder) {
            UnpackSingleFile(header, key, inStream);
        }else {
            UnpackSingleFolder(header, key, inStream);
        }
        File.Delete(file);
        _progress?.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(file)} decrypted successfully");
        
        #endregion
    }

    public async Task UnpackFiles(byte[] key, string pwdHash) {
        _clock.Restart();
        List<string> files = Directory.EnumerateFiles(_folderPath)
            .Where(f => f.EndsWith(".enc")).ToList();

        double progress = 100.0 / (!files.Any() ? 100 : files.Count );

        // decrypt files and folders
        await Parallel.ForEachAsync(files, (file, _) =>
        {
            try{
                UnpackObject(key, file);
                if(_progress is not null)
                    _progress.Percentage += progress;
            }catch (Exception e)
            {
                _progress?.Message(Message.LEVEL.ERROR, $"{e.Message}");
                _progress?.Stop();
                Console.WriteLine(e);
            }

            return ValueTask.CompletedTask;
        });
        _clock.Stop();
    }
    
    #endregion

}