using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SafeFolder;

public static class Engine
{
    private const int _keySize = 256;
    private const int _blockSize = 128;
    private const PaddingMode _paddingMode = PaddingMode.PKCS7;
    private const CipherMode _cipherMode = CipherMode.CBC;
    
    private static readonly string _safeFolderName = Process.GetCurrentProcess().ProcessName;
    
    // TODO fix this folders
    #region Folders

    public static async Task PackFolders(byte[] key)
    {
        // for each folder, compress, encrypt, delete folder
        var folders = Utils.GetFoldersFromSafeFile();
        var taskList = new List<Task>();

        foreach (var folder in folders)
        {
            taskList.Add(Task.Run(() =>
            {
                var dirInfo = new DirectoryInfo(folder);
                var zipName = $"./{dirInfo.Name}.zip";
                ZipFile.CreateFromDirectory(dirInfo.FullName, zipName, CompressionLevel.Fastest, false);
                //Encryptor.AesStreamEncrypt(zipName, zipName + ".enc", key, Utils.GetIvFromSafeFile());
                File.Delete(zipName);
                Directory.Delete(folder, true);
            }));
        }
        var whenAllTask = Task.WhenAll(taskList);
        try{
            await whenAllTask;
        }
        catch{
            whenAllTask.Exception.InnerExceptions.ToList()
                .ForEach(e => Utils.WriteLine(e.Message, ConsoleColor.Red));
        }
    }
    
    public static async Task UnpackFolders(byte[] key)
    {
        // for each folder, decrypt, decompress and delete zip
        var folders = Utils.GetFoldersFromSafeFile();
        var taskList = new List<Task>();

        foreach (var folder in folders)
        {
            taskList.Add(Task.Run(() =>
            {
                var dirInfo = new DirectoryInfo(folder);
                var zipName = $"./{dirInfo.Name}.zip";
                var zipEncName = $"./{dirInfo.Name}.zip.enc";
                //Encryptor.AesStreamDecrypt(zipEncName, zipName, key, Utils.GetIvFromSafeFile());
                ZipFile.ExtractToDirectory(zipName, dirInfo.FullName);
                File.Delete(zipEncName);
                File.Delete(zipName);
            }));
        }

        var whenAllTask = Task.WhenAll(taskList);
        try{
            await whenAllTask;
        }
        catch{
            whenAllTask.Exception.InnerExceptions.ToList()
                .ForEach(e => Utils.WriteLine(e.Message, ConsoleColor.Red));
        }
    }

    #endregion

    #region Files

    private static void PackSingleFile(byte[] key, string pwdHash, string file)
    {
        #region header
        var iv = Utils.GenerateIv();
        var guid = Guid.NewGuid();
        var encFile = guid.ToString().Replace("-", "") + ".enc";
        var header = new Header{
            Guid = guid,
            Hash = pwdHash,
            Name = file,
            IvLength = iv.Length,
            Iv = iv
        };
        #endregion

        #region stream init
        using var outStream = File.Create(encFile);
        using var inStream = File.OpenRead(file);
        using var bw = new BinaryWriter(outStream);
        bw.Write(header);
        #endregion

        #region cryptography
        using var aes = Aes.Create();
        aes.KeySize = _keySize;
        aes.BlockSize = _blockSize;
        aes.Padding = _paddingMode;
        aes.Mode = _cipherMode;
        aes.Key = key;
        aes.IV = iv;
        
        using var cryptoStream = new CryptoStream(outStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
        Span<byte> buffer = stackalloc byte[1024];
        int bytesRead;
        while ( (bytesRead= inStream.Read(buffer)) > 0)
        {
            cryptoStream.Write(buffer[..bytesRead]);
        }

        #endregion
    }
    
    public static async Task PackFiles(byte[] key, string pwdHash)
    {
        var files = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => !f.EndsWith(_safeFolderName) && !f.EndsWith($"{_safeFolderName}.exe")
                             && !f.EndsWith(".pdb") && !f.EndsWith(".safe"));
        foreach (var file in files)
        {
            PackSingleFile(key, pwdHash, Path.GetFileName(file));
            File.Delete(file);
        }
        //await Parallel.ForEachAsync(files, async (f, _) => await PackSingleFile(key, pwdHash, Path.GetFileName(f)));
    }

    private static /*async Task*/ void UnpackSingleFile(byte[] key, string pwdHash, string file, string pwd)
    {
        #region header
        var guidFileName = Guid.Parse(Path.GetFileName(file).Replace(".enc", ""));
        /*await*/ using var inStream = new FileStream(file, FileMode.Open, FileAccess.Read);
        using var br = new BinaryReader(inStream);
        var header = br.ReadHeader();
        if(header.Guid != guidFileName || !Utils.CheckHash(pwd, header.Hash))
        {
            Utils.WriteLine($"Wrong password or file corrupted ({file})", ConsoleColor.Red);
            throw new Exception("Wrong password or file corrupted");
        }
        #endregion

        #region init stream

        /*await*/ using var outStream = File.Create(header.Name);

        #endregion

        #region criptography

        using var aes = Aes.Create();
        aes.KeySize = _keySize;
        aes.BlockSize = _blockSize;
        aes.Padding = _paddingMode;
        aes.Mode = _cipherMode;
        aes.Key = key;
        aes.IV = header.Iv;
            
        using var cryptoStream = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
        Span<byte> buffer = stackalloc byte[1024];
        int bytesRead;
        while ((bytesRead = cryptoStream.Read(buffer)) > 0)
            outStream.Write(buffer[..bytesRead]);
        #endregion
    }

    public static /*async Task*/ void UnpackFiles(byte[] key, string pwdHash, string pwd)
    {
        var files = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => f.EndsWith(".enc"));

        foreach (var file in files)
        {
            /*await*/ UnpackSingleFile(key, pwdHash, file, pwd);
            File.Delete(file);
        }
        //await Parallel.ForEachAsync(files, async (f, _) => await UnpackSingleFile(key, pwdHash, f));
    }
    
    #endregion
}