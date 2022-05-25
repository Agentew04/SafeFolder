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

    private static async Task PackSingleFile(byte[] key, string pwdHash, string file)
    {
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
        // write header to a stream
        using var ms = new MemoryStream();
        await using var bw = new BinaryWriter(ms);
        bw.Write(header);
        ms.Seek(0, SeekOrigin.Begin);

            
        await using var fs = new FileStream(file, FileMode.Open, FileAccess.Read);
        using var outStream = Encryptor.AesStreamEncrypt(fs, key, iv);

        await using var outFs = File.Create(encFile);
        await ms.CopyToAsync(outFs);
        await outStream.CopyToAsync(outFs);

        fs.Close();
        try {File.Delete(file);} catch (Exception){ }
    }
    
    public static async Task PackFiles(byte[] key, string pwdHash)
    {
        var files = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => !f.EndsWith(_safeFolderName) && !f.EndsWith($"{_safeFolderName}.exe")
                             && !f.EndsWith(".safe"));
        await Parallel.ForEachAsync(files, async (f, _) => await PackSingleFile(key, pwdHash, f));
    }

    private static /*async Task*/ void UnpackSingleFile(byte[] key, string pwdHash, string file)
    {
        // get header, decrypt, delete encrypted file
        var fileInfo = new FileInfo(file);
        var guidFileName = Guid.Parse(fileInfo.Name.Replace(".enc", ""));
        /*await*/ using var fs = new FileStream(file, FileMode.Open, FileAccess.Read);
        using var br = new BinaryReader(fs);
        var header = br.ReadHeader();
        if(header.Guid != guidFileName || header.Hash != pwdHash)
        {
            Utils.WriteLine($"Wrong password or file corrupted ({fileInfo.Name})", ConsoleColor.Red);
            return;
        }
        var iv = header.Iv;
        var decryptedFileName = header.Name;
        
        using var decStream = Encryptor.AesStreamDecrypt(fs, key, iv);
        /*await*/ using var decFs = File.Create(decryptedFileName);
        
        /*await*/ decStream.CopyToAsync(decFs);
        fs.Close();
        File.Delete(file);
    }

    public static /*async Task*/ void UnpackFiles(byte[] key, string pwdHash)
    {
        var files = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => f.EndsWith(".enc"));

        foreach (var file in files)
        {
            /*await*/ UnpackSingleFile(key,pwdHash, file);
        }
        //await Parallel.ForEachAsync(files, async (f, _) => await UnpackSingleFile(key, pwdHash, f));
    }
    #endregion
}