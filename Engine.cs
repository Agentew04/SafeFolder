using PerrysNetConsole;
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
    private static void PackSingleFolder(byte[] key, string pwdHash, string folder)
    {
        var dirInfo = new DirectoryInfo(folder);
        var zipName = $"./{dirInfo.Name}.zip";
        ZipFile.CreateFromDirectory(dirInfo.FullName, zipName, CompressionLevel.Fastest, false);
        
        #region header
        var iv = Utils.GenerateIv();
        var guid = Guid.NewGuid();
        var encFile = guid.ToString().Replace("-", "") + ".enc";
        var header = new Header{
            Guid = guid,
            Hash = pwdHash,
            Name = zipName,
            IvLength = iv.Length,
            Iv = iv
        };
        #endregion

        #region stream init
        using var outStream = File.Create(encFile);
        using var inStream = File.OpenRead(zipName);
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
    
    public static async Task PackFiles(byte[] key, string pwdHash, Progress prog)
    {
        var files = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => !Path.GetFileName(f).Contains(_safeFolderName) && !f.EndsWith(".pdb") && !f.EndsWith(".enc"));

        var folders = Directory.GetDirectories(Directory.GetCurrentDirectory());

        double progress = 100.0/(files.Count() + folders.Count() == 0 ? 100 : files.Count() + folders.Count());

        // foreach (var file in files)
        // {
        //     PackSingleFile(key, pwdHash, Path.GetFileName(file));
        //     File.Delete(file);
        // }

        await Parallel.ForEachAsync(files, async (file, _) => {
            try{
                PackSingleFile(key, pwdHash, Path.GetFileName(file));
                File.Delete(file);
                prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(file)} encrypted successfully");
                prog.Percentage += progress;
            }catch (Exception e)
            {
                prog.Message(Message.LEVEL.ERROR, $"{e.Message}");
                prog.Stop();
                Console.WriteLine(e);
            }
        });

        // foreach (var folder in folders)
        // {
        //     PackSingleFolder(key, pwdHash, Path.GetFileName(folder));
        //     Directory.Delete(folder, true);
        //     File.Delete(Path.GetFileName(folder) + ".zip");
        // }

        await Parallel.ForEachAsync(folders, async (folder, _) => {
            try{
                PackSingleFolder(key, pwdHash, Path.GetFileName(folder));
                Directory.Delete(folder, true);
                File.Delete(Path.GetFileName(folder) + ".zip");
                prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(folder)} encrypted successfully");
                prog.Percentage += progress;
            }catch (Exception e)
            {
                prog.Message(Message.LEVEL.ERROR, $"{e.Message}");
                prog.Stop();
                Console.WriteLine(e);
            }
        });
    }

    private static void UnpackSingleFile(byte[] key, string pwdHash, string file, Progress prog)
    {
        #region header
        var guidFileName = Guid.Parse(Path.GetFileName(file).Replace(".enc", ""));
        /*await*/ using var inStream = new FileStream(file, FileMode.Open, FileAccess.Read);
        using var br = new BinaryReader(inStream);
        var header = br.ReadHeader();
        if(header.Guid != guidFileName || !Utils.CheckHash(Utils.HashBytes(key), header.Hash))
        {
            prog.Message(Message.LEVEL.WARN, $"Wrong password or file corrupted ({Path.GetFileName(file)})");
            // Utils.WriteLine($"Wrong password or file corrupted ({file})", ConsoleColor.Red);
            // throw new Exception("Wrong password or file corrupted");
            return;
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
        inStream.Close();
        File.Delete(file);
    }

    public static async Task UnpackFiles(byte[] key, string pwdHash, Progress prog)
    {
        var files = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => f.EndsWith(".enc"));

        var zips = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => f.EndsWith(".zip"));

        double progress = 100.0/(files.Count() == 0 ? 100 : files.Count() + zips.Count());

        // foreach (var file in files)
        // {
        //     /*await*/ UnpackSingleFile(key, pwdHash, file);
        //     File.Delete(file);
        // }

        await Parallel.ForEachAsync(files, async (file, _) => {
            try{
                UnpackSingleFile(key, pwdHash, file, prog);
                prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(file)} decrypted successfully");
                prog.Percentage += progress;
            }catch (Exception e)
            {
                prog.Message(Message.LEVEL.ERROR, $"{e.Message}");
                prog.Stop();
                Console.WriteLine(e);
            }
        });

        // foreach (var zip in zips)
        // {
        //     ZipFile.ExtractToDirectory(zip, $"./{Path.GetFileName(zip).Replace(".zip", "")}");
        //     File.Delete(zip);
        // }

        await Parallel.ForEachAsync(zips, async (zip, _) => {
            try{
                ZipFile.ExtractToDirectory(zip, $"./{Path.GetFileName(zip).Replace(".zip", "")}");
                File.Delete(zip);
                prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(zip)} decrypted successfully");
                prog.Percentage += progress;
            }catch (Exception e)
            {
                prog.Message(Message.LEVEL.ERROR, $"{e.Message}");
                prog.Stop();
                Console.WriteLine(e);
            }
        });
    }
    
    #endregion
}