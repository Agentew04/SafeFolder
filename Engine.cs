using PerrysNetConsole;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.IO.Compression;

namespace SafeFolder;

public static class Engine
{
    private const int KeySize = 256;
    private const int BlockSize = 128;
    private const PaddingMode PaddingMode = System.Security.Cryptography.PaddingMode.PKCS7;
    private const CipherMode CipherMode = System.Security.Cryptography.CipherMode.CBC;
    
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

        #endregion
    }
    private static void PackSingleFolder(byte[] key, string pwdHash, string folder, bool method)
    {
        if (method){
            var dirInfo = new DirectoryInfo(folder);
            using var ms = new MemoryStream();
            using var zip = new Ionic.Zip.ZipFile();

            zip.AddDirectory(folder, dirInfo.Name);
            zip.Save(ms);
            ms.Seek(0, SeekOrigin.Begin);
            
            
            #region header
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
            
            #endregion

            #region stream init
            using var outStream = File.Create(encFile);
            using var bw = new BinaryWriter(outStream);
            bw.Write(header);
            #endregion

            #region cryptography
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
            while ( (bytesRead= ms.Read(buffer)) > 0)
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

            bw.Write(header);

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
    
    public static async Task PackFiles(byte[] key, string pwdHash, Progress prog, bool method, bool traces)
    {
        var files = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => !Path.GetFileName(f).Contains(_safeFolderName) && !f.EndsWith(".pdb") && !f.EndsWith(".enc"))
            .ToList();

        var folders = Directory.GetDirectories(Directory.GetCurrentDirectory()).ToList();

        var progress = 100.0 / (files.Count + folders.Count == 0 ? 100 : files.Count + folders.Count);

        // encrypt files
        await Parallel.ForEachAsync(files, (file, _) =>
        {
            try{
                PackSingleFile(key, pwdHash, Path.GetFileName(file));
                File.Delete(file);
                prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(file)} encrypted successfully");
                if (traces){
                    prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(file)} cleared traces successfully");
                }
                prog.Percentage += progress;
            }catch (Exception e)
            {
                prog.Message(Message.LEVEL.ERROR, $"{e.Message}");
                prog.Stop();
                Console.WriteLine(e);
            }

            return ValueTask.CompletedTask;
        });

        // encrypt folders
        await Parallel.ForEachAsync(folders, (folder, _) =>
        {
            try{
                PackSingleFolder(key, pwdHash, Path.GetFileName(folder), method);
                Directory.Delete(folder, true);
                File.Delete(Path.GetFileName(folder) + ".zip");
                prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(folder)} encrypted successfully");
                if (traces){
                    prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(folder)} cleared traces successfully");
                }
                prog.Percentage += progress;
            }catch (Exception e)
            {
                prog.Message(Message.LEVEL.ERROR, $"{e.Message}");
                prog.Stop();
                Console.WriteLine(e);
            }

            return ValueTask.CompletedTask;
        });
    }

    private static void UnpackSingleFileOrFolder(byte[] key, string file, Progress prog, bool method)
    {
        #region header
        var guidFileName = Guid.Parse(Path.GetFileName(file).Replace(".enc", ""));
        using var inStream = new FileStream(file, FileMode.Open, FileAccess.Read);
        using var br = new BinaryReader(inStream);
        var header = br.ReadHeader();
        if(header.Guid != guidFileName || !Utils.CheckHash(Utils.HashBytes(key), header.Hash))
        {
            prog.Message(Message.LEVEL.WARN, $"Wrong password or file corrupted ({Path.GetFileName(file)})");
            return;
        }

        var isFolder = header.IsFolder;
        #endregion

        #region criptography
        
        if (!isFolder)
        {
            // file
            using var outStream = File.Create(header.Name);
            using var aes = Aes.Create();
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;
            aes.Padding = PaddingMode;
            aes.Mode = CipherMode;
            aes.Key = key;
            aes.IV = header.Iv;

            using var cryptoStream = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            Span<byte> buffer = stackalloc byte[1024];
            int bytesRead;
            while ((bytesRead = cryptoStream.Read(buffer)) > 0)
                outStream.Write(buffer[..bytesRead]);

            inStream.Close();
        }
        else
        {
            // directory
            if (method){
                using var ms = new MemoryStream();
                using var aes = Aes.Create();
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Padding = PaddingMode;
                aes.Mode = CipherMode;
                aes.Key = key;
                aes.IV = header.Iv;

                using var cryptoStream = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
                Span<byte> buffer = stackalloc byte[1024];
                int bytesRead;
                while ((bytesRead = cryptoStream.Read(buffer)) > 0)
                    ms.Write(buffer[..bytesRead]);
                
                ms.Seek(0, SeekOrigin.Begin);
                
                // ms has a zip file
                using var zip = Ionic.Zip.ZipFile.Read(ms);
                
                
                zip.ExtractAll(Directory.GetCurrentDirectory() , Ionic.Zip.ExtractExistingFileAction.OverwriteSilently);
            }else{
                using var outStream = File.Create($"{header.Name}.zip");
                using var aes = Aes.Create();
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Padding = PaddingMode;
                aes.Mode = CipherMode;
                aes.Key = key;
                aes.IV = header.Iv;

                using var cryptoStream = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
                Span<byte> buffer = stackalloc byte[1024];
                int bytesRead;
                while ((bytesRead = cryptoStream.Read(buffer)) > 0)
                    outStream.Write(buffer[..bytesRead]);

                inStream.Close();
                outStream.Close();

                ZipFile.ExtractToDirectory($"{header.Name}.zip", "./");
                File.Delete($"{header.Name}.zip");
            }
        }
        File.Delete(file);
        prog.Message(Message.LEVEL.DEBUG, $"{Path.GetFileName(file)} decrypted successfully");
        #endregion
        
    }

    public static async Task UnpackFiles(byte[] key, string pwdHash, Progress prog, bool method)
    {
        var files = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => f.EndsWith(".enc")).ToList();

        var zips = Directory.EnumerateFiles(Directory.GetCurrentDirectory())
            .Where(f => f.EndsWith(".zip")).ToList();

        var progress = 100.0 / (!files.Any() ? 100 : files.Count + zips.Count);
        

        // decrypt files and folders
        await Parallel.ForEachAsync(files, (file, _) =>
        {
            try{
                UnpackSingleFileOrFolder(key, file, prog, method);
                prog.Percentage += progress;
            }catch (Exception e)
            {
                prog.Message(Message.LEVEL.ERROR, $"{e.Message}");
                prog.Stop();
                Console.WriteLine(e);
            }

            return ValueTask.CompletedTask;
        });


        /*await Parallel.ForEachAsync(zips, async (zip, _) => {
            try{
                UnpackSingleFolder();
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
        });*/
    }
    
    #endregion
}