using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;

namespace SafeFolder;

public static class Engine
{
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
                Encryptor.AesFileEncrypt(zipName, zipName + ".enc", key, Utils.GetIvFromSafeFile());
                File.Delete(zipName);
                Directory.Delete(folder, true);
            }));
        }
        await Task.WhenAll(taskList);
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
                Encryptor.AesFileDecrypt(zipEncName, zipName, key, Utils.GetIvFromSafeFile());
                ZipFile.ExtractToDirectory(zipName, dirInfo.FullName);
                File.Delete(zipEncName);
                File.Delete(zipName);
            }));
        }

        await Task.WhenAll(taskList);
    }

    #endregion

    #region Files

    public static async Task PackFiles(byte[] key)
    {
        // files don't need to be compressed, just encrypted
        var files = Utils.GetFilesFromSafeFile();
        var taskList = new List<Task>();

        foreach (var file in files)
        {
            taskList.Add(Task.Run(() =>
                {
                    if (file.EndsWith(".safe")) return;
                    Encryptor.AesFileEncrypt(file, file + ".enc", key, Utils.GetIvFromSafeFile());
                    File.Delete(file);
                }));
        }
        await Task.WhenAll(taskList);
    }
    
    public static async Task UnpackFiles(byte[] key)
    {
        // files don't need to be decompressed, just decrypted
        var files = Utils.GetFilesFromSafeFile();
        var taskList = new List<Task>();

        foreach (var file in files)
        {
            taskList.Add(Task.Run(() =>
                {
                    if (file.EndsWith(".safe")) return;
                    Encryptor.AesFileDecrypt(file + ".enc", file, key, Utils.GetIvFromSafeFile());
                    File.Delete(file + ".enc");
                }));
        }
        await Task.WhenAll(taskList);
    }

    #endregion
}