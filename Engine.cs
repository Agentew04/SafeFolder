using System.Diagnostics;
using System.IO;
using System.IO.Compression;

namespace SafeFolder;

public static class Engine
{
    #region Folders

    public static void PackFolders(byte[] key)
    {
        // for each folder, compress, encrypt, delete folder
        var folders = Utils.GetFoldersFromSafeFile();

        foreach (var folder in folders)
        {
            var dirInfo = new DirectoryInfo(folder);
            var zipName = $"./{dirInfo.Name}.zip";
            ZipFile.CreateFromDirectory(dirInfo.FullName, zipName);
            Encryptor.AESFileEncrypt(zipName, zipName+".enc", key, Utils.GetIVFromSafeFile());
            File.Delete(zipName);
            Directory.Delete(folder,true);
        }
    }
    
    public static void UnpackFolders(byte[] key)
    {
        // for each folder, decrypt, decompress and delete zip
        var folders = Utils.GetFoldersFromSafeFile();

        foreach (var folder in folders)
        {
            var dirInfo = new DirectoryInfo(folder);
            var zipName = $"./{dirInfo.Name}.zip";
            var zipEncName = $"./{dirInfo.Name}.zip.enc";
            Encryptor.AESFileDecrypt(zipEncName, zipName, key, Utils.GetIVFromSafeFile());
            ZipFile.ExtractToDirectory(zipName, dirInfo.FullName);
            File.Delete(zipEncName);
            File.Delete(zipName);
        }
    }

    #endregion

    #region Files

    public static void PackFiles(byte[] key)
    {
        // files don't need to be compressed, just encrypted
        var files = Utils.GetFilesFromSafeFile();
        
        foreach (var file in files)
        {
            if(file.EndsWith(".safe")) continue;
            Encryptor.AESFileEncrypt(file, file+".enc", key, Utils.GetIVFromSafeFile());
            File.Delete(file);
        }
    }
    
    public static void UnpackFiles(byte[] key)
    {
        // files don't need to be decompressed, just decrypted
        var files = Utils.GetFilesFromSafeFile();
        
        foreach (var file in files)
        {
            if(file.EndsWith(".safe")) continue;
            Encryptor.AESFileDecrypt(file+".enc", file, key, Utils.GetIVFromSafeFile());
            File.Delete(file+".enc");
        }
    }

    #endregion
}