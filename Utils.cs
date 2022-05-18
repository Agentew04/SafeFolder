using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace SafeFolder
{
    public static class Utils{

        #region IO

        public static string GetPasswordInput(string prompt = "")
        {
            Console.Write(prompt);
            var password = "";
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key != ConsoleKey.Backspace || password.Length <= 0) continue;
                    password = password[..^1]; // black magic, but it works
                    Console.Write("\b \b");
                }
            }
            while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return password;
        }

        public static void ShowSplashScreen()
        {
            Console.WriteLine(@"
=============================================

            Welcome to SafeFolder
                   v0.1.0

=============================================
");
        }
        
        public static void ShowCorrupt()
        {
            Console.WriteLine(@"
=============================================
                
             _  
           .' ) 
 ,.--.    / .'          Installation is corrupted
//    \  / /    
\\    / / /     
 `'--' . '      
 ,.--. | |      
//    \' '      
\\    / \ \             Try reinstalling SafeFolder
 `'--'   \ \    
          \ '.  
           '._)
   

=============================================
");
            Thread.Sleep(5000);
        }
        
        #endregion

        #region Binary

        public static void Write(this BinaryWriter stream, IEnumerable<string> strings)
        {
            // Write the number of strings
            stream.Write(strings.Count());
            
            // Write each string
            foreach (var str in strings)
            {
                stream.Write(str);
            }
        }

        public static IEnumerable<string> ReadStrings(this BinaryReader stream)
        {
            var strings = new List<string>();
            // Read the number of strings
            var count = stream.ReadInt32();
            
            // Read each string
            for (var i = 0; i < count; i++)
            {
                strings.Add(stream.ReadString());
            }

            return strings;
        }

        #endregion

        #region  safeFile
        
        private static readonly string _currentPath = Environment.CurrentDirectory;
        private static readonly string _safeFilePath = $"{_currentPath}\\.safe";
        
        public static bool GetStateFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            var state = binaryReader.ReadBoolean();
            return state;
        }
        public static void SetStateToSafeFile(bool state)
        {
            using var binaryWriter = new BinaryWriter(File.OpenWrite(_safeFilePath));
            binaryWriter.Write(state);
        }
        
        public static string GetHashFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            _ = binaryReader.ReadBoolean();
            var hash = binaryReader.ReadString();
            return hash;
        }

        public static IEnumerable<string> GetFilesFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            _ = binaryReader.ReadBoolean();
            _ = binaryReader.ReadString();
            var files = binaryReader.ReadStrings();
            return files;
        }
        
        public static IEnumerable<string> GetFoldersFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            _ = binaryReader.ReadBoolean();
            _ = binaryReader.ReadString();
            _ = binaryReader.ReadStrings();
            var folders = binaryReader.ReadStrings();
            return folders;
        }
        
        public static byte[] GetIVFromSafeFile()
        {
            using var binaryReader = new BinaryReader(File.OpenRead(_safeFilePath));
            _ = binaryReader.ReadBoolean();
            _ = binaryReader.ReadString();
            _ = binaryReader.ReadStrings();
            _ = binaryReader.ReadStrings();
            var length = binaryReader.ReadInt32();
            var iv = binaryReader.ReadBytes(length);
            return iv;
        }

        
        #endregion
        
        #region dict
        private static byte[] jsondictIV = new byte[16]{24,92,159,42,12,39,84,147,129,96,10,48,28,248,139,57};
        public static string DictionaryToJson(Dictionary<Guid,CryptoInfo> dict){
            //convert dict to json using json serializer
            return JsonSerializer.Serialize(dict);
        }
        public static Dictionary<Guid,CryptoInfo> JsonToDictionary(string json){
            Dictionary<Guid,CryptoInfo> dict = new Dictionary<Guid,CryptoInfo>();
            try{
                dict = JsonSerializer.Deserialize<Dictionary<Guid,CryptoInfo>>(json);
            }
            catch(Exception){}
            return dict;
        }
        public static Dictionary<Guid,CryptoInfo> LoadDictionary(byte[] key){
            //load dictionary from json file
            string path = Environment.CurrentDirectory + "/SafeFolder/info.safe";
            if(!File.Exists(path)){
                return new Dictionary<Guid,CryptoInfo>();
            }
            string cryptoJson = File.ReadAllText(path);
            var json = AESDecryptString(cryptoJson,key,jsondictIV);
            return JsonToDictionary(json);
        }
        public static void SaveDictionary(Dictionary<Guid,CryptoInfo> dict,byte[] key){
            //save dictionary to json file
            string path = Environment.CurrentDirectory + "/SafeFolder/info.safe";
            string json = DictionaryToJson(dict);
            var cryptoJson = AESEncryptString(json,key,jsondictIV);
            File.WriteAllText(path,cryptoJson);
        }
        public static string AESEncryptString(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an AesManaged object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return Convert.ToBase64String(encrypted);
        }

        public static string AESDecryptString(string cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                return "";
                //throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an AesManaged object
            // with the specified key and IV.
            // was using AesManaged aesAlg = new AesManaged();
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                var cipherTextBytes = Convert.FromBase64String(cipherText);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        #endregion

        #region hashfile
        public static void saveHashToFile(string hash){
            //save hash to file
            string path = Environment.CurrentDirectory + "/SafeFolder/hash.safe";
            File.WriteAllText(path,hash);
        }
        public static string loadHashFromFile(){
            //load hash from file
            string path = Environment.CurrentDirectory + "/SafeFolder/hash.safe";
            if(!File.Exists(path)){
                return "";
            }
            return File.ReadAllText(path);
        }

        #endregion
        
        #region state
        public static void setEncryptionState(bool state){
            //set encryption state
            string path = Environment.CurrentDirectory + "/SafeFolder/state.safe";
            File.WriteAllText(path,state.ToString());
        }
        public static bool getEncryptionState(){
            //get encryption state
            string path = Environment.CurrentDirectory + "/SafeFolder/state.safe";
            if(!File.Exists(path)){
                return false;
            }
            return bool.Parse(File.ReadAllText(path));
        }


        #endregion

        #region Cryptography

        public static string HashFile(string path){
            //hash file
            string hash = "";
            using(FileStream fs = File.OpenRead(path)){
                using(SHA256 sha = SHA256.Create()){
                    byte[] hashbytes = sha.ComputeHash(fs);
                    hash = Convert.ToBase64String(hashbytes);
                }
            }
            return hash;
        }
        
        public static byte[] CreateKey(string hash, string password) => Convert.FromHexString(GetHash(hash + password));

        public static byte[] GenerateIV()
        {
            //generate random IV
            using var aes = Aes.Create();
            return aes.IV;
        }

        public static string GetHash(string str){
            const int hashNum = 500_000;
            for(var i=0;i<hashNum;i++){
                str = RawHash(str);
            }
            return str;
        }        
        private static string RawHash(string s){
            //sha256
            var sha256 = SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(s);
            var hash = sha256.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        #endregion
        
    }
}
