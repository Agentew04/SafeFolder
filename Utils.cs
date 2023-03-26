using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
using PerrysNetConsole;

namespace SafeFolder
{
    public static class Utils{

        #region IO

        private static string GetVersion() {
            //get version from assembly
            string? version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString();
            return version ?? "";
        }

        /// <summary>
        /// Shows the splash screen.
        /// </summary>
        public static void ShowSplashScreen() {
            Console.WriteLine(@$"
=============================================

            Welcome to SafeFolder
                  v{GetVersion()}

=============================================
");
        }

        /// <summary>
        /// Shows the info screen.
        /// </summary>
        public static void ShowInfoScreen() {
            Console.WriteLine(@"
Encrypt/Decrypt files in memory: Fast, but demands more ram.

Encrypt/Decrypt files in memory:
    - Uses the RAM memory to convert your files faster. Not recommended for big files as it might crash!
Clear traces:
    - Clear all traces of the files in the hard drive, making it impossible to recover them.


Safe folder now has full CLI support! Flags are now available to use in the command line:
    -n  --nogui               => Disable the GUI and use the command line interface. Must be included to use the CLI flags.
    -h  --help                => Show this help screen.
    -v  --version             => Display the current version of the program.
    -m  --inmemory            => Encrypt/Decrypt files in memory.
    -c  --cleartraces         => Clear traces of the files in the hard drive.
    -e  --encrypt             => Encrypt the files.
    -d  --decrypt             => Decrypt the files.
    -p  --password <password> => Set the password to use.
    -V  --verbosity           => If enabled, an output will be shown.
    -b  --blacklist <regex>   => Multiple regexes separated by semicolon. Files that match these are ignored.

Also, include the path of the folder that will be encrypted anywhere on the arguments (except after a flag that accepts
a value) and it will recognize it! Defaults to current directory.
");
        }

        /// <summary>
        /// Writes a line to the console, with a color.
        /// </summary>
        /// <param name="message">The message, if not ends with \n, \n will be appended</param>
        /// <param name="color">The color to write the message</param>
        public static void WriteLine(string message, ConsoleColor color = ConsoleColor.White) {
            Console.ForegroundColor = color;
            if(!message.EndsWith("\n"))
                message+= "\n";
            Console.Write(message);
            Console.ResetColor();
        }
        
        #endregion
        
        
        #region Cryptography
        public static string HashBytes(byte[] bytes)
        {
            using var sha = SHA512.Create();
            return Convert.ToHexString(sha.ComputeHash(bytes));
        }

        /// <summary>
        /// Creates a key based on one or two strings. String -> Byte[] uses UTF8
        /// </summary>
        /// <param name="input">The main input</param>
        /// <param name="salt">The salt used. If <see langword="null"/>, the salt will be a empty array</param>
        /// <returns>The Key derived</returns>
        public static byte[] DeriveKeyFromString(string input, string? salt = null)
        {
            //get input bytes
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] saltBytes = salt != null ? Encoding.UTF8.GetBytes(salt) : new byte[16];
            // Generate the hash
            Rfc2898DeriveBytes pbkdf2 = new(inputBytes, saltBytes, iterations: 5000, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(32); //32 bytes length is 256 bits
        }

        /// <summary>
        /// Generates a random iv for AES
        /// </summary>
        /// <returns>The IV that has been generated</returns>
        public static byte[] GenerateIv()
        {
            //generate random IV
            using var aes = Aes.Create();
            return aes.IV;
        }
        public static string GetHash(string str){
            return BCrypt.Net.BCrypt.HashPassword(str);
        }        
        public static bool CheckHash(string password, string hash){
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        /// <summary>
        /// Encrypts a string using AES256 and a static IV.
        /// </summary>
        /// <param name="plaintext">The text that will be encrypted</param>
        /// <param name="key">The key used</param>
        /// <returns>The cyphertext</returns>
        public static string EncryptString(string plaintext, byte[] key) {
            byte[] iv = {
                0xcc, 0x2c, 0x77, 0xfb, 0xba, 0x3a, 0x90, 0x22, 0x47, 0x11, 0x6e, 0x51, 0x04, 0x5e, 0x38, 0x7d/*,
                0xe1, 0xa0, 0xc2, 0xf5, 0xbf, 0x8b, 0x5c, 0x1d, 0x34, 0xe9, 0x7e, 0x4f, 0x3d, 0xb5, 0x6f, 0xf4*/
            };
            Aes aes = Aes.Create();
            aes.Key = key;

            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);;
            return Convert.ToHexString(aes.EncryptCbc(plainBytes, iv));
        }

        /// <summary>
        /// Decrypts a string using AES256 and a fixed IV.
        /// </summary>
        /// <param name="cypherText">The ciphertext to be decrypted</param>
        /// <param name="key">The key used to decrypt</param>
        /// <returns>The plaintext</returns>
        public static string DecryptString(string cypherText, byte[] key) {
            byte[] iv = {
                0xcc, 0x2c, 0x77, 0xfb, 0xba, 0x3a, 0x90, 0x22, 0x47, 0x11, 0x6e, 0x51, 0x04, 0x5e, 0x38, 0x7d/*,
                0xe1, 0xa0, 0xc2, 0xf5, 0xbf, 0x8b, 0x5c, 0x1d, 0x34, 0xe9, 0x7e, 0x4f, 0x3d, 0xb5, 0x6f, 0xf4*/
            };
            Aes aes = Aes.Create();
            aes.Key = key;

            byte[] cypherBytes = Convert.FromHexString(cypherText);
            return Encoding.UTF8.GetString(aes.DecryptCbc(cypherBytes, iv));
        }
        
        /// <summary>
        /// Deletes a file in a secure way by overwriting it with zeros.
        /// </summary>
        /// <param name="filename">Full path of the file to be deleted</param>
        public static bool WipeFile(string filename) {
            try
            {
                if (!File.Exists(filename)) return true;
                // Set the files attributes to normal in case it's read-only.
                File.SetAttributes(filename, FileAttributes.Normal);

                // Calculate the total number of sectors in the file.
                var sectors = (int)Math.Ceiling(new FileInfo(filename).Length/512.0);
                    
                // Create a dummy-buffer the size of a sector.
                var buffer = new byte[512];

                // Open a FileStream to the file.
                var inputStream = new FileStream(filename, FileMode.Open);

                // Loop all sectors
                for (var i = 0; i < sectors; i++)
                {
                    // write zeros
                    inputStream.Write(buffer, 0, buffer.Length);
                }
                // truncate file
                inputStream.SetLength(0);
                // Close the stream.
                inputStream.Close();

                // wipe dates
                DateTime dt = new(2037, 1, 1, 0, 0, 0);
                File.SetCreationTime(filename, dt);
                File.SetLastAccessTime(filename, dt);
                File.SetLastWriteTime(filename, dt);

                File.SetCreationTimeUtc(filename, dt);
                File.SetLastAccessTimeUtc(filename, dt);
                File.SetLastWriteTimeUtc(filename, dt);

                // Finally, delete the file
                File.Delete(filename);
                return true;
            }
            catch(Exception) {
                return false;
            }
        }

        /// <summary>
        /// Recursively Wipes all files inside a folder and its subfolders.
        /// </summary>
        /// <param name="folder">The folder to be wiped</param>
        /// <returns>If the operation was successful or not.</returns>
        public static bool WipeFolder(string folder)
        {
            try {
                if (!Directory.Exists(folder)) 
                    return true;

                DirectoryInfo dir = new(folder);
                
                foreach (FileInfo file in dir.GetFiles())
                    WipeFile(file.FullName);

                foreach (DirectoryInfo subDir in dir.GetDirectories())
                    WipeFolder(subDir.FullName);

                // wipe dates
                DateTime dt = new(2037, 1, 1, 0, 0, 0);
                Directory.SetCreationTime(folder, dt);
                Directory.SetLastAccessTime(folder, dt);
                Directory.SetLastWriteTime(folder, dt);

                Directory.SetCreationTimeUtc(folder, dt);
                Directory.SetLastAccessTimeUtc(folder, dt);
                Directory.SetLastWriteTimeUtc(folder, dt);

                // Finally, delete the folder
                Directory.Delete(folder, true);
                return true;
            }
            catch(Exception) {
                return false;
            }
        }
        
        #endregion
    }
}
