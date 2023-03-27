using System;
using System.IO;

namespace SafeFolder; 

public static class Extensions {
    /// <summary>
    /// Writes a GUID bytes to a binary stream
    /// </summary>
    /// <param name="stream">The binary stream</param>
    /// <param name="guid">The <see cref="Guid"/> to be written</param>
    public static void Write(this BinaryWriter stream, Guid guid) => stream.Write(guid.ToByteArray());
    
    /// <summary>
    /// Writes the file header to the stream
    /// </summary>
    /// <param name="writer">The binaryWrite object</param>
    /// <param name="header">The header object</param>
    /// <param name="key">The key used to encrypt the original filename</param>
    public static void Write(this BinaryWriter writer, Header header, byte[] key)
    {
        writer.Write(header.Hash);
        writer.Write(header.IsFolder);
        writer.Write(Utils.EncryptString(header.Name, key));
        writer.Write(header.Guid);
        writer.Write(header.IvLength);
        writer.Write(header.Iv);
    }
    
    /// <summary>
    /// Reads a guid from a binary stream
    /// </summary>
    /// <param name="stream">The binary stream</param>
    /// <returns>The guid that has been read</returns>
    public static Guid ReadGuid(this BinaryReader stream) => new(stream.ReadBytes(16));
    
    /// <summary>
    /// Reads a header from a binary stream
    /// </summary>
    /// <param name="reader">the stream</param>
    /// <param name="key">The key used to encrypt the filename</param>
    /// <returns>The header file that has been read</returns>
    public static Header ReadHeader(this BinaryReader reader, byte[] key) {
        Header header = new() {
            Hash = reader.ReadString(),
            IsFolder = reader.ReadBoolean(),
            Name = Utils.DecryptString(reader.ReadString(), key),
            Guid = reader.ReadGuid(),
            IvLength = reader.ReadInt32()
        };

        header.Iv = reader.ReadBytes(header.IvLength);
        return header;
    }
}