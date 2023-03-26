using System;
using System.Text.Json.Serialization;

namespace SafeFolder;

[Serializable]
public class Header {
    public string Hash { get; set; } = "";
    public bool IsFolder { get; set; }
    public string Name { get; set; } = "";
    public Guid Guid { get; set; } = Guid.NewGuid();
    public int IvLength { get; set; } = 0;
    public byte[] Iv { get; set; } = Array.Empty<byte>();
    
    [JsonIgnore]
    public byte[] Key { get; init; }

    public Header(string hash, bool isFolder, string name, Guid guid, int ivLength, byte[] iv) {
        Hash = hash;
        IsFolder = isFolder;
        Name = name;
        Guid = guid;
        IvLength = ivLength;
        Iv = iv;
    }

    public Header() {
        
    }
}