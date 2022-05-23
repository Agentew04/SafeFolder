using System;
using System.IO;

namespace SafeFolder;

[Serializable]
public class Header
{
    public int size { get; set; }
    public string hash { get; set; }
    public string name { get; set; }
    public Guid guid { get; set; }
    public int ivLength { get; set; }
    public byte[] iv { get; set; }
}