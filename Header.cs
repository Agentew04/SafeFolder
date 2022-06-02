using System;

namespace SafeFolder;

[Serializable]
public class Header
{
    public string Hash { get; set; }
    public bool IsFolder { get; set; }
    public string Name { get; set; }
    public Guid Guid { get; set; }
    public int IvLength { get; set; }
    public byte[] Iv { get; set; }
}