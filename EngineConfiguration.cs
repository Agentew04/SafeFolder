using PerrysNetConsole;

namespace SafeFolder; 

public struct EngineConfiguration {
    public /*required*/ string FolderPath { get; init; }
    public Progress? ProgressBar { get; init; }
    
    /// <summary>
    /// A string of different regexes separated by semicolons. Any file that matches
    /// these regex are not going to be encrypted.
    /// </summary>
    public string Blacklist { get; init; }
    
    /// <summary>
    /// If the RAM is to be used to encrypt/decrypt folders. If false, the disk is used instead
    /// </summary>
    public bool UseRam { get; init; }
    
    /// <summary>
    /// If we should completely erase the files from the disk.
    /// </summary>
    public bool ClearTraces { get; init; }
}