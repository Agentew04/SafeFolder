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
}