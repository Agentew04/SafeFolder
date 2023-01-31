using PerrysNetConsole;

namespace SafeFolder; 

public struct EngineConfiguration {
    public /*required*/ string FolderPath { get; set; }
    public Progress? ProgressBar { get; set; }
}