using System.Linq;

namespace SafeFolder;

public record Flag(string FullName, string? CompactName);

public static class CliUtils {
    public static bool hasFlag(string[] args, Flag flag) {
        string full = "--" + flag.FullName;
        string? small = flag.CompactName is not null ? "-" + flag.CompactName : null;
        return args.Any(x => x == full || ( small is not null && x == small ));
    }
    
    public static string? getFlagValue(string[] args, Flag flag) {
        string full = "--" + flag.FullName;
        string? small = flag.CompactName is not null ? "-" + flag.CompactName : null;
        
        for (var i = 0; i < args.Length; i++) {
            if (args[i] != full && args[i] != small) 
                continue;
            if (i + 1 < args.Length) {
                return args[i + 1];
            }
        }
        return null;
    }
}