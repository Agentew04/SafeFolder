using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;

namespace SafeFolder;

/*
 * Borrowed from UniChain CLI:
 * https://github.com/Agentew04/UniChain
 */

public class Flag {
    /// <summary>
    /// The simplified flag name
    /// </summary>
    public string Simplified { get; init; }
    
    /// <summary>
    /// The full flag name
    /// </summary>
    public string Full { get; init; }

    /// <summary>
    /// If the flag has a value associated with it
    /// </summary>
    public bool HasValue { get; init; }

    /// <summary>
    /// When the Flag has value, if the value can be empty(<see cref="string.Empty"></see>)
    /// </summary>
    public bool CanBeEmpty { get; init; }

    /// <summary>
    /// The value of the flag, null if <see cref="HasValue"/> is false
    /// </summary>
    public string? Value { get; set; }

    public Flag(string fullname, string simpleName, bool hasValue = false, bool canBeEmpty = false, string? value = null) {
        Simplified = simpleName;
        Full = fullname;
        HasValue = hasValue;
        CanBeEmpty = canBeEmpty;
        Value = value;
    }

    public static bool TryGetFlagValue(string[] args, Flag flag, out string value) {
        value = "";
        if (!flag.HasValue)
            return false;
        if (args.Length == 0) 
            return false;
        if (!args.Any(x => x=="--"+flag.Full || x=="-"+flag.Simplified))
            return false;

        int flagIndex = -1;
        for (var i = 0; i < args.Length; i++) {
            if (args[i] != "-"+flag.Simplified && args[i] != "--"+flag.Full) continue;
            flagIndex = i;
            break;
        }
        if (flagIndex == args.Length - 1)
            return false;

        // flag not found
        if (flagIndex == -1)
            return false;
        
        value = args[flagIndex + 1];

        // check if value is not other flag( has no value)
        return !value.StartsWith("-") && !value.StartsWith("--");
    }

    public static List<string> GetStrayArgs(string[] args, IEnumerable<Flag> flags) {
        List<string> argsList = args.ToList();
        List<string> strays = new();
        for (var i = 0; i < argsList.Count; i++) {
            // check if current is flag
            string arg = argsList[i];
            if (IsFlag(arg)) {
                Flag? flag = flags.FirstOrDefault(x => arg == "--"+x.Full || arg == "-"+x.Simplified);
                if (flag is null)
                    throw new FlagException($"Flag '{arg}' does not exist!");

                if (flag.HasValue) {
                    argsList.RemoveAt(i+1);
                }
                argsList.RemoveAt(i);
                i--;
            }
            else {
                strays.Add(argsList[i]);
            }
        }

        return strays;
    }

    public static bool HasFlag(string[] args, Flag flag) {
        if (args.Length == 0)
            return false;
        return args.Any(x => IsFlag(x) && x == "--"+flag.Full || x=="-"+flag.Simplified);
    }

    private static bool IsFlag(string arg) {
        return arg.StartsWith("-");
    }

    public Flag Clone() {
        return new Flag(Full, Simplified, HasValue, CanBeEmpty, Value);
    }
}

[Serializable]
public class FlagException : Exception {
    protected FlagException(SerializationInfo info, StreamingContext ctx) : base(info, ctx){}
    
    public FlagException(string message) : base(message){}
}
