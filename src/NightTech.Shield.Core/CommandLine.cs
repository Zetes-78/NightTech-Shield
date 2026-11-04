namespace NightTech.Shield.Core;

/// <summary>Works out which program a startup command runs, the way Windows does.</summary>
public static class CommandLine
{
    /// <summary>
    /// Splits a command into the program and the rest. A quoted program is taken as-is; an unquoted one is the shortest
    /// run of words that names a file that exists (so "C:\Program Files\App\app.exe /min" works), or the first word.
    /// </summary>
    public static (string Program, string Arguments) Split(string command, Func<string, bool> fileExists)
    {
        var c = (command ?? "").Trim();
        if (c.Length == 0) return ("", "");
        if (c[0] == '"')
        {
            int end = c.IndexOf('"', 1);
            if (end < 0) return (c.Trim('"'), "");
            return (c[1..end], c[(end + 1)..].Trim());
        }
        var words = c.Split(' ');
        for (int n = 1; n <= words.Length; n++)
        {
            var candidate = string.Join(' ', words.Take(n));
            if (Exists(candidate, fileExists)) return (WithExe(candidate, fileExists), string.Join(' ', words.Skip(n)).Trim());
        }
        return (words[0], string.Join(' ', words.Skip(1)).Trim());
    }

    private static bool Exists(string path, Func<string, bool> fileExists) =>
        fileExists(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && fileExists(path + ".exe");

    private static string WithExe(string path, Func<string, bool> fileExists) =>
        fileExists(path) ? path : path + ".exe";

    private static readonly string[] Hosts = { "rundll32", "regsvr32", "wscript", "cscript", "mshta", "powershell", "pwsh", "cmd", "conhost" };

    /// <summary>The bare file name without ".exe", lower case: "rundll32", "powershell".</summary>
    public static string BaseName(string program)
    {
        var name = program.Replace('/', '\\');
        name = name[(name.LastIndexOf('\\') + 1)..];
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
        return name.ToLowerInvariant();
    }

    /// <summary>True when the program is one of Windows' script or loader programs that run something else.</summary>
    public static bool IsScriptHost(string program) => Hosts.Contains(BaseName(program));

    /// <summary>
    /// For rundll32/regsvr32/wscript/cscript, the file it actually loads ("C:\x\evil.dll,Start" gives C:\x\evil.dll).
    /// Empty when there isn't one.
    /// </summary>
    public static string Payload(string program, string arguments)
    {
        var b = BaseName(program);
        if (b is not ("rundll32" or "regsvr32" or "wscript" or "cscript")) return "";
        var args = arguments.Trim();
        // Skip switches such as /s, /u, /B, //nologo.
        while (args.StartsWith('/') || args.StartsWith('-'))
        {
            int sp = args.IndexOf(' ');
            if (sp < 0) return "";
            args = args[(sp + 1)..].TrimStart();
        }
        if (args.Length == 0) return "";
        string first;
        if (args[0] == '"')
        {
            int end = args.IndexOf('"', 1);
            first = end < 0 ? args.Trim('"') : args[1..end];
        }
        else
        {
            int sp = args.IndexOf(' ');
            first = sp < 0 ? args : args[..sp];
        }
        int comma = first.IndexOf(',');
        if (comma > 0 && b == "rundll32") first = first[..comma];
        return first.Trim();
    }
}
