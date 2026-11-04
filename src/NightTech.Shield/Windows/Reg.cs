using System;
using Microsoft.Win32;

namespace NightTech.Shield.Windows;

/// <summary>
/// Registry locations written as text so findings and the undo log can point back at them:
/// "HKLM\SOFTWARE\...", "HKLM32\SOFTWARE\..." (the 32-bit view) or "HKU\S-1-5-21-...\Software\...".
/// The signed-in person's settings are always under HKU\&lt;their SID&gt;, even when another administrator approved Shield.
/// </summary>
public static class Reg
{
    public static string Machine(string path, bool wow32 = false) => (wow32 ? "HKLM32\\" : "HKLM\\") + path;
    public static string User(string sid, string path) => $"HKU\\{sid}\\{path}";

    /// <summary>Opens a key from its text form. Null when it doesn't exist.</summary>
    public static RegistryKey? Open(string location, bool writable = false)
    {
        var (root, path) = Split(location);
        if (root is null) return null;
        try { return root.OpenSubKey(path, writable); }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException) { return null; }
    }

    public static (RegistryKey? Root, string Path) Split(string location)
    {
        int slash = location.IndexOf('\\');
        if (slash < 0) return (null, "");
        var hive = location[..slash].ToUpperInvariant();
        var path = location[(slash + 1)..];
        RegistryKey? root = hive switch
        {
            "HKLM" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64),
            "HKLM32" => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32),
            "HKU" => RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64),
            _ => null,
        };
        return (root, path);
    }

    /// <summary>Friendly words for where a key is: "this user" or "all users".</summary>
    public static string Scope(string location) => location.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase) ? "this user" : "all users";

    public static string Str(RegistryKey k, string name) => k.GetValue(name, null, RegistryValueOptions.None)?.ToString()?.Trim() ?? "";

    public static int? Int(RegistryKey k, string name) => k.GetValue(name) switch
    {
        int i => i,
        long l => (int)l,
        string s when int.TryParse(s, out var v) => v,
        _ => null,
    };
}
