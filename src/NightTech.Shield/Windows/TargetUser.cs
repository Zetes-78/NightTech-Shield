using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace NightTech.Shield.Windows;

/// <summary>
/// The person signed in at the screen. Shield runs as administrator; when a different administrator account approved
/// it, the browsers, startup items and proxy to check are still the signed-in person's, not the administrator's.
/// </summary>
public sealed class TargetUser
{
    public string Sid { get; init; } = "";
    public string Name { get; init; } = "";
    public string Profile { get; init; } = "";
    public bool IsCurrentProcessUser { get; init; }

    public string Roaming => Path.Combine(Profile, "AppData", "Roaming");
    public string Local => Path.Combine(Profile, "AppData", "Local");

    public static TargetUser Find()
    {
        var me = WindowsIdentity.GetCurrent();
        var mySid = me.User?.Value ?? "";
        string sid = ConsoleExplorerOwner() ?? mySid;
        // The hive has to be loaded to be checked; it is whenever the person is signed in.
        using (var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64))
            if (users.OpenSubKey(sid) is null) sid = mySid;
        return new TargetUser
        {
            Sid = sid,
            Name = NameOf(sid),
            Profile = ProfileOf(sid) ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            IsCurrentProcessUser = sid == mySid,
        };
    }

    /// <summary>Expands %USERPROFILE%, %APPDATA%, %LOCALAPPDATA% and %TEMP% for this person, then the machine-wide variables.</summary>
    public string Expand(string s)
    {
        if (string.IsNullOrEmpty(s) || !s.Contains('%')) return s ?? "";
        s = Replace(s, "%USERPROFILE%", Profile);
        s = Replace(s, "%APPDATA%", Roaming);
        s = Replace(s, "%LOCALAPPDATA%", Local);
        s = Replace(s, "%TEMP%", Path.Combine(Local, "Temp"));
        s = Replace(s, "%TMP%", Path.Combine(Local, "Temp"));
        return Environment.ExpandEnvironmentVariables(s);
    }

    private static string Replace(string s, string token, string value) =>
        s.Replace(token, value, StringComparison.OrdinalIgnoreCase);

    private static string? ConsoleExplorerOwner()
    {
        try
        {
            uint session = WTSGetActiveConsoleSessionId();
            if (session == 0xFFFFFFFF) return null;
            foreach (var p in Process.GetProcessesByName("explorer"))
            {
                using (p)
                {
                    if ((uint)p.SessionId != session) continue;
                    using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {p.Id}");
                    foreach (ManagementObject o in searcher.Get())
                        using (o)
                        {
                            var outParams = o.InvokeMethod("GetOwnerSid", null, null);
                            if (outParams?["Sid"] is string s && s.Length > 0) return s;
                        }
                }
            }
        }
        catch (Exception e) when (e is ManagementException or COMException or InvalidOperationException or UnauthorizedAccessException) { }
        return null;
    }

    private static string? ProfileOf(string sid)
    {
        using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            .OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        var path = k?.GetValue("ProfileImagePath") as string;
        return string.IsNullOrEmpty(path) ? null : Environment.ExpandEnvironmentVariables(path);
    }

    private static string NameOf(string sid)
    {
        try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
        catch (SystemException) { return sid; }   // not mapped (deleted or domain account offline)
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
}
