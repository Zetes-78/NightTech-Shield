using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using NightTech.Shield.Core;

namespace NightTech.Shield.Windows;

/// <summary>
/// Makes the fixes the person ticked, and puts them back on request. Every change that can be undone is written to the
/// undo log first; files are moved into Shield's own folder rather than deleted.
/// </summary>
public sealed class Fixer
{
    private readonly TargetUser _user;
    public UndoLog Log { get; }

    public static string DataFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Night Tech Solutions", "Shield");
    public static string LogPath => Path.Combine(DataFolder, "changes.json");
    private static string KeptFolder => Path.Combine(DataFolder, "Kept");

    public Fixer(TargetUser user)
    {
        _user = user;
        PrepareFolder();
        Log = UndoLog.Load(LogPath);
    }

    /// <summary>
    /// Shield's folder is for administrators only. Anyone who could edit the undo log could get Shield to write
    /// startup entries for them, so ordinary accounts can't change it.
    /// </summary>
    private static void PrepareFolder()
    {
        // ProgramData lets any account make folders, so a folder made ahead of time by someone else (or a link to
        // somewhere else) is refused rather than used.
        var company = Path.GetDirectoryName(DataFolder)!;
        foreach (var path in new[] { company, DataFolder, KeptFolder })
        {
            var dir = new DirectoryInfo(path);
            if (!dir.Exists) dir.Create();
            dir.Refresh();
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"{path} is a link to another folder, so Shield won't use it. Delete it and open Shield again.");
            var owner = dir.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner is null || !(owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || owner.IsWellKnown(WellKnownSidType.LocalSystemSid)))
                throw new InvalidOperationException($"{path} was made by another account, so Shield won't trust it. An administrator should delete it, then open Shield again.");
            dir.SetAccessControl(AdminsOnly(readableByUsers: path == company));
        }
    }

    private static DirectorySecurity AdminsOnly(bool readableByUsers)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (readableByUsers)
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        sec.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        return sec;
    }

    /// <summary>True when the folder, or any folder above it, is a junction or link (which could point Shield somewhere else).</summary>
    private static bool HasLink(string dir)
    {
        for (var d = new DirectoryInfo(Path.GetFullPath(dir)); d is not null; d = d.Parent)
            if (d.Exists && (d.Attributes & FileAttributes.ReparsePoint) != 0) return true;
        return false;
    }

    private static bool IsInside(string path, string folder)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(folder).TrimEnd('\\') + "\\";
        return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    private void Save() => Log.Save(LogPath);

    private Change Record(ChangeKind kind, string title, Dictionary<string, string>? data = null, IEnumerable<string>? lines = null)
    {
        var c = Log.Add(new Change { Kind = kind, Title = title, Data = data ?? new(), Lines = lines?.ToList() ?? new() }, DateTime.UtcNow);
        Save();
        return c;
    }

    /// <summary>A Windows restore point before the first change, so the whole PC can be rolled back too.</summary>
    public static string CreateRestorePoint()
    {
        try
        {
            using var sr = new ManagementClass(new ManagementScope(@"\\.\root\default"), new ManagementPath("SystemRestore"), null);
            using var inParams = sr.GetMethodParameters("CreateRestorePoint");
            inParams["Description"] = "Before Night Tech Shield fixes";
            inParams["RestorePointType"] = 12;   // MODIFY_SETTINGS
            inParams["EventType"] = 100;         // BEGIN_SYSTEM_CHANGE
            using var result = sr.InvokeMethod("CreateRestorePoint", inParams, null);
            uint rv = Convert.ToUInt32(result?["ReturnValue"] ?? 1u);
            return rv == 0 ? "Made a Windows restore point." : "Windows didn't make a restore point (System Protection may be off). Fixes continued.";
        }
        catch (Exception e) when (e is ManagementException or COMException or UnauthorizedAccessException)
        {
            return "Windows didn't make a restore point (System Protection may be off). Fixes continued.";
        }
    }

    // ---------------- Fixes ----------------

    /// <summary>Makes one fix. Returns what happened in plain words; throws with a plain message when it couldn't.</summary>
    public async Task<string> Apply(Finding f, CancellationToken ct)
    {
        switch (f.Fix)
        {
            case FixKind.UpdateDefinitions:
            {
                var r = await Defender.UpdateDefinitions(ct);
                if (r.ExitCode != 0) throw new InvalidOperationException(r.TimedOut ? "The update took too long. Check the internet connection and try again." : "Defender couldn't download new definitions. Check the internet connection and try again.");
                Record(ChangeKind.Record, "Updated Microsoft Defender's virus definitions");
                return "Definitions updated.";
            }
            case FixKind.QuickScan:
            {
                var r = await Defender.Scan(full: false, ct);
                Record(ChangeKind.Record, "Ran a Microsoft Defender quick scan");
                return r.ExitCode switch
                {
                    0 => "Quick scan finished. Nothing found.",
                    2 => "Quick scan finished and Defender found something. Scan again in Shield to see it.",
                    _ => r.TimedOut ? "The scan took too long and was stopped." : "Defender couldn't finish the scan.",
                };
            }
            case FixKind.RemoveThreats:
            {
                var r = await Defender.RemoveThreats(ct);
                if (r.ExitCode != 0) throw new InvalidOperationException("Defender couldn't remove it. Try a Microsoft Defender Offline scan (in Shield's More menu), or call Night Tech.");
                Record(ChangeKind.Record, "Asked Microsoft Defender to remove " + f.Title.Replace("Malware found: ", "", StringComparison.Ordinal));
                return "Defender removed it. A restart may be needed to finish.";
            }
            case FixKind.TurnOnRealTime:
            {
                var r = await Defender.TurnOnRealTime(ct);
                // Set-MpPreference reports success even when a policy quietly keeps it off, so check.
                if (r.ExitCode != 0 || Defender.RealTimeOn() != true)
                {
                    bool opened = OpenLink("windowsdefender://threatsettings");
                    throw new InvalidOperationException("Windows didn't allow it (a setting or another program may be blocking it). "
                        + (opened ? "Windows Security is open: turn on Real-time protection there." : "Open Windows Security from the Start menu and turn on Real-time protection there."));
                }
                Record(ChangeKind.Record, "Turned on Defender's real-time protection");
                return "Real-time protection is on.";
            }
            case FixKind.OpenWindowsSecurity:
                return OpenLink("windowsdefender://threat") ? "Windows Security is open." : "Open Windows Security from the Start menu.";
            case FixKind.Uninstall:
                return await Uninstall(f, ct);
            case FixKind.DisableStartup:
                return DisableStartup(f);
            case FixKind.RemovePolicy:
                return RemovePolicies(f);
            case FixKind.CleanHosts:
                return CleanHosts(f.Id);
            case FixKind.TurnOffProxy:
                return TurnOffProxy();
            case FixKind.ResetBrowser:
            case FixKind.OpenExtensions:
                // Done by the person in the browser itself (see BrowserHelp). Nothing changes here.
                return "See the steps on screen.";
            default:
                return "";
        }
    }

    /// <summary>
    /// True when the person signed in at the PC is the one who approved Shield. Only then does handing a link to
    /// Explorer open it in their own, ordinary (not administrator) browser.
    /// </summary>
    public static bool LinksAllowed { get; set; }

    /// <summary>Opens a web or Windows link through the signed-in person's Explorer. False when it wasn't opened (show the address instead).</summary>
    public static bool OpenLink(string url)
    {
        if (!LinksAllowed || !Regex.IsMatch(url, @"^(https://|windowsdefender://|ms-settings:|tel:\+\d+$)")) return false;
        try
        {
            Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), "\"" + url + "\"") { UseShellExecute = false })?.Dispose();
            return true;
        }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    private async Task<string> Uninstall(Finding f, CancellationToken ct)
    {
        var keyPath = f.FixData.ElementAtOrDefault(0) ?? "";
        var name = f.FixData.ElementAtOrDefault(1) ?? "the program";
        string command;
        using (var k = Reg.Open(keyPath))
        {
            if (k is null) return $"{name} is already gone.";
            command = Reg.Str(k, "UninstallString");
        }
        if (command.Length == 0) throw new InvalidOperationException($"{name} has no uninstaller. Remove it from Settings, Apps.");

        // Only uninstallers registered for the whole PC, in folders ordinary accounts can't change, run with Shield's
        // administrator rights. Anything else could be a program pretending to be an uninstaller.
        static string Settings() => "Remove it in Settings, Apps, Installed apps" + (OpenLink("ms-settings:appsfeatures") ? " (now open)." : ".");
        if (!keyPath.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"{name} was installed just for this user, so Shield won't run its uninstaller as administrator. {Settings()}");

        string exe, args;
        var subkey = keyPath[(keyPath.LastIndexOf('\\') + 1)..];
        var msi = Regex.Match(command, @"^\s*""?(?:[A-Z]:\\Windows\\(?:System32|SysWOW64)\\)?msiexec(?:\.exe)?""?\s+/[IX]\s*(\{[0-9A-F-]{36}\})\s*$", RegexOptions.IgnoreCase);
        if (msi.Success)
        {
            if (!string.Equals(msi.Groups[1].Value, subkey, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"{name}'s uninstall entry points at a different program. {Settings()}");
            exe = Path.Combine(Environment.SystemDirectory, "msiexec.exe");
            args = "/X" + msi.Groups[1].Value;
        }
        else
        {
            (exe, args) = CommandLine.Split(Environment.ExpandEnvironmentVariables(command), File.Exists);
            if (!Path.IsPathRooted(exe) || !File.Exists(exe) || !InProtectedFolder(exe))
                throw new InvalidOperationException($"{name}'s uninstaller isn't in Program Files. {Settings()}");
        }

        using var p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(exe) ?? Environment.SystemDirectory })
                      ?? throw new InvalidOperationException($"{name}'s uninstaller didn't start.");
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromMinutes(30));
        try { await p.WaitForExitAsync(limit.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        Record(ChangeKind.Record, $"Ran the uninstaller for {name}");
        using var still = Reg.Open(keyPath);
        return still is null ? $"{name} was uninstalled." : $"{name}'s uninstaller ran. If a window is still open, finish it there, then scan again.";
    }

    /// <summary>Program Files and Windows' own folders: only administrators can change files there.</summary>
    private static bool InProtectedFolder(string path)
    {
        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.SystemDirectory,
            Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
        };
        return folders.Where(f => f.Length > 0).Any(f => IsInside(path, f)) && !HasLink(Path.GetDirectoryName(path)!);
    }

    private string DisableStartup(Finding f)
    {
        var kind = f.FixData.ElementAtOrDefault(0);
        var location = f.FixData.ElementAtOrDefault(1) ?? "";
        var name = f.FixData.ElementAtOrDefault(2) ?? "";
        if (kind == nameof(StartupKind.RegistryValue))
        {
            using var k = Reg.Open(location, writable: true) ?? throw new InvalidOperationException("The startup entry is already gone.");
            var value = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (value is null) return "It was already gone.";
            var valueKind = k.GetValueKind(name);
            Record(ChangeKind.RegistryValue, $"Stopped \"{name}\" starting with Windows",
                new() { ["Key"] = location, ["Name"] = name, ["Type"] = valueKind.ToString(), ["Value"] = value as string ?? "" },
                value as string[]);
            k.DeleteValue(name, throwOnMissingValue: false);
            return "It won't start with Windows any more.";
        }
        if (kind == nameof(StartupKind.StartupFolderFile))
        {
            var source = Path.Combine(location, name);
            if (!IsStartupFolder(location) || HasLink(location))
                throw new InvalidOperationException("That Startup folder is a link to somewhere else, so Shield left it alone.");
            if (!File.Exists(source)) return "It was already gone.";
            var keptDir = Path.Combine(KeptFolder, "Startup", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6]);
            Directory.CreateDirectory(keptDir);
            var kept = Path.Combine(keptDir, name);
            File.Move(source, kept);
            Record(ChangeKind.MovedFile, $"Moved \"{name}\" out of the Startup folder", new() { ["From"] = source, ["To"] = kept });
            return "It won't start with Windows any more. The file is kept, so it can be put back.";
        }
        throw new InvalidOperationException("Unknown startup item.");
    }

    private string RemovePolicies(Finding f)
    {
        int removed = 0;
        foreach (var entry in f.FixData)
        {
            int bar = entry.LastIndexOf('|');
            if (bar < 0) continue;
            var key = entry[..bar];
            var name = entry[(bar + 1)..];
            using var k = Reg.Open(key, writable: true);
            var value = k?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (k is null || value is null) continue;
            Record(ChangeKind.RegistryValue, $"Removed the browser policy {Path.GetFileName(key)}\\{name}",
                new() { ["Key"] = key, ["Name"] = name, ["Type"] = k.GetValueKind(name).ToString(), ["Value"] = value as string ?? "" }, value as string[]);
            k.DeleteValue(name, throwOnMissingValue: false);
            removed++;
        }
        return removed == 0 ? "It was already gone." : "Removed. Close and reopen the browser, then reset its settings if the search engine or start page is still wrong.";
    }

    private string CleanHosts(string findingId)
    {
        var path = Collector.HostsPath;
        var bytes = File.ReadAllBytes(path);
        string text;
        try { text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes); }
        catch (DecoderFallbackException) { throw new InvalidOperationException("The hosts file uses an older text format, so Shield left it alone. Call Night Tech to have it checked."); }
        bool bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
        if (bom) text = text[1..];
        string newline = text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var lines = text.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        bool endsWithNewline = lines.Count > 0 && lines[^1].Length == 0;
        if (endsWithNewline) lines.RemoveAt(lines.Count - 1);

        // Judge the file as it is now, not as it was at scan time, and only for the finding that was ticked.
        var flagged = Rules.HostsLinesFor(findingId, lines);
        if (flagged.Count == 0) return "Nothing to change any more.";
        var backup = Path.Combine(KeptFolder, $"hosts-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}.txt");
        File.WriteAllBytes(backup, bytes);
        Record(ChangeKind.FileBackup, $"Turned off {flagged.Count} line{(flagged.Count == 1 ? "" : "s")} in the hosts file", new() { ["Path"] = path, ["Backup"] = backup });

        var result = string.Join(newline, HostsFile.CommentOut(lines, flagged, DateTime.Now)) + (endsWithNewline ? newline : "");
        var encoded = new UTF8Encoding(bom).GetPreamble().Concat(new UTF8Encoding(false).GetBytes(result)).ToArray();
        WriteHosts(path, encoded);
        FlushDns();
        return "Those lines are turned off (kept as comments).";
    }

    /// <summary>Writes the hosts file through a temporary file in the same folder, so it's never left half-written.</summary>
    private static void WriteHosts(string path, byte[] bytes)
    {
        var attrs = File.GetAttributes(path);
        var tmp = path + ".nightech-shield.tmp";
        File.WriteAllBytes(tmp, bytes);
        if ((attrs & FileAttributes.ReadOnly) != 0) File.SetAttributes(path, attrs & ~FileAttributes.ReadOnly);
        File.Move(tmp, path, overwrite: true);
        if ((attrs & FileAttributes.ReadOnly) != 0) File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
    }

    private static void FlushDns()
    {
        try { using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "ipconfig.exe"), "/flushdns") { UseShellExecute = false, CreateNoWindow = true }); p?.WaitForExit(10000); }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { }
    }

    private string TurnOffProxy()
    {
        var key = Reg.User(_user.Sid, Collector.InternetSettingsPath);
        using var k = Reg.Open(key, writable: true) ?? throw new InvalidOperationException("The proxy settings couldn't be opened.");
        var enable = k.GetValue("ProxyEnable");
        var auto = k.GetValue("AutoConfigURL") as string;
        Record(ChangeKind.RegistryValue, "Turned off the web proxy",
            new() { ["Key"] = key, ["Name"] = "ProxyEnable", ["Type"] = nameof(RegistryValueKind.DWord), ["Value"] = (enable is int i ? i : 0).ToString() });
        if (auto is not null)
            Record(ChangeKind.RegistryValue, "Removed the proxy setup script",
                new() { ["Key"] = key, ["Name"] = "AutoConfigURL", ["Type"] = nameof(RegistryValueKind.String), ["Value"] = auto });
        k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        k.DeleteValue("AutoConfigURL", throwOnMissingValue: false);

        // Windows keeps the same settings in a binary value too, and copies it back over the ones above.
        // Byte 8 holds the flags: 0x02 = use a proxy server, 0x04 = use a setup script.
        var connKey = key + "\\Connections";
        using (var conn = Reg.Open(connKey, writable: true))
        {
            if (conn?.GetValue("DefaultConnectionSettings") is byte[] blob && blob.Length > 8 && (blob[8] & 0x06) != 0)
            {
                Record(ChangeKind.RegistryValue, "Turned off the proxy in Windows' connection settings",
                    new() { ["Key"] = connKey, ["Name"] = "DefaultConnectionSettings", ["Type"] = nameof(RegistryValueKind.Binary), ["Value"] = Convert.ToBase64String(blob) });
                var changed = (byte[])blob.Clone();
                changed[8] = (byte)(changed[8] & ~0x06);
                uint counter = BitConverter.ToUInt32(changed, 4) + 1;
                BitConverter.GetBytes(counter).CopyTo(changed, 4);
                conn.SetValue("DefaultConnectionSettings", changed, RegistryValueKind.Binary);
            }
        }
        RefreshInternetSettings();
        return "The proxy is off. Close and reopen the browser, then check web pages load.";
    }

    private static void RefreshInternetSettings()
    {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);   // INTERNET_OPTION_SETTINGS_CHANGED
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);   // INTERNET_OPTION_REFRESH
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int option, IntPtr buffer, int length);

    // ---------------- Undo ----------------

    /// <summary>Puts one change back the way it was.</summary>
    public string Undo(Change c)
    {
        if (!c.CanUndo) return "That can't be undone from Shield.";
        switch (c.Kind)
        {
            case ChangeKind.RegistryValue:
            {
                var location = c.Get("Key");
                if (!IsAllowedUndoKey(location, _user.Sid)) throw new InvalidOperationException("That change points somewhere Shield doesn't change, so it wasn't put back.");
                var (root, path) = Reg.Split(location);
                using var k = root?.CreateSubKey(path, writable: true) ?? throw new InvalidOperationException("The registry key couldn't be opened.");
                var kind = Enum.TryParse<RegistryValueKind>(c.Get("Type"), out var vk) ? vk : RegistryValueKind.String;
                object value = kind switch
                {
                    RegistryValueKind.DWord => int.TryParse(c.Get("Value"), out var n) ? n : 0,
                    RegistryValueKind.Binary => Convert.FromBase64String(c.Get("Value")),
                    RegistryValueKind.MultiString => c.Lines.ToArray(),
                    RegistryValueKind.ExpandString or RegistryValueKind.String => c.Get("Value"),
                    _ => throw new InvalidOperationException("That kind of value can't be put back."),
                };
                k.SetValue(c.Get("Name"), value, kind);
                if (location.EndsWith("Internet Settings", StringComparison.OrdinalIgnoreCase)) RefreshInternetSettings();
                break;
            }
            case ChangeKind.MovedFile:
            {
                var from = c.Get("To");
                var to = c.Get("From");
                var toDir = Path.GetDirectoryName(Path.GetFullPath(to)) ?? "";
                if (!IsInside(from, KeptFolder) || !IsStartupFolder(toDir) || HasLink(toDir) || !string.Equals(Path.GetFileName(to), Path.GetFileName(from), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("That change points somewhere Shield doesn't change, so it wasn't put back.");
                if (!File.Exists(from)) throw new InvalidOperationException("The kept file is gone, so it can't be put back.");
                if (File.Exists(to)) throw new InvalidOperationException("A file with that name is back in the Startup folder already.");
                File.Move(from, to);
                break;
            }
            case ChangeKind.FileBackup:
            {
                var backup = c.Get("Backup");
                var hosts = Collector.HostsPath;
                if (!IsInside(backup, KeptFolder) || !string.Equals(Path.GetFullPath(c.Get("Path")), Path.GetFullPath(hosts), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("That change points somewhere Shield doesn't change, so it wasn't put back.");
                if (!File.Exists(backup)) throw new InvalidOperationException("The kept copy is gone, so it can't be put back.");
                WriteHosts(hosts, File.ReadAllBytes(backup));
                FlushDns();
                break;
            }
        }
        c.UndoneUtc = DateTime.UtcNow;
        Save();
        return "Put back.";
    }

    /// <summary>Undo only ever writes to the places Shield's fixes change.</summary>
    private static bool IsAllowedUndoKey(string location, string sid)
    {
        var path = Reg.Split(location).Path;
        if (location.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
        {
            // Only the signed-in person's own settings.
            if (!path.StartsWith(sid + "\\", StringComparison.OrdinalIgnoreCase)) return false;
            path = path[(sid.Length + 1)..];
        }
        return path.Equals(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)
               || path.Equals(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", StringComparison.OrdinalIgnoreCase)
               || path.Equals(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", StringComparison.OrdinalIgnoreCase)
               || path.Equals(Collector.InternetSettingsPath, StringComparison.OrdinalIgnoreCase)
               || path.Equals(Collector.InternetSettingsPath + "\\Connections", StringComparison.OrdinalIgnoreCase)
               || Collector.ChromiumBrowsers.Any(b => b.Policy.Length > 0 && (path.Equals(b.Policy, StringComparison.OrdinalIgnoreCase)
                                                                             || path.StartsWith(b.Policy + "\\", StringComparison.OrdinalIgnoreCase)));
    }

    private bool IsStartupFolder(string dir) =>
        string.Equals(dir, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), StringComparison.OrdinalIgnoreCase)
        || string.Equals(dir, Path.Combine(_user.Roaming, @"Microsoft\Windows\Start Menu\Programs\Startup"), StringComparison.OrdinalIgnoreCase);
}
