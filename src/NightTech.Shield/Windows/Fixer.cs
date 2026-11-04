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
        var dir = new DirectoryInfo(DataFolder);
        if (!dir.Exists) dir.Create();
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        dir.SetAccessControl(sec);
        Directory.CreateDirectory(KeptFolder);
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
                if (r.ExitCode != 0)
                {
                    OpenLink("windowsdefender://threatsettings");
                    throw new InvalidOperationException("Windows didn't allow it (a setting or another program may be blocking it). Windows Security is open: turn on Real-time protection there.");
                }
                Record(ChangeKind.Record, "Turned on Defender's real-time protection");
                return "Real-time protection is on.";
            }
            case FixKind.OpenWindowsSecurity:
                OpenLink("windowsdefender://threat");
                return "Windows Security is open.";
            case FixKind.Uninstall:
                return await Uninstall(f);
            case FixKind.DisableStartup:
                return DisableStartup(f);
            case FixKind.RemovePolicy:
                return RemovePolicies(f);
            case FixKind.CleanHosts:
                return CleanHosts();
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

    /// <summary>Opens a web or Windows link without administrator rights, through the signed-in person's own Explorer.</summary>
    public static void OpenLink(string url)
    {
        if (!Regex.IsMatch(url, @"^(https://|windowsdefender://|ms-settings:|tel:\+\d+$)")) return;
        Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), "\"" + url + "\"") { UseShellExecute = false });
    }

    private async Task<string> Uninstall(Finding f)
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

        string exe, args;
        var msi = Regex.Match(command, @"msiexec(\.exe)?\s+/[IX]\s*(\{[0-9A-F-]{36}\})", RegexOptions.IgnoreCase);
        if (msi.Success)
        {
            exe = Path.Combine(Environment.SystemDirectory, "msiexec.exe");
            args = "/X" + msi.Groups[2].Value;
        }
        else
        {
            (exe, args) = CommandLine.Split(_user.Expand(command), File.Exists);
            if (!Path.IsPathRooted(exe) || !File.Exists(exe))
                throw new InvalidOperationException($"{name}'s uninstaller wasn't found. Remove it from Settings, Apps.");
        }

        using var p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(exe) ?? Environment.SystemDirectory })
                      ?? throw new InvalidOperationException($"{name}'s uninstaller didn't start.");
        using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(30));
        try { await p.WaitForExitAsync(limit.Token); } catch (OperationCanceledException) { }
        Record(ChangeKind.Record, $"Ran the uninstaller for {name}");
        using var still = Reg.Open(keyPath);
        return still is null ? $"{name} was uninstalled." : $"{name}'s uninstaller ran. If a window is still open, finish it there, then scan again.";
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

    private string CleanHosts()
    {
        var path = Collector.HostsPath;
        var bytes = File.ReadAllBytes(path);
        var lines = File.ReadAllLines(path).ToList();
        // Judge the file as it is now, not as it was at scan time.
        var flagged = Rules.Evaluate(new ScanFacts { Defender = new DefenderState { Present = true, AntivirusEnabled = true }, SecurityCenter = { new AvProduct { Name = "x", Enabled = true, UpToDate = true } }, Hosts = lines }, DateTime.UtcNow)
            .Where(x => x.Fix == FixKind.CleanHosts).SelectMany(x => x.FixData).Select(int.Parse).Distinct().ToList();
        if (flagged.Count == 0) return "Nothing to change any more.";
        var backup = Path.Combine(KeptFolder, $"hosts-{DateTime.UtcNow:yyyyMMdd-HHmmss}.txt");
        File.WriteAllBytes(backup, bytes);
        Record(ChangeKind.FileBackup, $"Turned off {flagged.Count} line{(flagged.Count == 1 ? "" : "s")} in the hosts file", new() { ["Path"] = path, ["Backup"] = backup });
        var attrs = File.GetAttributes(path);
        if ((attrs & FileAttributes.ReadOnly) != 0) File.SetAttributes(path, attrs & ~FileAttributes.ReadOnly);
        File.WriteAllLines(path, HostsFile.CommentOut(lines, flagged, DateTime.Now), new UTF8Encoding(false));
        if ((attrs & FileAttributes.ReadOnly) != 0) File.SetAttributes(path, attrs);
        FlushDns();
        return "Those lines are turned off (kept as comments).";
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
            new() { ["Key"] = key, ["Name"] = "ProxyEnable", ["Type"] = nameof(RegistryValueKind.DWord), ["Value"] = (enable is int i ? i : 0).ToString(), ["Restore"] = "set" });
        if (auto is not null)
            Record(ChangeKind.RegistryValue, "Removed the proxy setup script",
                new() { ["Key"] = key, ["Name"] = "AutoConfigURL", ["Type"] = nameof(RegistryValueKind.String), ["Value"] = auto });
        k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        k.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
        RefreshInternetSettings();
        return "The proxy is off. Open web pages again to check they load.";
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
                if (!IsAllowedUndoKey(location)) throw new InvalidOperationException("That change points somewhere Shield doesn't change, so it wasn't put back.");
                var (root, path) = Reg.Split(location);
                using var k = root?.CreateSubKey(path, writable: true) ?? throw new InvalidOperationException("The registry key couldn't be opened.");
                var kind = Enum.TryParse<RegistryValueKind>(c.Get("Type"), out var vk) ? vk : RegistryValueKind.String;
                object value = kind switch
                {
                    RegistryValueKind.DWord => int.TryParse(c.Get("Value"), out var n) ? n : 0,
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
                if (!from.StartsWith(KeptFolder + "\\", StringComparison.OrdinalIgnoreCase) || !IsStartupFolder(Path.GetDirectoryName(to) ?? ""))
                    throw new InvalidOperationException("That change points somewhere Shield doesn't change, so it wasn't put back.");
                if (!File.Exists(from)) throw new InvalidOperationException("The kept file is gone, so it can't be put back.");
                if (File.Exists(to)) throw new InvalidOperationException("A file with that name is back in the Startup folder already.");
                File.Move(from, to);
                break;
            }
            case ChangeKind.FileBackup:
            {
                var backup = c.Get("Backup");
                if (!backup.StartsWith(KeptFolder + "\\", StringComparison.OrdinalIgnoreCase) || !string.Equals(c.Get("Path"), Collector.HostsPath, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("That change points somewhere Shield doesn't change, so it wasn't put back.");
                var attrs = File.GetAttributes(Collector.HostsPath);
                if ((attrs & FileAttributes.ReadOnly) != 0) File.SetAttributes(Collector.HostsPath, attrs & ~FileAttributes.ReadOnly);
                File.Copy(backup, Collector.HostsPath, overwrite: true);
                if ((attrs & FileAttributes.ReadOnly) != 0) File.SetAttributes(Collector.HostsPath, attrs);
                FlushDns();
                break;
            }
        }
        c.UndoneUtc = DateTime.UtcNow;
        Save();
        return "Put back.";
    }

    /// <summary>Undo only ever writes to the places Shield's fixes change.</summary>
    private static bool IsAllowedUndoKey(string location)
    {
        var path = Reg.Split(location).Path;
        if (location.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
            path = path.Contains('\\') ? path[(path.IndexOf('\\') + 1)..] : "";
        return path.Equals(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase)
               || path.Equals(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", StringComparison.OrdinalIgnoreCase)
               || path.Equals(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", StringComparison.OrdinalIgnoreCase)
               || path.Equals(Collector.InternetSettingsPath, StringComparison.OrdinalIgnoreCase)
               || Collector.ChromiumBrowsers.Any(b => b.Policy.Length > 0 && (path.Equals(b.Policy, StringComparison.OrdinalIgnoreCase)
                                                                             || path.StartsWith(b.Policy + "\\", StringComparison.OrdinalIgnoreCase)));
    }

    private bool IsStartupFolder(string dir) =>
        string.Equals(dir, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), StringComparison.OrdinalIgnoreCase)
        || string.Equals(dir, Path.Combine(_user.Roaming, @"Microsoft\Windows\Start Menu\Programs\Startup"), StringComparison.OrdinalIgnoreCase);
}
