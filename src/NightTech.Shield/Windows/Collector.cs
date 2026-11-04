using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using NightTech.Shield.Core;

namespace NightTech.Shield.Windows;

/// <summary>Reads everything a scan looks at. Only reads: nothing on the PC is changed here.</summary>
public static class Collector
{
    public static ScanFacts Collect(TargetUser user, IProgress<string> progress)
    {
        var f = new ScanFacts { TakenUtc = DateTime.UtcNow, Computer = Environment.MachineName, CheckedUser = user.Name };
        Step(f, progress, "Checking Windows", WindowsInfo);
        Step(f, progress, "Checking Microsoft Defender", Defender);
        Step(f, progress, "Checking what Defender has found", Threats);
        Step(f, progress, "Checking installed programs", x => Programs(x, user));
        Step(f, progress, "Checking what starts with Windows", x => Startup(x, user));
        Step(f, progress, "Checking browsers", x => Browsers(x, user));
        Step(f, progress, "Checking network settings", x => Network(x, user));
        return f;
    }

    private static void Step(ScanFacts f, IProgress<string> progress, string label, Action<ScanFacts> check)
    {
        progress.Report(label + "...");
        try { check(f); }
        catch (Exception e) when (e is ManagementException or COMException or IOException or UnauthorizedAccessException
                                      or System.Security.SecurityException or InvalidOperationException or ArgumentException)
        {
            f.Notes.Add($"{label}: this check didn't finish ({e.Message.Trim()}).");
        }
    }

    private static List<ManagementBaseObject> Query(string scope, string wql)
    {
        using var searcher = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql),
            new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(30), ReturnImmediately = false });
        return searcher.Get().Cast<ManagementBaseObject>().ToList();
    }

    private static object? Get(ManagementBaseObject o, string p) { try { return o[p]; } catch (ManagementException) { return null; } }
    private static string Str(ManagementBaseObject o, string p) => Get(o, p)?.ToString()?.Trim() ?? "";
    private static bool? Bool(ManagementBaseObject o, string p) => Get(o, p) is bool b ? b : null;
    private static long? Num(ManagementBaseObject o, string p) => Get(o, p) switch
    {
        null => null,
        IConvertible c => c.ToInt64(CultureInfo.InvariantCulture),
        _ => null,
    };

    /// <summary>Defender reports "never" as the largest number it can hold.</summary>
    private static int? Age(ManagementBaseObject o, string p) => Num(o, p) is long n ? (int)Math.Min(n, 65535) : null;

    // ---------------- Windows ----------------

    private static void WindowsInfo(ScanFacts f)
    {
        using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        if (k is not null)
        {
            var name = Reg.Str(k, "ProductName");
            int.TryParse(Reg.Str(k, "CurrentBuildNumber"), out int build);
            if (build >= 22000) name = name.Replace("Windows 10", "Windows 11", StringComparison.Ordinal);
            var version = Reg.Str(k, "DisplayVersion");
            f.Windows = $"{name}{(version.Length > 0 ? " " + version : "")} (build {build})";
        }
        bool? domain = null;
        foreach (var o in Query(@"root\cimv2", "SELECT PartOfDomain FROM Win32_ComputerSystem")) domain = Bool(o, "PartOfDomain");
        using var entra = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo");
        bool entraJoined = entra?.GetSubKeyNames().Length > 0;
        f.DomainJoined = domain == true || entraJoined || MdmEnrolled() || BrowserCloudManaged() ? true : domain;
    }

    /// <summary>Enrolled in Intune or another device-management service (work or school PC).</summary>
    private static bool MdmEnrolled()
    {
        using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Enrollments");
        if (k is null) return false;
        foreach (var sub in k.GetSubKeyNames())
        {
            using var e = k.OpenSubKey(sub);
            if (e is not null && Reg.Str(e, "ProviderID").Length > 0 && Reg.Str(e, "UPN").Length > 0) return true;
        }
        return false;
    }

    /// <summary>Chrome or Edge enrolled in their company cloud management.</summary>
    private static bool BrowserCloudManaged()
    {
        using var chrome = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Google\Chrome");
        using var edge = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge");
        return chrome?.GetValue("CloudManagementEnrollmentToken") is string c && c.Length > 0
               || edge?.GetValue("CloudManagementEnrollmentToken") is string e && e.Length > 0;
    }

    // ---------------- Defender ----------------

    private static void Defender(ScanFacts f)
    {
        try
        {
            foreach (var o in Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
                if (Num(o, "productState") is long state)
                    f.SecurityCenter.Add(AvProduct.FromProductState(Str(o, "displayName"), (uint)state));
        }
        catch (ManagementException) { f.Notes.Add("Windows Security Center didn't answer, so other antivirus programs couldn't be listed."); }

        try
        {
            foreach (var o in Query(@"root\Microsoft\Windows\Defender",
                         "SELECT AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureAge, QuickScanAge, FullScanAge, AMRunningMode, AntivirusSignatureVersion FROM MSFT_MpComputerStatus"))
            {
                var d = f.Defender;
                d.Present = Bool(o, "AMServiceEnabled") != false;
                d.AntivirusEnabled = Bool(o, "AntivirusEnabled");
                d.RealTime = Bool(o, "RealTimeProtectionEnabled");
                d.TamperProtected = Bool(o, "IsTamperProtected");
                d.SignatureAgeDays = Age(o, "AntivirusSignatureAge");
                d.QuickScanAgeDays = Age(o, "QuickScanAge");
                d.FullScanAgeDays = Age(o, "FullScanAge");
                d.RunningMode = Str(o, "AMRunningMode");
                d.SignatureVersion = Str(o, "AntivirusSignatureVersion");
            }
        }
        catch (ManagementException e) when ((uint)e.ErrorCode is 0x8004100E or 0x80041010 or 0x80041002)
        {
            // Defender isn't installed (Windows Server without it) or has been removed.
        }
    }

    private static void Threats(ScanFacts f)
    {
        if (!f.Defender.Present) return;
        var names = new Dictionary<string, (string Name, string Severity, bool? Active)>();
        foreach (var o in Query(@"root\Microsoft\Windows\Defender", "SELECT ThreatID, ThreatName, SeverityID, IsActive FROM MSFT_MpThreat"))
            names[Str(o, "ThreatID")] = (Str(o, "ThreatName"), ThreatRecord.SeverityName((int)(Num(o, "SeverityID") ?? 0)), Bool(o, "IsActive"));

        var latest = new Dictionary<string, ThreatRecord>();
        foreach (var o in Query(@"root\Microsoft\Windows\Defender", "SELECT ThreatID, ThreatStatusID, InitialDetectionTime, Resources FROM MSFT_MpThreatDetection"))
        {
            var id = Str(o, "ThreatID");
            var when = Get(o, "InitialDetectionTime") is string dmtf && dmtf.Length > 0 ? ManagementDateTimeConverter.ToDateTime(dmtf).ToUniversalTime() : (DateTime?)null;
            var status = ThreatRecord.FromStatusId((int)(Num(o, "ThreatStatusID") ?? 0));
            var t = new ThreatRecord
            {
                ThreatId = id, Status = status, DetectedUtc = when,
                Resources = Get(o, "Resources") is string[] r ? r.ToList() : new List<string>(),
            };
            if (names.TryGetValue(id, out var n))
            {
                t.Name = n.Name;
                t.Severity = n.Severity;
                // Defender says a detection is "Detected" until it's dealt with; IsActive is the better word on whether it still is.
                if (status == ThreatStatus.Active && n.Active == false) t.Status = ThreatStatus.Unknown;
            }
            if (t.Name.Length == 0) t.Name = "Unknown threat " + id;
            if (!latest.TryGetValue(id, out var prev) || (t.DetectedUtc ?? DateTime.MinValue) >= (prev.DetectedUtc ?? DateTime.MinValue))
                latest[id] = t;
        }
        f.Threats = latest.Values.OrderByDescending(t => t.DetectedUtc).ToList();
    }

    // ---------------- Programs ----------------

    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    private static void Programs(ScanFacts f, TargetUser user)
    {
        foreach (var root in new[] { Reg.Machine(UninstallPath), Reg.Machine(UninstallPath, wow32: true), Reg.User(user.Sid, UninstallPath) })
        {
            using var k = Reg.Open(root);
            if (k is null) continue;
            foreach (var sub in k.GetSubKeyNames())
            {
                using var p = k.OpenSubKey(sub);
                if (p is null) continue;
                var name = Reg.Str(p, "DisplayName");
                if (name.Length == 0 || Reg.Int(p, "SystemComponent") == 1 || Reg.Str(p, "ParentKeyName").Length > 0) continue;
                DateTime? installed = DateTime.TryParseExact(Reg.Str(p, "InstallDate"), "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;
                f.Programs.Add(new InstalledProgram
                {
                    Name = name, Publisher = Reg.Str(p, "Publisher"), Version = Reg.Str(p, "DisplayVersion"),
                    UninstallCommand = Reg.Str(p, "UninstallString"), RegistryKey = root + "\\" + sub, InstalledOn = installed,
                });
            }
        }
        f.Programs = f.Programs.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ---------------- Startup ----------------

    private const string RunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOncePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string PolicyRunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
    private const string ApprovedPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

    private static void Startup(ScanFacts f, TargetUser user)
    {
        var keys = new List<(string Location, string Where, string Approved)>
        {
            (Reg.Machine(RunPath), "Run, all users", Reg.Machine(ApprovedPath + "\\Run")),
            (Reg.Machine(RunPath, true), "Run, all users (32-bit)", Reg.Machine(ApprovedPath + "\\Run32")),
            (Reg.Machine(RunOncePath), "Run once, all users", ""),
            (Reg.Machine(RunOncePath, true), "Run once, all users (32-bit)", ""),
            (Reg.Machine(PolicyRunPath), "Run by policy, all users", ""),
            (Reg.User(user.Sid, RunPath), "Run, this user", Reg.User(user.Sid, ApprovedPath + "\\Run")),
            (Reg.User(user.Sid, RunOncePath), "Run once, this user", ""),
            (Reg.User(user.Sid, PolicyRunPath), "Run by policy, this user", ""),
        };
        foreach (var (location, where, approved) in keys)
        {
            using var k = Reg.Open(location);
            if (k is null) continue;
            foreach (var name in k.GetValueNames())
            {
                if (name.Length == 0 || IsTurnedOff(approved, name)) continue;
                var command = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString() ?? "";
                if (command.Trim().Length == 0) continue;
                f.Startup.Add(Item(StartupKind.RegistryValue, where, location, name, command, user));
            }
        }

        var folders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Startup folder, all users", Reg.Machine(ApprovedPath + "\\StartupFolder")),
            (Path.Combine(user.Roaming, @"Microsoft\Windows\Start Menu\Programs\Startup"), "Startup folder, this user", Reg.User(user.Sid, ApprovedPath + "\\StartupFolder")),
        };
        foreach (var (folder, where, approved) in folders)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
            foreach (var file in Directory.GetFiles(folder))
            {
                var name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) || IsTurnedOff(approved, name)) continue;
                var command = name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? Shortcut(file) ?? file : "\"" + file + "\"";
                f.Startup.Add(Item(StartupKind.StartupFolderFile, where, folder, name, command, user));
            }
        }
    }

    /// <summary>Items turned off in Task Manager are marked in StartupApproved (an odd first byte means off).</summary>
    private static bool IsTurnedOff(string approvedKey, string name)
    {
        if (approvedKey.Length == 0) return false;
        using var k = Reg.Open(approvedKey);
        return k?.GetValue(name) is byte[] b && b.Length > 0 && (b[0] & 1) == 1;
    }

    private static StartupItem Item(StartupKind kind, string where, string location, string name, string command, TargetUser user)
    {
        var expanded = user.Expand(command);
        var (program, _) = CommandLine.Split(expanded, File.Exists);
        program = Resolve(program);
        bool? exists = program.Length == 0 ? null : File.Exists(program);
        var item = new StartupItem { Kind = kind, Where = where, Location = location, Name = name, Command = expanded, Program = program, ProgramExists = exists };
        if (exists == true)
        {
            (item.Signed, item.Signer) = Signature.Check(program);
            // Windows' own files are signed through catalogs, which this check doesn't read; only administrators can change these folders.
            if (item.Signed != true && IsWindowsOwnFile(program)) item.Signed = true;
        }
        return item;
    }

    private static bool IsWindowsOwnFile(string path)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? "";
        return string.Equals(dir, windows, StringComparison.OrdinalIgnoreCase)
               || dir.StartsWith(Path.Combine(windows, "System32"), StringComparison.OrdinalIgnoreCase)
               || dir.StartsWith(Path.Combine(windows, "SysWOW64"), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>"rundll32.exe" becomes C:\Windows\System32\rundll32.exe, the way Windows finds it.</summary>
    private static string Resolve(string program)
    {
        if (program.Length == 0 || Path.IsPathRooted(program)) return program;
        var candidates = new List<string> { Environment.SystemDirectory, Environment.GetFolderPath(Environment.SpecialFolder.Windows) };
        candidates.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries));
        foreach (var dir in candidates)
        {
            foreach (var name in program.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? new[] { program } : new[] { program + ".exe", program })
            {
                try
                {
                    var full = Path.Combine(dir.Trim(), name);
                    if (File.Exists(full)) return full;
                }
                catch (ArgumentException) { }
            }
        }
        return program;
    }

    /// <summary>A shortcut's target and arguments, read with Windows' own shortcut reader.</summary>
    private static string? Shortcut(string lnk)
    {
        var type = Type.GetTypeFromProgID("WScript.Shell");
        if (type is null) return null;
        object? shell = null, link = null;
        try
        {
            shell = Activator.CreateInstance(type);
            link = type.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, new object[] { lnk });
            if (link is null) return null;
            var lt = link.GetType();
            var target = lt.InvokeMember("TargetPath", System.Reflection.BindingFlags.GetProperty, null, link, null) as string ?? "";
            var args = lt.InvokeMember("Arguments", System.Reflection.BindingFlags.GetProperty, null, link, null) as string ?? "";
            return target.Length == 0 ? null : $"\"{target}\"{(args.Length > 0 ? " " + args : "")}";
        }
        catch (Exception e) when (e is COMException or System.Reflection.TargetInvocationException or MissingMethodException) { return null; }
        finally
        {
            if (link is not null && Marshal.IsComObject(link)) Marshal.FinalReleaseComObject(link);
            if (shell is not null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
        }
    }

    // ---------------- Browsers ----------------

    public static readonly (string Name, string Folder, string Policy)[] ChromiumBrowsers =
    {
        ("Chrome", @"Google\Chrome\User Data", @"SOFTWARE\Policies\Google\Chrome"),
        ("Edge", @"Microsoft\Edge\User Data", @"SOFTWARE\Policies\Microsoft\Edge"),
        ("Brave", @"BraveSoftware\Brave-Browser\User Data", @"SOFTWARE\Policies\BraveSoftware\Brave"),
        ("Vivaldi", @"Vivaldi\User Data", ""),
    };

    private static readonly string[] PolicyValues = { "DefaultSearchProviderSearchURL", "HomepageLocation", "NewTabPageLocation" };
    private static readonly string[] PolicyLists = { "ExtensionInstallForcelist", "RestoreOnStartupURLs" };

    private static void Browsers(ScanFacts f, TargetUser user)
    {
        foreach (var (name, folder, policy) in ChromiumBrowsers)
        {
            f.Browsers.AddRange(BrowserReader.Chromium(Path.Combine(user.Local, folder), name, f.Notes));
            if (policy.Length == 0) continue;
            foreach (var root in new[] { Reg.Machine(policy), Reg.User(user.Sid, policy) })
            {
                using (var k = Reg.Open(root))
                    if (k is not null)
                        foreach (var v in PolicyValues)
                            if (Reg.Str(k, v) is { Length: > 0 } value)
                                f.Policies.Add(new BrowserPolicy { Browser = name, Key = root, ValueName = v, Value = value, Setting = v });
                foreach (var list in PolicyLists)
                {
                    using var lk = Reg.Open(root + "\\" + list);
                    if (lk is null) continue;
                    foreach (var v in lk.GetValueNames())
                        if (Reg.Str(lk, v) is { Length: > 0 } value)
                            f.Policies.Add(new BrowserPolicy { Browser = name, Key = root + "\\" + list, ValueName = v, Value = value, Setting = list });
                }
            }
        }
        f.Browsers.AddRange(BrowserReader.Firefox(Path.Combine(user.Roaming, @"Mozilla\Firefox\Profiles"), f.Notes));
    }

    // ---------------- Network ----------------

    /// <summary>The hosts file, wherever Windows has been told to keep it (DataBasePath), normally System32\drivers\etc.</summary>
    public static string HostsPath
    {
        get
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
            var db = k is null ? "" : Environment.ExpandEnvironmentVariables(Reg.Str(k, "DataBasePath"));
            return Path.Combine(db.Length > 0 && Path.IsPathRooted(db) ? db : Path.Combine(Environment.SystemDirectory, @"drivers\etc"), "hosts");
        }
    }
    public const string InternetSettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    private static void Network(ScanFacts f, TargetUser user)
    {
        if (File.Exists(HostsPath)) f.Hosts = File.ReadAllLines(HostsPath).ToList();
        var key = Reg.User(user.Sid, InternetSettingsPath);
        using var k = Reg.Open(key);
        if (k is null) return;
        f.Proxy = new ProxyState
        {
            Key = key,
            Enabled = Reg.Int(k, "ProxyEnable") == 1,
            Server = Reg.Str(k, "ProxyServer"),
            AutoConfigUrl = Reg.Str(k, "AutoConfigURL"),
        };
    }
}
