using System.Net;

namespace NightTech.Shield.Core;

/// <summary>
/// Turns what a scan read into plain-language findings, each with the fix Shield can make.
/// Findings describe what was seen at the time of the scan; they're not a guarantee the PC is free of malware.
/// </summary>
public static class Rules
{
    public const int DefinitionsWarnDays = 3, DefinitionsRiskDays = 7;
    public const int QuickScanWarnDays = 14;
    public const int RecentThreatDays = 30;

    public static List<Finding> Evaluate(ScanFacts f, DateTime nowUtc)
    {
        var list = new List<Finding>();
        Antivirus(f, list);
        Threats(f, nowUtc, list);
        Programs(f, list);
        Startup(f, list);
        Browsers(f, list);
        Policies(f, list);
        Hosts(f, list);
        Proxy(f, list);
        // Most serious first, then by area, so the person sees what matters at the top.
        return list.OrderByDescending(x => x.Severity).ThenBy(x => AreaOrder(x.Area)).ThenBy(x => x.Title, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static int AreaOrder(string area) => area switch
    {
        "Threats" => 0, "Antivirus" => 1, "Startup" => 2, "Programs" => 3, "Browsers" => 4, "Network" => 5, _ => 6,
    };

    private static Finding Add(List<Finding> list, string id, string area, Severity s, string title, string detail,
        FixKind fix = FixKind.None, string fixLabel = "", bool recommended = false, params string[] data)
    {
        var x = new Finding
        {
            Id = id, Area = area, Severity = s, Title = title, Detail = detail, Fix = fix, FixLabel = fix == FixKind.None ? "" : fixLabel,
            Recommended = fix != FixKind.None && recommended, FixData = data.ToList(),
        };
        list.Add(x);
        return x;
    }

    // ---------------- Antivirus ----------------

    private static void Antivirus(ScanFacts f, List<Finding> list)
    {
        const string A = "Antivirus";
        var d = f.Defender;
        var others = f.SecurityCenter.Where(p => !p.IsDefender).ToList();
        var othersOn = others.Where(p => p.Enabled).ToList();
        bool defenderInCharge = d.Present && !d.IsPassive && d.AntivirusEnabled != false && othersOn.Count == 0;

        if (othersOn.Count > 1)
            Add(list, "av:several", A, Severity.Warning, "More than one antivirus is turned on",
                $"{string.Join(" and ", othersOn.Select(p => p.Name))} are all running. Two antivirus programs slow the PC down and can block each other. Keep one and uninstall the rest (Microsoft Defender, built into Windows, is enough for most people).");

        if (othersOn.Count > 0)
        {
            foreach (var p in othersOn.Where(p => !p.UpToDate))
                Add(list, "av:outdated:" + p.Name, A, Severity.Risk, $"{p.Name} is out of date",
                    $"Windows says {p.Name} isn't up to date. An expired subscription is the usual reason. Renew it, or uninstall it so Microsoft Defender takes over.",
                    FixKind.OpenWindowsSecurity, "Open Windows Security");
            Add(list, "av:other", A, Severity.Info, $"{string.Join(", ", othersOn.Select(p => p.Name))} protects this PC",
                "Another antivirus is in charge, so Microsoft Defender stands back. Shield still runs its own checks below.");
            return;
        }

        if (!d.Present)
        {
            if (f.SecurityCenter.Count == 0)
                Add(list, "av:none", A, Severity.Risk, "No antivirus answered",
                    "Neither Microsoft Defender nor any other antivirus answered. Something may have turned them off, which is what some malware does.",
                    FixKind.OpenWindowsSecurity, "Open Windows Security", true);
            else
                Add(list, "av:off", A, Severity.Risk, "No antivirus is turned on",
                    $"Windows lists {string.Join(", ", f.SecurityCenter.Select(p => p.Name))}, but none of them is on.",
                    FixKind.OpenWindowsSecurity, "Open Windows Security", true);
            return;
        }

        if (d.AntivirusEnabled == false || d.IsPassive)
        {
            Add(list, "defender:off", A, Severity.Risk, "Microsoft Defender is turned off",
                "No antivirus is protecting this PC. If another antivirus was uninstalled, Defender should have come back on by itself.",
                FixKind.OpenWindowsSecurity, "Open Windows Security", true);
            return;
        }

        if (d.RealTime == false)
            Add(list, "defender:realtime", A, Severity.Risk, "Real-time protection is off",
                "Defender only checks files when asked, so new malware can run without being stopped.",
                FixKind.TurnOnRealTime, "Turn real-time protection on", true);

        if (d.SignatureAgeDays is int age && age >= DefinitionsWarnDays)
            Add(list, "defender:definitions", A, age >= DefinitionsRiskDays ? Severity.Risk : Severity.Warning, "Defender's virus definitions are out of date",
                $"They were last updated {Days(age)} ago. Defender can't recognize malware that came out since then.",
                FixKind.UpdateDefinitions, "Update definitions now", true);

        if (defenderInCharge && d.QuickScanAgeDays is int qs && qs >= QuickScanWarnDays)
            Add(list, "defender:scan", A, Severity.Warning, "Defender hasn't scanned this PC lately",
                qs > 3650 ? "Defender has never finished a scan on this PC." : $"The last quick scan was {Days(qs)} ago. Windows normally runs one every day or two when the PC is idle.",
                FixKind.QuickScan, "Run a quick scan", true);

        if (d.TamperProtected == false)
            Add(list, "defender:tamper", A, Severity.Warning, "Tamper Protection is off",
                "Tamper Protection stops programs from switching Defender off. Only you can turn it on: Windows Security, Virus & threat protection settings, Tamper Protection.",
                FixKind.OpenWindowsSecurity, "Open Windows Security");
    }

    private static string Days(int n) => n == 1 ? "1 day" : $"{n} days";

    // ---------------- Threats ----------------

    private static void Threats(ScanFacts f, DateTime now, List<Finding> list)
    {
        const string A = "Threats";
        var active = f.Threats.Where(t => t.Status is ThreatStatus.Active or ThreatStatus.Failed).ToList();
        if (active.Count > 0)
        {
            foreach (var t in active)
                Add(list, "threat:" + t.ThreatId, A, Severity.Risk, $"Malware found: {t.Name}",
                    (t.Status == ThreatStatus.Failed ? "Defender found it but couldn't remove it. " : "Defender found it and it hasn't been removed yet. ")
                    + Where(t) + (t.Severity is "High" or "Severe" ? $" Defender rates it {t.Severity.ToLowerInvariant()}." : ""),
                    FixKind.RemoveThreats, "Remove with Defender", true, t.ThreatId);
        }

        foreach (var t in f.Threats.Where(t => t.Status == ThreatStatus.Allowed))
            Add(list, "threat-allowed:" + t.ThreatId, A, Severity.Warning, $"Defender was told to allow {t.Name}",
                "Someone chose \"Allow\" for this detection, so Defender leaves it alone. Scammers often ask people to do this. If you didn't, remove it in Windows Security, Protection history. " + Where(t),
                FixKind.OpenWindowsSecurity, "Open Windows Security");

        var recent = f.Threats.Where(t => t.Status is ThreatStatus.Quarantined or ThreatStatus.Removed or ThreatStatus.Blocked
                                          && t.DetectedUtc is { } w && (now - w).TotalDays <= RecentThreatDays).ToList();
        if (recent.Count > 0)
            Add(list, "threat:recent", A, Severity.Info, recent.Count == 1 ? "Defender stopped 1 threat recently" : $"Defender stopped {recent.Count} threats recently",
                "In the last 30 days Defender removed or quarantined: " + string.Join("; ", recent.Select(t => t.Name).Distinct().Take(10))
                + ". Nothing more to do, but think about where they came from (a download, an email attachment, a USB stick).");
    }

    private static string Where(ThreatRecord t)
    {
        var r = t.Resources.Select(Clean).Where(s => s.Length > 0).Take(3).ToList();
        return r.Count == 0 ? "" : "Found in " + string.Join(", ", r) + (t.Resources.Count > 3 ? " and more." : ".");
        static string Clean(string s)
        {
            int c = s.IndexOf(":_", StringComparison.Ordinal);     // "file:_C:\x\y.exe"
            s = c >= 0 ? s[(c + 2)..] : s;
            return s.Length > 120 ? s[..120] + "..." : s;
        }
    }

    // ---------------- Programs ----------------

    public static Lists.ProgramRule? BadProgram(string name)
    {
        Lists.ProgramRule? best = null;
        foreach (var r in Lists.BadPrograms)
            if (r.Pattern.IsMatch(name) && (best is null || r.Severity > best.Severity)) best = r;
        return best;
    }

    private static void Programs(ScanFacts f, List<Finding> list)
    {
        const string A = "Programs";
        foreach (var p in f.Programs.Where(p => p.Name.Length > 0).GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
        {
            bool canUninstall = p.UninstallCommand.Length > 0;
            if (BadProgram(p.Name) is { } rule)
                Add(list, "program:" + p.Name, A, rule.Severity, $"Remove {p.Name}",
                    $"{p.Name} is {rule.Why}." + (canUninstall ? "" : " It has no uninstaller listed; remove it from Settings, Apps, or call Night Tech."),
                    canUninstall ? FixKind.Uninstall : FixKind.None, "Uninstall it", true, p.RegistryKey, p.Name);
            else if (Lists.RemoteControl.IsMatch(p.Name))
                Add(list, "remote:" + p.Name, A, Severity.Warning, $"Remote-control program: {p.Name}",
                    $"{p.Name} lets someone see and control this PC from anywhere. That's fine if you or your IT person use it. "
                    + "If you don't know why it's here, or someone who called you about a \"problem\" asked you to install it, uninstall it and change your passwords from another device.",
                    canUninstall ? FixKind.Uninstall : FixKind.None, "Uninstall it", false, p.RegistryKey, p.Name);
        }
    }

    // ---------------- Startup ----------------

    /// <summary>How suspicious one startup item looks, and why. Null when it looks fine.</summary>
    public static (Severity Severity, string Why, bool Recommended)? JudgeStartup(StartupItem s)
    {
        var program = s.Program.Length > 0 ? s.Program : s.Command;
        // The arguments: what follows the program in the command ("wscript.exe //B x.vbs" with program C:\Windows\System32\wscript.exe gives "//B x.vbs").
        var args = s.Command.Length > program.Length && s.Command.Contains(program, StringComparison.OrdinalIgnoreCase)
            ? s.Command[(s.Command.IndexOf(program, StringComparison.OrdinalIgnoreCase) + program.Length)..].Trim().TrimStart('"').Trim()
            : CommandLine.Split(s.Command, _ => false).Arguments;

        if (CommandLine.IsScriptHost(program))
        {
            if (Lists.SneakyArguments.IsMatch(args))
                return (Severity.Risk, $"it starts {CommandLine.BaseName(program)} with hidden or downloaded commands, a common malware trick", true);
            var payload = CommandLine.Payload(program, args);
            var target = payload.Length > 0 ? payload : args;
            if (Lists.TempLikeFolder.IsMatch(target) || Lists.ScriptFile.IsMatch(target) && Lists.UserDataFolder.IsMatch(target))
                return (Severity.Risk, $"it uses {CommandLine.BaseName(program)} to run a file from {FolderWords(target)}", true);
            if (Lists.UserDataFolder.IsMatch(target))
                return (Severity.Warning, $"it uses {CommandLine.BaseName(program)} to load a file from {FolderWords(target)}. Some programs do this; malware does it often", false);
        }

        var bad = BadProgram(s.Name) ?? BadProgram(CommandLine.BaseName(program));
        if (bad is not null)
            return (bad.Severity, $"it looks like {bad.Why.Split('.')[0]}", true);

        if (Lists.TempLikeFolder.IsMatch(program))
            return s.Signed == true
                ? (Severity.Warning, $"it starts a program from {FolderWords(program)}, which programs don't normally run from", false)
                : (Severity.Risk, $"it starts an unsigned program from {FolderWords(program)}, which is how a lot of malware starts", true);

        if (s.ProgramExists == false)
            return (Severity.Info, "the program it points to isn't there any more (left over from something uninstalled). Turning it off is safe", true);

        if (s.Signed == false && Lists.UserDataFolder.IsMatch(program))
            return (Severity.Warning, $"it starts a program from {FolderWords(program)} that has no digital signature, so there's no way to tell who made it", false);

        return null;
    }

    private static string FolderWords(string path) =>
        path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\Tmp\", StringComparison.OrdinalIgnoreCase) ? "a temporary folder"
        : path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) ? "the Downloads folder"
        : path.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase) ? "the Public folder"
        : path.Contains("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ? "the Recycle Bin"
        : path.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) ? "the ProgramData folder"
        : path.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) ? "your AppData folder"
        : "an unusual folder";

    private static void Startup(ScanFacts f, List<Finding> list)
    {
        foreach (var s in f.Startup)
        {
            if (JudgeStartup(s) is not { } j) continue;
            var label = s.Name.Length > 0 ? s.Name : CommandLine.BaseName(s.Program);
            Add(list, $"startup:{s.Location}|{s.Name}", "Startup", j.Severity, $"Startup item: {label}",
                $"\"{label}\" starts with Windows ({s.Where}), and {j.Why}. Command: {Short(s.Command, 200)}"
                + (s.Signer.Length > 0 ? $" Signed by {s.Signer}." : ""),
                FixKind.DisableStartup, "Stop it starting", j.Recommended, s.Kind.ToString(), s.Location, s.Name);
        }
    }

    private static string Short(string s, int n) => s.Length <= n ? s : s[..n] + "...";

    // ---------------- Browsers ----------------

    private static void Browsers(ScanFacts f, List<Finding> list)
    {
        const string A = "Browsers";
        foreach (var b in f.Browsers)
        {
            var where = b.Profile.Length > 0 && b.Profile != "Default" ? $"{b.Browser} ({b.Profile})" : b.Browser;
            var key = $"{b.Browser}|{b.ProfilePath}";
            if (b.SearchUrl.Length > 0 && !Lists.IsGoodSite(b.SearchUrl))
                Add(list, "search:" + key, A, Severity.Warning, $"{where}: search engine changed",
                    $"Searches go to {Host(b.SearchUrl)}, which isn't a well-known search engine. Hijackers do this to show ads and track searches. Resetting the browser's settings puts the search engine back and turns off extensions; bookmarks, history and saved passwords stay.",
                    FixKind.ResetBrowser, "Reset browser settings", true, b.Browser, b.ProfilePath);

            var pages = b.StartupUrls.Append(b.HomePage).Where(u => u.Length > 0 && !Lists.IsGoodSite(u) && Lists.HijackUrl.IsMatch(u)).Distinct().ToList();
            if (pages.Count > 0)
                Add(list, "pages:" + key, A, Severity.Warning, $"{where}: start page changed",
                    $"The browser opens {string.Join(", ", pages.Select(Host))} when it starts, which looks like a search hijacker. Resetting settings puts the start page back.",
                    FixKind.ResetBrowser, "Reset browser settings", true, b.Browser, b.ProfilePath);

            var sideloaded = b.Extensions.Where(e => e.FromStore == false && e.Enabled).ToList();
            foreach (var e in sideloaded)
                Add(list, $"ext:{key}|{e.Id}", A, Severity.Warning, $"{where}: extension \"{Short(e.Name, 60)}\" wasn't installed from the store",
                    "Extensions that didn't come from the browser's own store were usually put there by another program, often adware. Remove it unless you or your IT person added it on purpose.",
                    FixKind.OpenExtensions, "Open the extensions page", false, b.Browser, b.ProfilePath);

            var others = b.Extensions.Where(e => e.FromStore != false && e.Enabled).Select(e => e.Name).ToList();
            if (others.Count > 0)
                Add(list, "exts:" + key, A, Severity.Info, $"{where}: {others.Count} extension{(others.Count == 1 ? "" : "s")}",
                    $"{string.Join(", ", others.Take(15).Select(n => Short(n, 50)))}{(others.Count > 15 ? " and more" : "")}. Extensions can read the pages you visit; remove any you don't recognize.",
                    FixKind.OpenExtensions, "Open the extensions page", false, b.Browser, b.ProfilePath);
        }
    }

    private static string Host(string url)
    {
        if (Uri.TryCreate(url.Replace("{searchTerms}", "x"), UriKind.Absolute, out var u) && u.Host.Length > 0) return u.Host;
        return Short(url, 60);
    }

    private static void Policies(ScanFacts f, List<Finding> list)
    {
        const string A = "Browsers";
        bool managed = f.DomainJoined == true;
        foreach (var g in f.Policies.GroupBy(p => (p.Browser, p.Setting)))
        {
            var p = g.First();
            string what = p.Setting switch
            {
                "ExtensionInstallForcelist" => "forces extensions to install and stops them being removed",
                "DefaultSearchProviderSearchURL" or "DefaultSearchProviderEnabled" => "locks the search engine",
                "HomepageLocation" or "NewTabPageLocation" => "locks the home page",
                "RestoreOnStartupURLs" => "locks the start pages",
                _ => "locks a browser setting",
            };
            var values = string.Join(", ", g.Select(x => Short(x.Value, 80)).Distinct().Take(5));
            if (managed)
                Add(list, $"policy:{p.Browser}|{p.Setting}", A, Severity.Info, $"{p.Browser} is managed by your organization",
                    $"A policy {what} ({values}). On a work PC that's normally your IT department.");
            else
                Add(list, $"policy:{p.Browser}|{p.Setting}", A, Severity.Risk, $"{p.Browser}: a program {what}",
                    $"A browser policy {what} ({values}). On a home or small-business PC with no IT department, that's almost always adware making sure you can't undo its changes. Removing the policy lets the browser's own settings work again.",
                    FixKind.RemovePolicy, "Remove the policy", true, g.Select(x => x.Key + "|" + x.ValueName).ToArray());
        }
    }

    // ---------------- Hosts file ----------------

    public sealed record HostsEntry(int Line, string Address, string Host, bool Blocks);

    public static List<HostsEntry> ParseHosts(IReadOnlyList<string> lines)
    {
        var entries = new List<HostsEntry>();
        for (int i = 0; i < lines.Count; i++)
        {
            var line = lines[i];
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            bool blocks = IsLoopbackOrNull(parts[0]);
            foreach (var host in parts.Skip(1))
                entries.Add(new HostsEntry(i, parts[0], host.TrimEnd('.').ToLowerInvariant(), blocks));
        }
        return entries;
    }

    private static bool IsLoopbackOrNull(string address) =>
        IPAddress.TryParse(address, out var ip) && (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any));

    public static bool IsProtected(string host) => Lists.ProtectedDomains.Any(d =>
        d.EndsWith('.') ? host.StartsWith(d, StringComparison.Ordinal) || host.Contains("." + d, StringComparison.Ordinal)
        : !d.Contains('.') ? host.Contains(d, StringComparison.Ordinal)
        : host == d || host.EndsWith("." + d, StringComparison.Ordinal));

    private static readonly string[] SecurityOrUpdate =
    {
        "windowsupdate", "update.microsoft", "wdcp.microsoft", "wd.microsoft", "smartscreen", "defender", "malwarebytes", "kaspersky", "avast", "avg.com",
        "norton", "mcafee", "bitdefender", "eset.com", "sophos", "avira", "trendmicro", "webroot", "f-secure", "virustotal", "eicar",
    };

    /// <summary>Ad, tracking and telemetry names people block on purpose with privacy tools.</summary>
    private static readonly string[] AdOrTelemetry =
    {
        "ad.", "ads.", "adservice", "pagead", "analytics", "track", "telemetry", "vortex", "watson", "stats.", "metrics", "doubleclick", "settings-win.data",
    };

    private static void Hosts(ScanFacts f, List<Finding> list)
    {
        const string A = "Network";
        var entries = ParseHosts(f.Hosts).Where(e => e.Host != "localhost" && e.Host != "localhost.localdomain").ToList();
        var redirects = entries.Where(e => !e.Blocks && IsProtected(e.Host)).ToList();
        var blockedSecurity = entries.Where(e => e.Blocks && SecurityOrUpdate.Any(s => e.Host.Contains(s, StringComparison.Ordinal))
                                                 && !AdOrTelemetry.Any(a => e.Host.Contains(a, StringComparison.Ordinal))).ToList();
        var bad = redirects.Concat(blockedSecurity).ToList();
        if (redirects.Count > 0)
            Add(list, "hosts:redirect", A, Severity.Risk, "The hosts file sends well-known sites somewhere else",
                $"{string.Join(", ", redirects.Select(e => $"{e.Host} goes to {e.Address}").Distinct().Take(6))}. This is how fake bank and login pages get shown at the real address.",
                FixKind.CleanHosts, "Remove those lines", true, bad.Select(e => e.Line.ToString()).Distinct().ToArray());
        if (blockedSecurity.Count > 0)
            Add(list, "hosts:block", A, Severity.Risk, "The hosts file blocks security or update sites",
                $"{string.Join(", ", blockedSecurity.Select(e => e.Host).Distinct().Take(6))} can't be reached. Malware does this to stop antivirus and Windows from updating.",
                FixKind.CleanHosts, "Remove those lines", true, bad.Select(e => e.Line.ToString()).Distinct().ToArray());

        int otherCount = entries.Count - bad.Count;
        if (otherCount > 0)
            Add(list, "hosts:other", A, Severity.Info, $"The hosts file has {otherCount} other entr{(otherCount == 1 ? "y" : "ies")}",
                otherCount > 200
                    ? "This looks like an ad-blocking list someone added on purpose. Shield leaves it alone."
                    : "Shield doesn't see a problem with them: " + string.Join(", ", entries.Except(bad).Select(e => e.Host).Distinct().Take(8)) + ". Remove any you didn't add.");
    }

    // ---------------- Proxy ----------------

    private static void Proxy(ScanFacts f, List<Finding> list)
    {
        const string A = "Network";
        var p = f.Proxy;
        bool managed = f.DomainJoined == true;
        string target = p.AutoConfigUrl.Length > 0 ? $"the setup script at {Short(p.AutoConfigUrl, 100)}" : p.Server;
        if (!p.Enabled && p.AutoConfigUrl.Length == 0) return;
        if (p.AutoConfigUrl.Length == 0 && IsLocal(p.Server))
        {
            Add(list, "proxy:local", A, Severity.Info, "Web traffic goes through a program on this PC",
                $"The proxy is set to {p.Server}. Some privacy, parental-control and developer tools do this. If you don't use one, turn it off.",
                FixKind.TurnOffProxy, "Turn the proxy off", false);
            return;
        }
        if (managed)
            Add(list, "proxy", A, Severity.Info, "Web traffic goes through a proxy",
                $"The proxy is set to {target}. On a work PC that's normally your IT department.");
        else
            Add(list, "proxy", A, Severity.Warning, "Web traffic goes through a proxy",
                $"Everything you do on the web goes through {target}. Home and small-business PCs almost never need one, and malware sets one to watch or change web pages. Turn it off unless your internet provider or IT person set it up.",
                FixKind.TurnOffProxy, "Turn the proxy off", true);
    }

    private static bool IsLocal(string server)
    {
        var s = server.ToLowerInvariant();
        return s.Split(';').All(part =>
        {
            var hostPort = part.Contains('=') ? part[(part.IndexOf('=') + 1)..] : part;
            var host = hostPort.Split(':')[0].Trim();
            return host is "localhost" or "127.0.0.1" or "::1" or "[::1]" || host.StartsWith("127.", StringComparison.Ordinal);
        });
    }
}
