using System.Text.RegularExpressions;

namespace NightTech.Shield.Core;

/// <summary>Night Tech's own lists: what we see on customers' PCs that antivirus programs often leave alone.</summary>
public static class Lists
{
    public sealed record ProgramRule(Regex Pattern, Severity Severity, string Why);

    private static Regex R(string p) => new(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));

    /// <summary>Programs to remove. Matched against the name in Installed apps.</summary>
    public static readonly IReadOnlyList<ProgramRule> BadPrograms = new[]
    {
        new ProgramRule(R(@"\bKMS ?(pico|Auto|Tools|Activator|Matrix)\b|\bAAct\b|Microsoft Toolkit|Windows Loader"), Severity.Risk,
            "a tool for activating Windows or Office without a license. These often carry malware, and they turn off parts of Windows' protection"),
        new ProgramRule(R(@"\bWave Browser\b|\bOneLaunch\b|WebNavigator|\bSearch Manager\b|\bWeb Companion\b|\bWebDiscover\b|\bShift Browser\b"), Severity.Warning,
            "adware: it changes your browser's search and start page and shows ads"),
        new ProgramRule(R(@"\bSegurazo\b|\bSAntivirus\b|\bByteFence\b"), Severity.Warning,
            "a program that's hard to remove and shows fake warnings to sell an upgrade"),
        new ProgramRule(R(@"\bReimage\b|\bRestoro\b|\bFortect\b|\bPC Accelerate\b|\bMyCleanPC\b|\bPC Optimizer Pro\b|\bSmart PC Care\b|\bSpeedUpMyPC\b|\bRegClean Pro\b|\bSlimCleaner\b|\bPC HelpSoft\b|\bAdvanced SystemCare\b|\bWinZip System Utilities\b|\bSystweak\b|\bPC App Store\b|\bClario\b|\bMacKeeper\b"), Severity.Warning,
            "a \"PC optimizer\" that finds scary-sounding problems to sell a fix. Windows doesn't need it"),
        new ProgramRule(R(@"Driver ?Booster|DriverFix|Driver Support|Driver ?Updater|Driver Reviver|Advanced Driver Updater|\bOutbyte\b|DriverPack"), Severity.Warning,
            "a driver updater. Windows Update installs drivers itself, and these can install the wrong ones"),
        new ProgramRule(R(@"\bAsk Toolbar\b|\bConduit\b|\bBabylon\b|\bMindspark\b|\bMyWay\b|\bIminent\b|\bMyStart\b|\bManuals ?Library\b|\bEasy ?PDF ?Combine\b|\bPDF ?Spark\b|\bFrom Doc to PDF\b|\bConvert ?Docs ?Now\b"), Severity.Warning,
            "an old-style toolbar or search hijacker"),
        new ProgramRule(R(@"\bHola\b.*\bVPN\b|\bHola Better Internet\b"), Severity.Warning,
            "a free VPN that shares your internet connection with other people"),
    };

    /// <summary>Remote-control programs: fine when the person uses them, dangerous when a scammer installed one.</summary>
    public static readonly Regex RemoteControl = R(
        @"\bAnyDesk\b|\bTeamViewer\b|ScreenConnect|ConnectWise Control|\bLogMeIn\b|\bGoTo (Resolve|Assist)\b|\bRustDesk\b|\bUltraViewer\b|\bSupremo\b|\bSplashtop\b|\b(Real|Tight|Ultra|Tiger)VNC\b|\bAmmyy\b|\bAeroAdmin\b|\bRemotePC\b|\bZoho Assist\b|\bAction1\b|\bAtera\b|\bSimpleHelp\b|\bNetSupport\b|\bLiteManager\b");

    /// <summary>Search engines and start pages nobody needs warning about (the site and everything under it).</summary>
    public static readonly string[] GoodDomains =
    {
        "bing.com", "duckduckgo.com", "yahoo.com", "ecosia.org", "startpage.com", "brave.com", "search.brave.com", "msn.com", "microsoft.com",
        "live.com", "office.com", "outlook.com", "microsoft365.com", "qwant.com", "kagi.com", "mozilla.org", "firefox.com",
    };

    /// <summary>Browser pages and new-tab pages.</summary>
    private static readonly string[] GoodSchemes = { "chrome", "edge", "brave", "vivaldi", "about", "chrome-search", "chrome-extension", "file" };

    /// <summary>
    /// True for well-known search engines and start pages, judged by the site's name, not by words anywhere in the address.
    /// Chrome's own Google search address starts with {google:baseURL}.
    /// </summary>
    public static bool IsGoodSite(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;
        var u = url.Trim().Replace("{google:baseURL}", "https://www.google.com/", StringComparison.OrdinalIgnoreCase);
        u = Regex.Replace(u, @"\{[^}]*\}", "x");
        if (!u.Contains("://", StringComparison.Ordinal) && !u.StartsWith("about:", StringComparison.OrdinalIgnoreCase)) u = "https://" + u;
        if (!Uri.TryCreate(u, UriKind.Absolute, out var uri)) return false;
        if (GoodSchemes.Contains(uri.Scheme.ToLowerInvariant())) return true;
        var host = uri.Host.ToLowerInvariant().TrimEnd('.');
        if (Regex.IsMatch(host, @"(^|\.)google\.(com|[a-z]{2}|co\.[a-z]{2}|com\.[a-z]{2})$")) return true;
        return GoodDomains.Any(d => host == d || host.EndsWith("." + d, StringComparison.Ordinal));
    }

    /// <summary>Words hijackers put in their search and start-page addresses.</summary>
    public static readonly Regex HijackUrl = R(@"search|srch|query|find|mystart|myway|startpage|safe-?finder|feed\.|results\.|go\.php|\?q=");

    /// <summary>Sites a hosts file should never point somewhere else: search, Microsoft and Windows Update, security companies, banks and big shops.</summary>
    public static readonly string[] ProtectedDomains =
    {
        "google.", "bing.com", "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "office.com", "microsoftonline.com", "msftncsi.com",
        "apple.com", "icloud.com", "amazon.", "paypal.com", "facebook.com", "youtube.com", "gmail.com", "yahoo.com", "outlook.com",
        "virustotal.com", "malwarebytes.com", "kaspersky.", "avast.com", "avg.com", "norton.com", "nortonlifelock.com", "mcafee.com",
        "bitdefender.", "eset.com", "sophos.com", "avira.com", "trendmicro.com", "webroot.com", "f-secure.com", "eicar.org",
        "chase.com", "bankofamerica.com", "wellsfargo.com", "capitalone.com", "citi.com", "usbank.com", "truist.com", "pnc.com",
        "americanexpress.com", "discover.com", "venmo.com", "zelle", "irs.gov", "ssa.gov", "nighttech.solutions",
    };

    /// <summary>Folders programs shouldn't normally start from.</summary>
    public static readonly Regex TempLikeFolder = R(@"\\(Temp|Tmp)\\|\\AppData\\Local\\Temp\\|\\Downloads\\|\\Users\\Public\\|\\\$Recycle\.Bin\\|\\Windows\\Temp\\|\\INetCache\\|\\Temporary Internet Files\\");

    /// <summary>User and shared data folders: programs there are fine when signed, worth a look when not.</summary>
    public static readonly Regex UserDataFolder = R(@"\\AppData\\(Roaming|Local|LocalLow)\\|\\ProgramData\\");

    /// <summary>Command-line tricks malware uses to hide what it runs.</summary>
    public static readonly Regex SneakyArguments = R(
        @"(^|\s)-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s|-w(indowstyle)?\s+h(idden)?\b|\bIEX\b|Invoke-Expression|DownloadString|DownloadFile|FromBase64String|Net\.WebClient|Invoke-WebRequest|\biwr\b|Start-BitsTransfer|bitsadmin|certutil.*-urlcache|javascript:|vbscript:|https?://|scrobj|\\\\[a-z0-9.-]+\\");

    /// <summary>Script files Windows runs with a double-click.</summary>
    public static readonly Regex ScriptFile = R(@"\.(js|jse|vbs|vbe|wsf|wsh|hta|ps1|bat|cmd|scr|pif)(""|\s|$)");
}
