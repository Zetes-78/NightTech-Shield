using System.Text.Json.Serialization;

namespace NightTech.Shield.Core;

/// <summary>
/// Everything one scan read from the PC. Collecting only reads; nothing is changed until the person chooses fixes.
/// Null means "couldn't check".
/// </summary>
public sealed class ScanFacts
{
    public string Computer { get; set; } = "";
    public string Windows { get; set; } = "";
    public DateTime TakenUtc { get; set; }
    /// <summary>The signed-in person whose settings were checked (may differ from the administrator who approved the scan).</summary>
    public string CheckedUser { get; set; } = "";
    public bool? DomainJoined { get; set; }

    public DefenderState Defender { get; set; } = new();
    public List<AvProduct> SecurityCenter { get; set; } = new();
    public List<ThreatRecord> Threats { get; set; } = new();
    public List<InstalledProgram> Programs { get; set; } = new();
    public List<StartupItem> Startup { get; set; } = new();
    public List<BrowserProfile> Browsers { get; set; } = new();
    public List<BrowserPolicy> Policies { get; set; } = new();
    /// <summary>The hosts file's lines, as they are.</summary>
    public List<string> Hosts { get; set; } = new();
    public ProxyState Proxy { get; set; } = new();

    /// <summary>Checks that couldn't finish, in plain words.</summary>
    public List<string> Notes { get; set; } = new();
}

public sealed class DefenderState
{
    /// <summary>Defender's service answered at all.</summary>
    public bool Present { get; set; }
    /// <summary>"Normal", "Passive", "EDR Block Mode", "SxS Passive Mode" (Passive: another antivirus is in charge).</summary>
    public string RunningMode { get; set; } = "";
    public bool? AntivirusEnabled { get; set; }
    public bool? RealTime { get; set; }
    public bool? TamperProtected { get; set; }
    public int? SignatureAgeDays { get; set; }
    public int? QuickScanAgeDays { get; set; }
    public int? FullScanAgeDays { get; set; }
    public string SignatureVersion { get; set; } = "";

    public bool IsPassive => RunningMode.Contains("Passive", StringComparison.OrdinalIgnoreCase);
}

/// <summary>An antivirus that Windows Security Center lists.</summary>
public sealed class AvProduct
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public bool UpToDate { get; set; }

    public bool IsDefender => Name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase)
                              || Name.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase);

    /// <summary>Decodes Security Center's productState number.</summary>
    public static AvProduct FromProductState(string name, uint state) => new()
    {
        Name = name,
        Enabled = ((state >> 12) & 0xF) == 1,
        UpToDate = ((state >> 4) & 0xF) == 0,
    };
}

[JsonConverter(typeof(JsonStringEnumConverter<ThreatStatus>))]
public enum ThreatStatus { Unknown, Active, Quarantined, Removed, Allowed, Blocked, Failed }

/// <summary>Something Defender detected.</summary>
public sealed class ThreatRecord
{
    public string ThreatId { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>Low, Moderate, High, Severe (Defender's words).</summary>
    public string Severity { get; set; } = "";
    public ThreatStatus Status { get; set; }
    public DateTime? DetectedUtc { get; set; }
    public List<string> Resources { get; set; } = new();

    /// <summary>Defender's ThreatStatusID (MSFT_MpThreatDetection) in plain terms.</summary>
    public static ThreatStatus FromStatusId(int id) => id switch
    {
        1 => ThreatStatus.Active,          // Detected
        2 or 4 => ThreatStatus.Removed,    // Cleaned, Removed
        3 => ThreatStatus.Quarantined,
        5 => ThreatStatus.Allowed,
        6 => ThreatStatus.Blocked,
        102 or 103 or 104 or 105 or 107 => ThreatStatus.Failed, // quarantine/remove/allow failed, abandoned, block failed
        _ => ThreatStatus.Unknown,
    };

    public static string SeverityName(int id) => id switch { 1 => "Low", 2 => "Moderate", 4 => "High", 5 => "Severe", _ => "Unknown" };
}

public sealed class InstalledProgram
{
    public string Name { get; set; } = "";
    public string Publisher { get; set; } = "";
    public string Version { get; set; } = "";
    public string UninstallCommand { get; set; } = "";
    /// <summary>Where it was listed (registry key path), used to find it again when fixing.</summary>
    public string RegistryKey { get; set; } = "";
    public DateTime? InstalledOn { get; set; }
}

[JsonConverter(typeof(JsonStringEnumConverter<StartupKind>))]
public enum StartupKind { RegistryValue, StartupFolderFile }

/// <summary>Something that starts with Windows.</summary>
public sealed class StartupItem
{
    public StartupKind Kind { get; set; }
    /// <summary>Plain words: "Run (this user)", "Run (all users)", "Startup folder (all users)".</summary>
    public string Where { get; set; } = "";
    /// <summary>Registry key (for RegistryValue) or folder (for StartupFolderFile).</summary>
    public string Location { get; set; } = "";
    /// <summary>Value name, or the file name in the Startup folder.</summary>
    public string Name { get; set; } = "";
    /// <summary>The command line (for a shortcut, its target and arguments).</summary>
    public string Command { get; set; } = "";
    /// <summary>The program it starts, resolved to a full path where possible.</summary>
    public string Program { get; set; } = "";
    public bool? ProgramExists { get; set; }
    /// <summary>True when the program has a valid digital signature. Null: not checked.</summary>
    public bool? Signed { get; set; }
    public string Signer { get; set; } = "";
}

public sealed class BrowserProfile
{
    public string Browser { get; set; } = "";   // Chrome, Edge, Brave, Firefox
    public string Profile { get; set; } = "";
    public string ProfilePath { get; set; } = "";
    public string SearchUrl { get; set; } = "";
    public List<string> StartupUrls { get; set; } = new();
    public string HomePage { get; set; } = "";
    public List<BrowserExtension> Extensions { get; set; } = new();
}

public sealed class BrowserExtension
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>False when the browser says it wasn't installed from its own store. Null: unknown.</summary>
    public bool? FromStore { get; set; }
    public bool Enabled { get; set; } = true;
}

/// <summary>A browser setting forced by policy in the registry (how most hijackers stop people changing settings back).</summary>
public sealed class BrowserPolicy
{
    public string Browser { get; set; } = "";
    /// <summary>Full registry key, for example HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist.</summary>
    public string Key { get; set; } = "";
    public string ValueName { get; set; } = "";
    public string Value { get; set; } = "";
    /// <summary>ExtensionInstallForcelist, DefaultSearchProviderSearchURL, HomepageLocation, RestoreOnStartupURLs...</summary>
    public string Setting { get; set; } = "";
}

public sealed class ProxyState
{
    public bool Enabled { get; set; }
    public string Server { get; set; } = "";
    public string AutoConfigUrl { get; set; } = "";
    /// <summary>Registry key that holds these, for the person checked.</summary>
    public string Key { get; set; } = "";
}

// ---------------- Results ----------------

[JsonConverter(typeof(JsonStringEnumConverter<Severity>))]
public enum Severity
{
    /// <summary>Worth knowing; nothing needs doing.</summary>
    Info,
    /// <summary>Worth fixing.</summary>
    Warning,
    /// <summary>A real problem: fix it now.</summary>
    Risk,
}

[JsonConverter(typeof(JsonStringEnumConverter<FixKind>))]
public enum FixKind
{
    None,
    TurnOnRealTime,
    UpdateDefinitions,
    QuickScan,
    RemoveThreats,
    OpenWindowsSecurity,
    Uninstall,
    DisableStartup,
    ResetBrowser,
    OpenExtensions,
    RemovePolicy,
    CleanHosts,
    TurnOffProxy,
}

public sealed class Finding
{
    /// <summary>Stable for the same problem across scans, for example "startup:HKCU\...\Run|Updater".</summary>
    public string Id { get; set; } = "";
    /// <summary>Antivirus, Threats, Programs, Startup, Browsers, Network.</summary>
    public string Area { get; set; } = "";
    public Severity Severity { get; set; }
    public string Title { get; set; } = "";
    /// <summary>What was found and why it matters, in plain words.</summary>
    public string Detail { get; set; } = "";
    public FixKind Fix { get; set; }
    /// <summary>Plain words for the fix button ("Turn it off at startup").</summary>
    public string FixLabel { get; set; } = "";
    /// <summary>What the fix needs to find its target: a registry key, a program's key, a browser, the hosts lines.</summary>
    public List<string> FixData { get; set; } = new();
    /// <summary>Ticked for fixing by default. Off for anything the person might use on purpose.</summary>
    public bool Recommended { get; set; }
}

public sealed class ScanResult
{
    public string Tool { get; set; } = "Night Tech Shield";
    public string ToolVersion { get; set; } = "";
    public ScanFacts Facts { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();

    public Severity? Worst => Findings.Count == 0 || Findings.All(f => f.Severity == Severity.Info) ? null : Findings.Max(f => f.Severity);
}
