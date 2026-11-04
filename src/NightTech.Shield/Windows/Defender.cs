using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace NightTech.Shield.Windows;

/// <summary>Asks Microsoft Defender to update, scan and clean up, with Windows' own command-line tools.</summary>
public static class Defender
{
    public sealed record RunResult(int ExitCode, string Output, bool TimedOut);

    /// <summary>Defender's command-line tool, from its newest platform folder.</summary>
    public static string? MpCmdRun()
    {
        using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender"))
            if (k?.GetValue("InstallLocation") is string loc && File.Exists(Path.Combine(loc, "MpCmdRun.exe")))
                return Path.Combine(loc, "MpCmdRun.exe");
        var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
        if (Directory.Exists(platform))
        {
            var newest = Directory.GetDirectories(platform)
                .Select(d => (Dir: d, Ok: Version.TryParse(Path.GetFileName(d).Split('-')[0], out var v), V: v))
                .Where(x => x.Ok && File.Exists(Path.Combine(x.Dir, "MpCmdRun.exe")))
                .OrderByDescending(x => x.V).FirstOrDefault();
            if (newest.Dir is not null) return Path.Combine(newest.Dir, "MpCmdRun.exe");
        }
        var pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
        return File.Exists(pf) ? pf : null;
    }

    public static Task<RunResult> UpdateDefinitions(CancellationToken ct) => Mp("-SignatureUpdate", TimeSpan.FromMinutes(15), ct);

    /// <summary>Quick scan (type 1) or full scan (type 2). Exit code 2 means Defender found something.</summary>
    public static Task<RunResult> Scan(bool full, CancellationToken ct) =>
        Mp($"-Scan -ScanType {(full ? 2 : 1)}", full ? TimeSpan.FromHours(12) : TimeSpan.FromHours(2), ct);

    public static Task<RunResult> ScanPath(string path, CancellationToken ct) =>
        Mp($"-Scan -ScanType 3 -File \"{path.TrimEnd('\\')}\"", TimeSpan.FromHours(6), ct);

    /// <summary>Removes what Defender has detected but not yet dealt with.</summary>
    public static Task<RunResult> RemoveThreats(CancellationToken ct) => PowerShell("Remove-MpThreat", TimeSpan.FromMinutes(15), ct);

    public static Task<RunResult> TurnOnRealTime(CancellationToken ct) =>
        PowerShell("Set-MpPreference -DisableRealtimeMonitoring $false", TimeSpan.FromMinutes(2), ct);

    /// <summary>Restarts the PC into Microsoft Defender Offline, which removes malware that hides while Windows is running.</summary>
    public static Task<RunResult> OfflineScan(CancellationToken ct) => PowerShell("Start-MpWDOScan", TimeSpan.FromMinutes(5), ct);

    private static async Task<RunResult> Mp(string args, TimeSpan limit, CancellationToken ct)
    {
        var exe = MpCmdRun() ?? throw new InvalidOperationException("Microsoft Defender's command-line tool wasn't found.");
        return await Run(exe, args, limit, ct);
    }

    private static Task<RunResult> PowerShell(string command, TimeSpan limit, CancellationToken ct)
    {
        var ps = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        return Run(ps, $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"", limit, ct);
    }

    /// <summary>Runs a Windows tool without a window and waits for it, up to a time limit.</summary>
    public static async Task<RunResult> Run(string exe, string args, TimeSpan limit, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Environment.SystemDirectory,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"{Path.GetFileName(exe)} didn't start.");
        var output = new StringBuilder();
        var outTask = p.StandardOutput.ReadToEndAsync();
        var errTask = p.StandardError.ReadToEndAsync();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(limit);
        bool timedOut = false;
        try { await p.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            timedOut = !ct.IsCancellationRequested;
            try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            if (!timedOut) throw;
        }
        output.Append(await outTask).Append(await errTask);
        return new RunResult(timedOut ? -1 : p.ExitCode, output.ToString().Trim(), timedOut);
    }
}
