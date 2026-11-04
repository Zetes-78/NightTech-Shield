using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using NightTech.Shield.Core;
using NightTech.Shield.Windows;

namespace NightTech.Shield;

public partial class MainWindow : Window
{
    public static string Version => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    private TargetUser? _user;
    private Fixer? _fixer;
    private ScanResult? _result;
    private readonly ObservableCollection<FindingRow> _rows = new();
    private CancellationTokenSource? _cts;
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();
        FindingsList.ItemsSource = _rows;
        PhoneRun.Text = Brand.Phone;
        TextRun.Text = Brand.TextPhone;
        VerseText.Text = Brand.Verse;
        Title = $"Night Tech Shield {Version}";
        Loaded += (_, _) => Start();
        Closing += OnClosing;
    }

    private void Start()
    {
        try
        {
            _user = TargetUser.Find();
            Fixer.LinksAllowed = _user.IsCurrentProcessUser;
            _fixer = new Fixer(_user);
            UndoMenu.IsEnabled = _fixer.Log.Undoable.Any();
            if (!_user.IsCurrentProcessUser)
                StatusDetail.Text += $" Settings will be checked for {_user.Name}, who is signed in at this PC.";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            ShowStatus("Shield couldn't start", "It needs administrator rights and access to its own folder. " + e.Message, Severity.Risk);
            ScanButton.IsEnabled = false;
        }
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!_busy) return;
        if (MessageBox.Show(this, "Shield is still working. Stop and close?", "Night Tech Shield", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            e.Cancel = true;
        else _cts?.Cancel();
    }

    // ---------------- Scan ----------------

    private async void Scan_Click(object sender, RoutedEventArgs e) => await Scan();

    private async Task Scan()
    {
        if (_user is null || _busy) return;
        SetBusy(true, "Scanning...", "This takes a minute or two.");
        try
        {
            var progress = new Progress<string>(s => StatusDetail.Text = s);
            var user = _user;
            var facts = await Task.Run(() => Collector.Collect(user, progress));
            _result = new ScanResult { ToolVersion = Version, Facts = facts, Findings = Rules.Evaluate(facts, DateTime.UtcNow) };
            ShowResult();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            ShowStatus("The scan didn't finish", ex.Message, Severity.Risk);
        }
        finally { SetBusy(false); }
    }

    private void ShowResult()
    {
        if (_result is null) return;
        _rows.Clear();
        foreach (var f in _result.Findings) _rows.Add(new FindingRow(f));
        var worst = _result.Worst;
        string title = worst switch
        {
            null => "No problems found",
            Severity.Risk => "Shield found problems to fix now",
            _ => "Shield found a few things worth fixing",
        };
        bool otherAv = _result.Findings.Any(f => f.Id == "av:other");
        bool partial = _result.Facts.Notes.Count > 0;
        string detail = Report.Summary(_result) + (worst is null
            ? (otherAv ? " Your antivirus is on" : " Microsoft Defender is on") + " and nothing suspicious turned up in the places Shield checked"
              + (partial ? ". Some checks didn't finish; they're listed at the bottom." : ".")
            : " The ones Night Tech recommends fixing are ticked. Untick anything you use on purpose, then choose Fix selected.");
        ShowStatus(title, detail, worst);
        NotesText.Text = _result.Facts.Notes.Count == 0 ? "" : "Couldn't check: " + string.Join(" ", _result.Facts.Notes);
        NotesText.Visibility = _result.Facts.Notes.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        SaveMenu.IsEnabled = true;
        UpdateFixButton();
    }

    private void ShowStatus(string title, string detail, Severity? level)
    {
        StatusTitle.Text = title;
        StatusDetail.Text = detail;
        StatusDot.Background = level switch
        {
            Severity.Risk => (Brush)FindResource("Risk"),
            Severity.Warning => (Brush)FindResource("Orange"),
            null => new SolidColorBrush(Color.FromRgb(0x2F, 0x85, 0x5A)),
            _ => (Brush)FindResource("Blue"),
        };
    }

    private void SetBusy(bool busy, string title = "", string detail = "", bool cancellable = false)
    {
        _busy = busy;
        Progress.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        ScanButton.IsEnabled = !busy && _user is not null;
        MoreButton.IsEnabled = !busy;
        CancelButton.Visibility = busy && cancellable ? Visibility.Visible : Visibility.Collapsed;
        foreach (var r in _rows) r.Locked = busy;
        if (busy)
        {
            StatusTitle.Text = title;
            StatusDetail.Text = detail;
            StatusDot.Background = (Brush)FindResource("Blue");
        }
        UpdateFixButton();
    }

    private void Row_Changed(object sender, RoutedEventArgs e) => UpdateFixButton();

    private void UpdateFixButton()
    {
        int n = _rows.Count(r => r.IsChecked && r.CanFix && !r.Done);
        FixButton.IsEnabled = !_busy && n > 0;
        FixButton.Content = n > 0 ? $"Fix selected ({n})" : "Fix selected";
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

    // ---------------- Fix ----------------

    private async void Fix_Click(object sender, RoutedEventArgs e)
    {
        if (_fixer is null || _busy) return;
        var chosen = _rows.Where(r => r.IsChecked && r.CanFix && !r.Done).ToList();
        if (chosen.Count == 0) return;

        var list = new StringBuilder();
        foreach (var r in chosen) list.AppendLine($"• {r.Finding.FixLabel}: {r.Finding.Title}");
        bool uninstalls = chosen.Any(r => r.Finding.Fix == FixKind.Uninstall);
        var question = $"Shield will make these changes:\n\n{list}\n"
                       + (uninstalls ? "Uninstallers may open their own windows; follow them through.\n" : "")
                       + "Startup items, browser policies, the hosts file and proxy can be put back later with More, Undo changes. Go ahead?";
        if (MessageBox.Show(this, question, "Fix selected", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        SetBusy(true, "Fixing...", "", cancellable: true);
        int ok = 0, failed = 0;
        try
        {
            if (RestorePoint.IsChecked == true)
            {
                StatusDetail.Text = "Making a Windows restore point (this can take a minute)...";
                var rp = await Task.Run(Fixer.CreateRestorePoint);
                StatusDetail.Text = rp;
            }
            // Browser steps are shown last, after everything Shield can do itself.
            foreach (var r in chosen.OrderBy(r => r.Finding.Fix is FixKind.ResetBrowser or FixKind.OpenExtensions ? 1 : 0))
            {
                ct.ThrowIfCancellationRequested();
                StatusDetail.Text = $"{r.Finding.FixLabel}: {r.Finding.Title}";
                if (r.Finding.Fix is FixKind.ResetBrowser or FixKind.OpenExtensions)
                {
                    BrowserHelp.Show(this, r.Finding);
                    r.SetResult("Follow the steps in the browser.", ok: true);
                    ok++;
                    continue;
                }
                try
                {
                    var fixer = _fixer;
                    var finding = r.Finding;
                    var message = await Task.Run(() => fixer.Apply(finding, ct), ct);
                    r.SetResult(message, ok: true);
                    ok++;
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    r.SetResult("Not fixed: " + ex.Message, ok: false);
                    failed++;
                }
            }
            ShowStatus(failed == 0 ? "Done" : "Done, with some problems",
                $"{ok} fixed{(failed > 0 ? $", {failed} couldn't be" : "")}. Scan again to check, and restart the PC if Defender removed anything.",
                failed == 0 ? Severity.Info : Severity.Warning);
        }
        catch (OperationCanceledException)
        {
            ShowStatus("Stopped", $"{ok} fixed before stopping. Scan again to see what's left.", Severity.Warning);
        }
        finally
        {
            SetBusy(false);
            UndoMenu.IsEnabled = _fixer.Log.Undoable.Any();
        }
    }

    // ---------------- More menu ----------------

    private void More_Click(object sender, RoutedEventArgs e)
    {
        MoreMenu.PlacementTarget = MoreButton;
        MoreMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        MoreMenu.IsOpen = true;
    }

    private async void QuickScan_Click(object sender, RoutedEventArgs e) =>
        await DefenderJob("Defender quick scan", "Usually 5 to 15 minutes. You can keep using the PC.", ct => Defender.Scan(full: false, ct), scanResult: true);

    private async void FullScan_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "A full scan checks every file and can take an hour or more. The PC will be slower while it runs. Start it?",
                "Defender full scan", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        await DefenderJob("Defender full scan", "This can take an hour or more. Leave the PC on and plugged in.", ct => Defender.Scan(full: true, ct), scanResult: true);
    }

    private async void ScanPath_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Choose a folder for Defender to scan" };
        if (_user is not null) dlg.InitialDirectory = Path.Combine(_user.Profile, "Downloads");
        if (dlg.ShowDialog(this) != true) return;
        var path = dlg.FolderName;
        await DefenderJob("Scanning " + path, "Defender is checking every file in it.", ct => Defender.ScanPath(path, ct), scanResult: true);
    }

    private async void Update_Click(object sender, RoutedEventArgs e) =>
        await DefenderJob("Updating virus definitions", "Downloading Defender's latest definitions.", Defender.UpdateDefinitions, scanResult: false);

    private async void Offline_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Microsoft Defender Offline restarts the PC and scans before Windows starts, which catches malware that hides while Windows is running. It takes about 15 minutes, and the PC restarts on its own.\n\nSave your work and close other apps first. Restart and scan now?",
                "Microsoft Defender Offline", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        await DefenderJob("Starting Defender Offline", "The PC will restart in about a minute.", Defender.OfflineScan, scanResult: false);
    }

    private async Task DefenderJob(string title, string detail, Func<CancellationToken, Task<Defender.RunResult>> job, bool scanResult)
    {
        if (_busy) return;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        SetBusy(true, title, detail, cancellable: true);
        bool rescan = false;
        try
        {
            var r = await Task.Run(() => job(ct), ct);
            rescan = scanResult && r.ExitCode == 2;
            _fixer?.Log.Add(new Change { Kind = ChangeKind.Record, Title = title }, DateTime.UtcNow);
            if (_fixer is not null) _fixer.Log.Save(Fixer.LogPath);
            if (scanResult)
                ShowStatus(r.ExitCode == 2 ? "Defender found something" : r.ExitCode == 0 ? "Defender's scan is finished" : "The scan didn't finish",
                    r.ExitCode == 2 ? "Choose Scan now to see what it found and remove it."
                    : r.ExitCode == 0 ? "Nothing was found."
                    : r.TimedOut ? "It took too long and was stopped." : "Defender couldn't finish. If another antivirus is installed, use that one's scan instead.",
                    r.ExitCode == 2 ? Severity.Risk : r.ExitCode == 0 ? null : Severity.Warning);
            else
                ShowStatus(r.ExitCode == 0 ? "Done" : "That didn't work", r.ExitCode == 0 ? "" : "Check the internet connection and try again.", r.ExitCode == 0 ? null : Severity.Warning);
        }
        catch (OperationCanceledException) { ShowStatus("Stopped", "", Severity.Info); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { ShowStatus("That didn't work", ex.Message, Severity.Warning); }
        finally { SetBusy(false); }
        // Defender found something: scan so it shows in the list with its Remove button.
        if (rescan) await Scan();
    }

    private void Undo_Click(object sender, RoutedEventArgs e)
    {
        if (_fixer is null) return;
        new UndoWindow(_fixer) { Owner = this }.ShowDialog();
        UndoMenu.IsEnabled = _fixer.Log.Undoable.Any();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (_result is null) return;
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save the scan report",
            FileName = $"Night Tech Shield report {_result.Facts.Computer} {DateTime.Now:yyyy-MM-dd}",
            Filter = "Web page (*.html)|*.html|Text file (*.txt)|*.txt",
            InitialDirectory = _user is null ? "" : Path.Combine(_user.Profile, "Documents"),
        };
        if (dlg.ShowDialog(this) != true) return;
        var changes = _fixer?.Log.Changes.Where(c => c.WhenUtc >= _result.Facts.TakenUtc).ToList();
        try
        {
            File.WriteAllText(dlg.FileName, dlg.FilterIndex == 2 ? Report.Text(_result, changes) : Report.Html(_result, changes), new UTF8Encoding(false));
            StatusDetail.Text = "Report saved to " + dlg.FileName;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, "The report couldn't be saved there: " + ex.Message, "Save report", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void WindowsSecurity_Click(object sender, RoutedEventArgs e)
    {
        if (!Fixer.OpenLink("windowsdefender://threat"))
            MessageBox.Show(this, "Open Windows Security from the Start menu.", "Windows Security", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void About_Click(object sender, RoutedEventArgs e) => new AboutWindow { Owner = this }.ShowDialog();
    private void Website_Click(object sender, RoutedEventArgs e) => Open(this, Brand.Website + "/");
    private void Phone_Click(object sender, RoutedEventArgs e) => Open(this, Brand.PhoneLink);

    /// <summary>
    /// Opens a link in the person's own browser. When a different administrator approved Shield, the browser would open
    /// with that administrator's rights, so the address is shown to copy instead.
    /// </summary>
    public static void Open(Window owner, string url)
    {
        if (Fixer.OpenLink(url)) return;
        bool phone = url.StartsWith("tel:", StringComparison.Ordinal);
        BrowserHelp.ShowAddress(owner, phone ? "Call Night Tech Solutions" : "Open in your browser", phone ? Brand.Phone : "Open this page",
            phone ? $"Call or text us at {Brand.Phone}. {Brand.Hours}." : "Copy this address into your browser.", phone ? Brand.Phone : url);
    }
}

/// <summary>One finding in the list.</summary>
public sealed class FindingRow : INotifyPropertyChanged
{
    public Finding Finding { get; }
    private bool _checked, _locked;

    public FindingRow(Finding f)
    {
        Finding = f;
        _checked = f.Recommended;
    }

    public bool CanFix => Finding.Fix != FixKind.None;
    public bool Done { get; private set; }
    public string Result { get; private set; } = "";
    public Brush ResultBrush { get; private set; } = Brushes.Black;

    public bool IsChecked { get => _checked; set { _checked = value; Changed(); } }
    public bool Locked { get => _locked; set { _locked = value; Changed(nameof(CanTick)); } }
    public bool CanTick => CanFix && !Done && !_locked;

    public Visibility CheckVisibility => CanFix ? Visibility.Visible : Visibility.Hidden;
    public Visibility FixVisibility => CanFix && !Done ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ResultVisibility => Result.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    public string FixText => "Fix: " + Finding.FixLabel;
    public string Label => Report.Label(Finding.Severity);

    public Brush Accent => Finding.Severity switch
    {
        Severity.Risk => new SolidColorBrush(Color.FromRgb(0xC5, 0x30, 0x30)),
        Severity.Warning => new SolidColorBrush(Color.FromRgb(0xC2, 0x41, 0x0C)),
        _ => new SolidColorBrush(Color.FromRgb(0x2B, 0x6C, 0xB0)),
    };

    public void SetResult(string message, bool ok)
    {
        Result = message;
        ResultBrush = ok ? new SolidColorBrush(Color.FromRgb(0x27, 0x67, 0x49)) : new SolidColorBrush(Color.FromRgb(0xC5, 0x30, 0x30));
        if (ok) { Done = true; _checked = false; }
        foreach (var p in new[] { nameof(Result), nameof(ResultBrush), nameof(ResultVisibility), nameof(IsChecked), nameof(CanTick), nameof(FixVisibility) }) Changed(p);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
