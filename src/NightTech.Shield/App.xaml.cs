using System.Threading;
using System.Windows;

namespace NightTech.Shield;

public partial class App : Application
{
    /// <summary>Matches AppMutex in the installer, so setup asks people to close Shield before upgrading.</summary>
    public const string MutexName = "Global\\NightTechSolutions.Shield";
    private Mutex? _single;

    protected override void OnStartup(StartupEventArgs e)
    {
        _single = new Mutex(true, MutexName, out bool first);
        // Any program could hold this name to keep Shield from opening, so it's a question, not a stop.
        if (!first && MessageBox.Show("Night Tech Shield looks like it's already open. Open another window anyway?", "Night Tech Shield",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            Shutdown();
            return;
        }
        base.OnStartup(e);
        new MainWindow().Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _single?.Dispose();
        base.OnExit(e);
    }
}
