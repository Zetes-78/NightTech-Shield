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
        if (!first)
        {
            MessageBox.Show("Night Tech Shield is already open.", "Night Tech Shield", MessageBoxButton.OK, MessageBoxImage.Information);
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
