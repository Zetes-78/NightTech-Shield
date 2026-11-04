using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NightTech.Shield.Core;

namespace NightTech.Shield;

/// <summary>
/// Steps for resetting a browser or removing extensions. The browser does this itself: Shield runs as administrator,
/// and opening the person's browser from here would start it with administrator rights, which isn't safe.
/// </summary>
public static class BrowserHelp
{
    public static void Show(Window owner, Finding f)
    {
        var browser = f.FixData.FirstOrDefault() ?? "";
        bool extensions = f.Fix == FixKind.OpenExtensions;
        var (address, steps) = (browser, extensions) switch
        {
            ("Firefox", false) => ("about:support", "Paste this into Firefox's address bar and press Enter, then choose \"Refresh Firefox\". Bookmarks, history and saved passwords stay; add-ons and settings are reset."),
            ("Firefox", true) => ("about:addons", "Paste this into Firefox's address bar and press Enter. Remove any add-on you don't recognize with its \"...\" menu, then Remove."),
            (_, true) => ($"{Scheme(browser)}://extensions", $"Paste this into {browser}'s address bar and press Enter. Choose Remove on any extension you don't recognize."),
            _ => ($"{Scheme(browser)}://settings/reset", $"Paste this into {browser}'s address bar and press Enter, then choose \"Restore settings to their original defaults\" and Reset settings. Bookmarks, history and saved passwords stay; extensions are turned off and the search engine and start page go back to normal."),
        };

        var win = new Window
        {
            Title = extensions ? $"Check {browser}'s extensions" : $"Reset {browser}",
            Owner = owner, Width = 520, SizeToContent = SizeToContent.Height, ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, FontFamily = new FontFamily("Segoe UI"), FontSize = 14,
        };
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = f.Title, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });
        panel.Children.Add(new TextBlock { Text = steps, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
        var box = new TextBox { Text = address, IsReadOnly = true, FontFamily = new FontFamily("Consolas"), FontSize = 15, Padding = new Thickness(6), Margin = new Thickness(0, 0, 0, 12) };
        panel.Children.Add(box);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var copy = new Button { Content = "Copy address", Style = (Style)Application.Current.FindResource("Primary"), Margin = new Thickness(0, 0, 10, 0) };
        copy.Click += (_, _) =>
        {
            try { Clipboard.SetText(address); copy.Content = "Copied"; }
            catch (System.Runtime.InteropServices.COMException) { box.SelectAll(); box.Focus(); }
        };
        var close = new Button { Content = "Done", Style = (Style)Application.Current.FindResource("Secondary"), IsCancel = true };
        close.Click += (_, _) => win.Close();
        buttons.Children.Add(copy);
        buttons.Children.Add(close);
        panel.Children.Add(buttons);
        win.Content = panel;
        win.ShowDialog();
    }

    private static string Scheme(string browser) => browser switch
    {
        "Edge" => "edge",
        "Brave" => "brave",
        "Vivaldi" => "vivaldi",
        _ => "chrome",
    };
}
