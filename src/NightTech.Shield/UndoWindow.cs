using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NightTech.Shield.Core;
using NightTech.Shield.Windows;

namespace NightTech.Shield;

/// <summary>Lists the changes Shield made that can be put back, newest first.</summary>
public sealed class UndoWindow : Window
{
    private readonly Fixer _fixer;
    private readonly StackPanel _list = new();

    public UndoWindow(Fixer fixer)
    {
        _fixer = fixer;
        Title = "Undo changes";
        Width = 620; Height = 480; MinHeight = 300;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        FontFamily = new FontFamily("Segoe UI"); FontSize = 14;
        var root = new DockPanel { Margin = new Thickness(20) };
        var intro = new TextBlock
        {
            Text = "These are the changes Shield made that can be put back. Uninstalls and Defender actions can't be undone here.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12),
        };
        DockPanel.SetDock(intro, Dock.Top);
        root.Children.Add(intro);
        var close = new Button { Content = "Close", Style = (Style)Application.Current.FindResource("Secondary"), HorizontalAlignment = HorizontalAlignment.Right, IsCancel = true, Margin = new Thickness(0, 12, 0, 0) };
        close.Click += (_, _) => Close();
        DockPanel.SetDock(close, Dock.Bottom);
        root.Children.Add(close);
        root.Children.Add(new ScrollViewer { Content = _list, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        Content = root;
        Fill();
    }

    private void Fill()
    {
        _list.Children.Clear();
        var items = _fixer.Log.Undoable.ToList();
        if (items.Count == 0)
        {
            _list.Children.Add(new TextBlock { Text = "Nothing to undo.", Foreground = Brushes.Gray });
            return;
        }
        foreach (var c in items)
        {
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            var button = new Button { Content = "Put back", Style = (Style)Application.Current.FindResource("Secondary"), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(10, 0, 0, 0) };
            DockPanel.SetDock(button, Dock.Right);
            var text = new TextBlock { TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center };
            text.Inlines.Add(new System.Windows.Documents.Run(c.Title));
            text.Inlines.Add(new System.Windows.Documents.Run($"   {c.WhenUtc.ToLocalTime():MMM d, h:mm tt}") { Foreground = Brushes.Gray, FontSize = 12 });
            var change = c;
            button.Click += (_, _) =>
            {
                try
                {
                    _fixer.Undo(change);
                    Fill();
                }
                catch (Exception e) when (e is InvalidOperationException or IOException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                    MessageBox.Show(this, "That couldn't be put back: " + e.Message, "Undo", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            };
            row.Children.Add(button);
            row.Children.Add(text);
            _list.Children.Add(row);
        }
    }
}
