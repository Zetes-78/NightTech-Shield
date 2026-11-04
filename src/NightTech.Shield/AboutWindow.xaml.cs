using System.Windows;
using NightTech.Shield.Core;
using NightTech.Shield.Windows;

namespace NightTech.Shield;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        VersionText.Text = $"Version {MainWindow.Version} · by {Brand.Company}";
        PhoneRun.Text = Brand.Phone;
        TextRun.Text = Brand.TextPhone;
        HoursText.Text = Brand.Hours;
        VerseText.Text = Brand.Verse;
    }

    private void Website_Click(object sender, RoutedEventArgs e) => Fixer.OpenLink(Brand.Website + "/");
    private void Phone_Click(object sender, RoutedEventArgs e) => Fixer.OpenLink(Brand.PhoneLink);
    private void Help_Click(object sender, RoutedEventArgs e) => Fixer.OpenLink(Brand.ShieldPage);
    private void FreeApps_Click(object sender, RoutedEventArgs e) => Fixer.OpenLink(Brand.FreeApps);
    private void Privacy_Click(object sender, RoutedEventArgs e) => Fixer.OpenLink(Brand.Privacy);
    private void Updates_Click(object sender, RoutedEventArgs e) => Fixer.OpenLink(Brand.Releases);
    private void Source_Click(object sender, RoutedEventArgs e) => Fixer.OpenLink(Brand.Source);
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
