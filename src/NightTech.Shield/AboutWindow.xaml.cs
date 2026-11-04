using System.Windows;
using NightTech.Shield.Core;

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

    private void Website_Click(object sender, RoutedEventArgs e) => MainWindow.Open(this, Brand.Website + "/");
    private void Phone_Click(object sender, RoutedEventArgs e) => MainWindow.Open(this, Brand.PhoneLink);
    private void Help_Click(object sender, RoutedEventArgs e) => MainWindow.Open(this, Brand.ShieldPage);
    private void FreeApps_Click(object sender, RoutedEventArgs e) => MainWindow.Open(this, Brand.FreeApps);
    private void Privacy_Click(object sender, RoutedEventArgs e) => MainWindow.Open(this, Brand.Privacy);
    private void Updates_Click(object sender, RoutedEventArgs e) => MainWindow.Open(this, Brand.Releases);
    private void Source_Click(object sender, RoutedEventArgs e) => MainWindow.Open(this, Brand.Source);
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
