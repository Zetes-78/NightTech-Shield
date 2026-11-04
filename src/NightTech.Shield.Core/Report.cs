using System.Net;
using System.Text;

namespace NightTech.Shield.Core;

/// <summary>Night Tech Solutions' details, shown in the app and in saved reports.</summary>
public static class Brand
{
    public const string Company = "Night Tech Solutions";
    public const string Website = "https://nighttech.solutions";
    public const string ShieldPage = "https://nighttech.solutions/security-apps/#shield";
    public const string ContactPage = "https://nighttech.solutions/contact/";
    public const string FreeApps = "https://nighttech.solutions/security-apps/";
    public const string Privacy = "https://nighttech.solutions/privacy/#apps";
    public const string Source = "https://github.com/Zetes-78/NightTech-Shield";
    public const string Releases = "https://github.com/Zetes-78/NightTech-Shield/releases/latest";
    public const string Phone = "(864) 381-8510";
    public const string PhoneLink = "tel:+18643818510";
    public const string TextPhone = "(864) 497-2701";
    public const string Email = "nighttechsolutions1@gmail.com";
    public const string Hours = "Weeknights 6-11 PM, weekends 9 AM-6 PM, remote help during the day";
    public const string Verse = "“Whatever you do, work heartily, as for the Lord.” Colossians 3:23";
    public const string Navy = "#1A365D", Orange = "#FF6B35", OrangeText = "#C2410C", Blue = "#4299E1", Gray = "#F7FAFC";
}

/// <summary>The hosts-file change Shield makes: the flagged lines are turned into comments, never silently deleted.</summary>
public static class HostsFile
{
    public const string Marker = "# Night Tech Shield turned this line off";

    public static List<string> CommentOut(IReadOnlyList<string> lines, IEnumerable<int> lineNumbers, DateTime when)
    {
        var set = lineNumbers.ToHashSet();
        return lines.Select((l, i) => set.Contains(i) && !l.TrimStart().StartsWith('#') ? $"{Marker} {when:yyyy-MM-dd}: {l}" : l).ToList();
    }
}

/// <summary>Saved scan reports: a plain-text one and a printable web page.</summary>
public static class Report
{
    public static string Summary(ScanResult r) => r.Worst switch
    {
        null => "No problems found.",
        Severity.Risk => Count(r, Severity.Risk, "serious problem") + (r.Findings.Any(f => f.Severity == Severity.Warning) ? " and " + Count(r, Severity.Warning, "thing") + " worth fixing." : "."),
        _ => Count(r, Severity.Warning, "thing") + " worth fixing.",
    };

    private static string Count(ScanResult r, Severity s, string noun)
    {
        int n = r.Findings.Count(f => f.Severity == s);
        return n == 1 ? $"1 {noun}" : $"{n} {noun}s";
    }

    public static string Label(Severity s) => s switch { Severity.Risk => "Fix now", Severity.Warning => "Worth fixing", _ => "For your information" };

    public static string Text(ScanResult r, IEnumerable<Change>? changes = null)
    {
        var sb = new StringBuilder();
        var f = r.Facts;
        sb.AppendLine($"Night Tech Shield {r.ToolVersion} scan report");
        sb.AppendLine($"Computer: {f.Computer}   Windows: {f.Windows}   Checked: {f.TakenUtc.ToLocalTime():MMMM d, yyyy h:mm tt}");
        if (f.CheckedUser.Length > 0) sb.AppendLine($"Settings checked for: {f.CheckedUser}");
        sb.AppendLine();
        sb.AppendLine(Summary(r));
        foreach (var g in r.Findings.GroupBy(x => x.Severity).OrderByDescending(g => g.Key))
        {
            sb.AppendLine();
            sb.AppendLine($"== {Label(g.Key)} ==");
            foreach (var x in g)
            {
                sb.AppendLine($"- {x.Title}");
                sb.AppendLine($"  {x.Detail}");
            }
        }
        var done = changes?.ToList() ?? new();
        if (done.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("== Changes made ==");
            foreach (var c in done) sb.AppendLine($"- {c.WhenUtc.ToLocalTime():MMM d h:mm tt}  {c.Title}{(c.UndoneUtc is null ? "" : " (undone)")}");
        }
        if (f.Notes.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("== Couldn't check ==");
            foreach (var n in f.Notes) sb.AppendLine("- " + n);
        }
        sb.AppendLine();
        sb.AppendLine("Shield reports what it saw during this scan. It can't promise a PC is free of every kind of malware.");
        sb.AppendLine($"Need a hand? Call {Brand.Company} at {Brand.Phone}, text {Brand.TextPhone}, or visit {Brand.Website}.");
        sb.AppendLine(Brand.Verse);
        return sb.ToString();
    }

    public static string Html(ScanResult r, IEnumerable<Change>? changes = null)
    {
        static string E(string s) => WebUtility.HtmlEncode(s);
        var f = r.Facts;
        var sb = new StringBuilder();
        sb.Append($$"""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Night Tech Shield report - {{E(f.Computer)}}</title>
            <style>
            body{font-family:Segoe UI,Arial,sans-serif;color:#1a202c;background:#fff;margin:0}
            header{background:{{Brand.Navy}};color:#fff;padding:20px 28px}header h1{margin:0;font-size:22px}header p{margin:4px 0 0;opacity:.85}
            main{max-width:860px;margin:0 auto;padding:20px 28px}
            .sum{font-size:20px;font-weight:600;margin:8px 0 16px}
            h2{font-size:16px;border-bottom:2px solid {{Brand.Orange}};padding-bottom:4px;margin-top:28px}
            .f{border:1px solid #e2e8f0;border-left:5px solid #a0aec0;border-radius:6px;padding:10px 14px;margin:10px 0}
            .f.Risk{border-left-color:#c53030}.f.Warning{border-left-color:{{Brand.Orange}}}.f.Info{border-left-color:{{Brand.Blue}}}
            .f b{display:block;margin-bottom:4px}.muted{color:#4a5568;font-size:13px}
            footer{background:{{Brand.Gray}};border-top:1px solid #e2e8f0;padding:16px 28px;font-size:14px;text-align:center;margin-top:30px}
            footer a{color:{{Brand.OrangeText}}}
            </style></head><body>
            <header><h1>Night Tech Shield scan report</h1><p>{{E(f.Computer)}} &middot; {{E(f.Windows)}} &middot; {{f.TakenUtc.ToLocalTime():MMMM d, yyyy h:mm tt}}</p></header>
            <main><p class="sum">{{E(Summary(r))}}</p>
            """);
        foreach (var g in r.Findings.GroupBy(x => x.Severity).OrderByDescending(g => g.Key))
        {
            sb.Append($"<h2>{E(Label(g.Key))}</h2>");
            foreach (var x in g) sb.Append($"<div class=\"f {g.Key}\"><b>{E(x.Title)}</b>{E(x.Detail)}</div>");
        }
        var done = changes?.ToList() ?? new();
        if (done.Count > 0)
        {
            sb.Append("<h2>Changes made</h2><ul>");
            foreach (var c in done) sb.Append($"<li>{c.WhenUtc.ToLocalTime():MMM d h:mm tt}: {E(c.Title)}{(c.UndoneUtc is null ? "" : " (undone)")}</li>");
            sb.Append("</ul>");
        }
        if (f.Notes.Count > 0)
        {
            sb.Append("<h2>Couldn't check</h2><ul>");
            foreach (var n in f.Notes) sb.Append($"<li>{E(n)}</li>");
            sb.Append("</ul>");
        }
        sb.Append($"""
            <p class="muted">Shield reports what it saw during this scan. It can't promise a PC is free of every kind of malware.</p></main>
            <footer><strong>Need a hand?</strong> Call {Brand.Company} at <a href="{Brand.PhoneLink}">{Brand.Phone}</a>, text {Brand.TextPhone}, or visit <a href="{Brand.Website}">nighttech.solutions</a>.<br>
            <span class="muted">{E(Brand.Verse)}</span></footer></body></html>
            """);
        return sb.ToString();
    }
}
