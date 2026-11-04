using System.Text.Json;
using System.Text.RegularExpressions;

namespace NightTech.Shield.Core;

/// <summary>Reads a browser's own settings files. Only reads; resets are done by the browser itself.</summary>
public static class BrowserReader
{
    private static readonly HashSet<string> BuiltInNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Chrome Web Store Payments", "Google Docs Offline", "Microsoft Edge PDF Viewer", "Web Store", "Edge relevant text changes",
        "Google Hangouts", "Chrome PDF Viewer", "Microsoft Clipboard Extension", "Microsoft Voices", "Edge Feedback", "Microsoft Edge Shopping",
    };

    /// <summary>Every profile in a Chromium browser's "User Data" folder (Chrome, Edge, Brave, Vivaldi).</summary>
    public static List<BrowserProfile> Chromium(string userDataDir, string browser, List<string>? notes = null)
    {
        var found = new List<BrowserProfile>();
        if (!Directory.Exists(userDataDir)) return found;
        string[] dirs;
        try { dirs = Directory.GetDirectories(userDataDir); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { notes?.Add($"{browser}: couldn't open its settings folder."); return found; }
        foreach (var profile in dirs.Where(d => File.Exists(Path.Combine(d, "Preferences"))).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            try { found.Add(ChromiumProfile(profile, browser)); }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                notes?.Add($"{browser} ({Path.GetFileName(profile)}): couldn't read its settings. Close the browser and scan again.");
            }
        }
        return found;
    }

    public static BrowserProfile ChromiumProfile(string profileDir, string browser)
    {
        var p = new BrowserProfile { Browser = browser, ProfilePath = profileDir, Profile = Path.GetFileName(profileDir) };
        using var prefs = JsonDocument.Parse(ReadShared(Path.Combine(profileDir, "Preferences")), new JsonDocumentOptions { AllowTrailingCommas = true });
        var root = prefs.RootElement;
        if (At(root, "profile", "name") is { ValueKind: JsonValueKind.String } pn && pn.GetString() is { Length: > 0 } name) p.Profile = name;
        if (At(root, "default_search_provider_data", "template_url_data", "url") is { ValueKind: JsonValueKind.String } u) p.SearchUrl = u.GetString() ?? "";

        bool specificPages = At(root, "session", "restore_on_startup") is { ValueKind: JsonValueKind.Number } r && r.GetInt32() == 4;
        if (specificPages && At(root, "session", "startup_urls") is { ValueKind: JsonValueKind.Array } urls)
            p.StartupUrls = urls.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").Where(s => s.Length > 0).ToList();
        bool homeIsNewTab = At(root, "homepage_is_newtabpage") is { ValueKind: JsonValueKind.True };
        if (!homeIsNewTab && At(root, "homepage") is { ValueKind: JsonValueKind.String } h) p.HomePage = h.GetString() ?? "";

        // Newer browsers keep extension settings in "Secure Preferences".
        var settings = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        JsonDocument? secure = null;
        try
        {
            var securePath = Path.Combine(profileDir, "Secure Preferences");
            if (File.Exists(securePath))
            {
                secure = JsonDocument.Parse(ReadShared(securePath), new JsonDocumentOptions { AllowTrailingCommas = true });
                Collect(secure.RootElement, settings);
            }
            Collect(root, settings);
            foreach (var (id, s) in settings)
                if (Extension(profileDir, id, s) is { } ext) p.Extensions.Add(ext);
        }
        finally { secure?.Dispose(); }
        p.Extensions = p.Extensions.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
        return p;
    }

    private static void Collect(JsonElement root, Dictionary<string, JsonElement> into)
    {
        if (At(root, "extensions", "settings") is not { ValueKind: JsonValueKind.Object } s) return;
        foreach (var e in s.EnumerateObject())
            if (!into.ContainsKey(e.Name) && e.Value.ValueKind == JsonValueKind.Object) into[e.Name] = e.Value.Clone();
    }

    private static BrowserExtension? Extension(string profileDir, string id, JsonElement s)
    {
        int location = s.TryGetProperty("location", out var l) && l.ValueKind == JsonValueKind.Number ? l.GetInt32() : 0;
        if (location is 5 or 10) return null;                                   // built into the browser
        if (At(s, "manifest", "type") is { ValueKind: JsonValueKind.String } t && t.GetString() is "theme" or "hosted_app" or "legacy_packaged_app") return null;
        bool? fromWebstore = s.TryGetProperty("from_webstore", out var fw) && fw.ValueKind is JsonValueKind.True or JsonValueKind.False ? fw.GetBoolean() : null;

        bool? fromStore = location switch
        {
            1 => true,                                   // installed by the person from a store
            4 or 8 => false,                             // loaded unpacked, or by a --load-extension command line
            2 or 3 or 6 => fromWebstore ?? false,        // put there by another program
            7 or 9 => null,                              // policy (reported separately)
            _ => fromWebstore,
        };

        bool enabled = true;
        if (s.TryGetProperty("state", out var st) && st.ValueKind == JsonValueKind.Number) enabled = st.GetInt32() == 1;
        if (s.TryGetProperty("disable_reasons", out var dr) &&
            (dr.ValueKind == JsonValueKind.Number && dr.GetInt32() != 0 || dr.ValueKind == JsonValueKind.Array && dr.GetArrayLength() > 0)) enabled = false;

        var name = At(s, "manifest", "name") is { ValueKind: JsonValueKind.String } mn ? mn.GetString() ?? "" : "";
        var relPath = s.TryGetProperty("path", out var pp) && pp.ValueKind == JsonValueKind.String ? pp.GetString() ?? "" : "";
        if (name.Length == 0 || name.StartsWith("__MSG_", StringComparison.Ordinal))
            name = NameFromFolder(profileDir, id, relPath, location, name);
        if (name.Length == 0) name = id;
        if (BuiltInNames.Contains(name)) return null;
        return new BrowserExtension { Id = id, Name = name, FromStore = fromStore, Enabled = enabled };
    }

    /// <summary>Reads the extension's manifest (and its English messages when the name is "__MSG_x__").</summary>
    private static string NameFromFolder(string profileDir, string id, string relPath, int location, string current)
    {
        try
        {
            string? dir = null;
            if (location is 4 or 8 && Path.IsPathRooted(relPath)) dir = relPath;
            else
            {
                var extDir = Path.Combine(profileDir, "Extensions", id);
                if (relPath.Length > 0 && Directory.Exists(Path.Combine(profileDir, "Extensions", relPath))) dir = Path.Combine(profileDir, "Extensions", relPath);
                else if (Directory.Exists(extDir)) dir = Directory.GetDirectories(extDir).OrderByDescending(d => d, StringComparer.Ordinal).FirstOrDefault();
            }
            if (dir is null) return current.StartsWith("__MSG_", StringComparison.Ordinal) ? "" : current;
            var name = current;
            var manifest = Path.Combine(dir, "manifest.json");
            string defaultLocale = "en";
            if (File.Exists(manifest))
            {
                using var m = JsonDocument.Parse(File.ReadAllText(manifest), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                if (m.RootElement.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String) name = n.GetString() ?? "";
                if (m.RootElement.TryGetProperty("default_locale", out var dl) && dl.ValueKind == JsonValueKind.String) defaultLocale = dl.GetString() ?? "en";
            }
            var msg = Regex.Match(name, @"^__MSG_(\w+)__$");
            if (!msg.Success) return name;
            foreach (var loc in new[] { "en", "en_US", defaultLocale }.Distinct())
            {
                var file = Path.Combine(dir, "_locales", loc, "messages.json");
                if (!File.Exists(file)) continue;
                using var d = JsonDocument.Parse(File.ReadAllText(file), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                foreach (var p in d.RootElement.EnumerateObject())
                    if (string.Equals(p.Name, msg.Groups[1].Value, StringComparison.OrdinalIgnoreCase) && p.Value.TryGetProperty("message", out var mm))
                        return mm.GetString() ?? "";
            }
            return "";
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException) { return current.StartsWith("__MSG_", StringComparison.Ordinal) ? "" : current; }
    }

    /// <summary>Firefox profiles in %APPDATA%\Mozilla\Firefox\Profiles: home page and add-ons (Firefox's search engine file is compressed and isn't read).</summary>
    public static List<BrowserProfile> Firefox(string profilesDir, List<string>? notes = null)
    {
        var found = new List<BrowserProfile>();
        if (!Directory.Exists(profilesDir)) return found;
        foreach (var dir in Directory.GetDirectories(profilesDir).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            var ext = Path.Combine(dir, "extensions.json");
            var prefs = Path.Combine(dir, "prefs.js");
            if (!File.Exists(ext) && !File.Exists(prefs)) continue;
            var p = new BrowserProfile { Browser = "Firefox", ProfilePath = dir, Profile = Path.GetFileName(dir) };
            try
            {
                if (File.Exists(prefs))
                {
                    var m = Regex.Match(ReadShared(prefs), "user_pref\\(\"browser\\.startup\\.homepage\",\\s*\"([^\"]*)\"\\);");
                    if (m.Success) p.HomePage = m.Groups[1].Value.Split('|')[0];
                }
                if (File.Exists(ext))
                {
                    using var d = JsonDocument.Parse(ReadShared(ext));
                    if (d.RootElement.TryGetProperty("addons", out var addons) && addons.ValueKind == JsonValueKind.Array)
                        foreach (var a in addons.EnumerateArray())
                        {
                            if (Str(a, "type") != "extension") continue;
                            var location = Str(a, "location");
                            if (location is "app-system-defaults" or "app-builtin" or "app-system-addons" or "temporary-addon") continue;
                            var name = At(a, "defaultLocale", "name") is { ValueKind: JsonValueKind.String } n ? n.GetString() ?? "" : Str(a, "id");
                            bool foreign = a.TryGetProperty("foreignInstall", out var fi) && fi.ValueKind == JsonValueKind.True;
                            bool active = !a.TryGetProperty("active", out var ac) || ac.ValueKind != JsonValueKind.False;
                            p.Extensions.Add(new BrowserExtension { Id = Str(a, "id"), Name = name, FromStore = !foreign && location == "app-profile", Enabled = active });
                        }
                }
                found.Add(p);
            }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                notes?.Add($"Firefox ({p.Profile}): couldn't read its settings. Close Firefox and scan again.");
            }
        }
        return found;
    }

    private static string Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static JsonElement? At(JsonElement e, params string[] names)
    {
        foreach (var n in names)
        {
            if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(n, out var next)) return null;
            e = next;
        }
        return e;
    }

    /// <summary>Reads a file the browser may have open.</summary>
    private static string ReadShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var sr = new StreamReader(fs);
        return sr.ReadToEnd();
    }
}
