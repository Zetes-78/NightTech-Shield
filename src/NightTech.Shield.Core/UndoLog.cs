using System.Text.Json;
using System.Text.Json.Serialization;

namespace NightTech.Shield.Core;

[JsonConverter(typeof(JsonStringEnumConverter<ChangeKind>))]
public enum ChangeKind
{
    /// <summary>A registry value was removed; Data holds what it was.</summary>
    RegistryValue,
    /// <summary>A file was moved into Shield's keep folder; Data holds where from and where to.</summary>
    MovedFile,
    /// <summary>A file's old contents were saved before it was changed.</summary>
    FileBackup,
    /// <summary>Something that can't be undone from Shield (an uninstall, a Defender action). Kept for the record.</summary>
    Record,
}

/// <summary>One change Shield made.</summary>
public sealed class Change
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTime WhenUtc { get; set; }
    public ChangeKind Kind { get; set; }
    /// <summary>Plain words: "Stopped \"Updater\" starting with Windows".</summary>
    public string Title { get; set; } = "";
    public Dictionary<string, string> Data { get; set; } = new();
    /// <summary>For a registry value of several strings (REG_MULTI_SZ).</summary>
    public List<string> Lines { get; set; } = new();
    public DateTime? UndoneUtc { get; set; }

    [JsonIgnore] public bool CanUndo => Kind != ChangeKind.Record && UndoneUtc is null;
    public string Get(string key) => Data.TryGetValue(key, out var v) ? v : "";
}

/// <summary>Every change Shield made on this PC, newest last, so each can be put back.</summary>
public sealed class UndoLog
{
    public int Schema { get; set; } = 1;
    public List<Change> Changes { get; set; } = new();

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static UndoLog Load(string path)
    {
        try
        {
            if (File.Exists(path))
                return JsonSerializer.Deserialize<UndoLog>(File.ReadAllText(path), Options) ?? new UndoLog();
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            // A damaged log is kept aside, never overwritten, so nothing that could be undone is lost.
            try { File.Copy(path, path + ".damaged-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss"), overwrite: false); } catch (IOException) { }
        }
        return new UndoLog();
    }

    /// <summary>Writes to a temporary file first, so a crash mid-write can't leave a half-written log.</summary>
    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Options));
        File.Move(tmp, path, overwrite: true);
    }

    public Change Add(Change c, DateTime nowUtc)
    {
        c.WhenUtc = nowUtc;
        Changes.Add(c);
        return c;
    }

    public IEnumerable<Change> Undoable => Changes.Where(c => c.CanUndo).OrderByDescending(c => c.WhenUtc);
}
