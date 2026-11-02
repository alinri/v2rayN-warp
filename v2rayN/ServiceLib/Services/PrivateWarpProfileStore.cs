namespace ServiceLib.Services;

/// <summary>Owner-only, atomic replacement with a recoverable copy of the previous profile.</summary>
public static class PrivateWarpProfileStore
{
    public static string? Save(string path, string json, bool backupExisting = true)
    {
        var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Invalid WARP profile path.");
        Directory.CreateDirectory(directory);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        string? backup = null;
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temp, options))
            {
                using var writer = new StreamWriter(stream, leaveOpen: true);
                writer.Write(json);
                writer.Flush();
                stream.Flush(true);
            }
            if (backupExisting && File.Exists(path))
            {
                backup = Path.Combine(directory, "warp-backup-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8] + ".private.json");
                File.Copy(path, backup, false);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(backup, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            File.Move(temp, path, true);
            return backup;
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
