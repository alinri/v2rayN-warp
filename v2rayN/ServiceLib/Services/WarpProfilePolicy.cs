using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ServiceLib.Services;

/// <summary>Test connectivity and report the observed WARP mode for a licensed profile.</summary>
public static class WarpProfilePolicy
{
    public const string PlusTag = "personal-warp-plus-entry";

    public static bool RequestsPlus(string profile) =>
        JsonNode.Parse(profile)?["tag"]?.GetValue<string>() == PlusTag;

    public static string ValidateTrace(string profile, string trace)
    {
        var mode = Regex.Match(trace, @"(?m)^warp=(on|plus)\r?$").Groups[1].Value;
        if (mode is not ("on" or "plus"))
            throw new InvalidOperationException("The test did not return a WARP connection. The active profile was not changed.");
        return mode == "plus" ? "WARP+" : RequestsPlus(profile) ? "WARP (license accepted; Plus not confirmed)" : "WARP";
    }
}
