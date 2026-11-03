using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ServiceLib.Services;

/// <summary>The saved outbound tag records whether an independent test must prove WARP+.</summary>
public static class WarpProfilePolicy
{
    public const string PlusTag = "personal-warp-plus-entry";

    public static bool RequiresPlus(string profile) =>
        JsonNode.Parse(profile)?["tag"]?.GetValue<string>() == PlusTag;

    public static string ValidateTrace(string profile, string trace)
    {
        var mode = Regex.Match(trace, @"(?m)^warp=(on|plus)\r?$").Groups[1].Value;
        if (RequiresPlus(profile) && mode != "plus")
            throw new InvalidOperationException("WARP+ was not confirmed by the independent connection test. The active profile was not changed. Try Test again after Cloudflare activates the subscription.");
        if (mode is not ("on" or "plus"))
            throw new InvalidOperationException("The test did not return a WARP connection. The active profile was not changed.");
        return mode == "plus" ? "WARP+" : "WARP";
    }
}
