using System.Text.Json;
using System.Text.Json.Nodes;

namespace ServiceLib.Services;

/// <summary>Put WARP before remote proxy sockets, preserving existing proxy chains and routing.</summary>
public static class WarpChainConfig
{
    public const string Tag = "personal-warp-entry";

    public static string Apply(string configJson, string warpJson, string? physicalInterface = null)
    {
        var config = JsonNode.Parse(configJson)!.AsObject();
        var outbounds = config["outbounds"]?.AsArray()
            ?? throw new InvalidOperationException("WARP requires an Xray configuration.");
        var imported = JsonNode.Parse(warpJson)!.AsObject();
        var warp = imported["outbounds"] is JsonArray entries
            ? entries.FirstOrDefault(x => x?["protocol"]?.GetValue<string>() is "masque" or "wireguard")?.DeepClone()?.AsObject()
            : imported.DeepClone().AsObject();
        if (warp?["protocol"]?.GetValue<string>() is not ("masque" or "wireguard"))
            throw new InvalidOperationException("Import an Xray MASQUE/WireGuard WARP outbound first.");
        if (outbounds.Any(x => x?["tag"]?.GetValue<string>() == Tag))
            throw new InvalidOperationException("This configuration already contains the WARP entry tag.");

        var attached = 0;
        foreach (var outbound in outbounds.OfType<JsonObject>())
        {
            var protocol = outbound["protocol"]?.GetValue<string>();
            if (protocol is "freedom" or "blackhole" or "dns" or "loopback")
                continue;
            if (protocol is not ("vless" or "vmess" or "trojan" or "shadowsocks" or "socks" or "http"))
                throw new InvalidOperationException("WARP currently supports TCP proxy profiles using Xray.");
            var stream = outbound["streamSettings"] as JsonObject;
            var sockopt = stream?["sockopt"] as JsonObject;
            // Attach WARP only to the first hop of any existing chain.
            if (sockopt?["dialerProxy"]?.GetValue<string>() is { Length: > 0 }
                || outbound["proxySettings"]?["tag"]?.GetValue<string>() is { Length: > 0 })
                continue;
            var settings = outbound["settings"];
            var servers = settings?["vnext"] as JsonArray ?? settings?["servers"] as JsonArray;
            if (servers == null || servers.Count == 0)
                throw new InvalidOperationException("WARP requires a remote proxy server.");
            foreach (var server in servers)
            {
                var address = server?["address"]?.GetValue<string>() ?? "";
                if (address.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                    || System.Net.IPAddress.TryParse(address, out var ip) && System.Net.IPAddress.IsLoopback(ip))
                    throw new InvalidOperationException("Select the real server profile, not a localhost helper, for WARP.");
            }
            if (stream == null) outbound["streamSettings"] = stream = new JsonObject();
            if (sockopt == null) stream["sockopt"] = sockopt = new JsonObject();
            // The proxy socket travels through WARP; only the WARP socket binds to the physical NIC.
            sockopt.Remove("interface");
            sockopt["dialerProxy"] = Tag;
            attached++;
        }
        if (attached == 0)
            throw new InvalidOperationException("No remote Xray proxy socket can be routed through WARP.");

        warp["tag"] = Tag;
        warp.Remove("proxySettings");
        var warpStream = warp["streamSettings"] as JsonObject;
        if (warpStream == null) warp["streamSettings"] = warpStream = new JsonObject();
        var warpSockopt = warpStream["sockopt"] as JsonObject;
        if (warpSockopt == null) warpStream["sockopt"] = warpSockopt = new JsonObject();
        warpSockopt.Remove("dialerProxy");
        if (!string.IsNullOrWhiteSpace(physicalInterface)) warpSockopt["interface"] = physicalInterface;
        outbounds.Add(warp);
        return config.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
}
