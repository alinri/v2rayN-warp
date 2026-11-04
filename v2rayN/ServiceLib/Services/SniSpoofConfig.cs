using System.Net;
using System.Text.Json.Nodes;
namespace ServiceLib.Services;

public static class SniSpoofConfig
{
    public static JsonObject Proxy(string json)
    {
        var root = JsonNode.Parse(json)!.AsObject();
        var proxies = root["outbounds"]!.AsArray().OfType<JsonObject>().Where(x => x["protocol"]?.ToString() is "vless" or "vmess" or "trojan").ToList();
        if (proxies.Count != 1)
            throw new InvalidOperationException("SNI Spoofing needs one regular Xray proxy.");
        var p = proxies[0];
        ValidateProxy(p);
        return p;
    }
    private static void ValidateProxy(JsonObject p)
    {
        if (p["protocol"]?.ToString() is not ("vless" or "vmess" or "trojan"))
            throw new InvalidOperationException("SNI supports Xray VLESS, VMess and Trojan over Cloudflare TLS WS/XHTTP.");
        var s = p["streamSettings"];
        if (s?["security"]?.ToString() != "tls" || s["network"]?.ToString() is not ("ws" or "xhttp"))
            throw new InvalidOperationException("SNI Spoofing supports Cloudflare WS and XHTTP over TLS.");
        if (s["xhttpSettings"]?["extra"]?["downloadSettings"] != null || s["tlsSettings"]?["alpn"]?.AsArray().Any(x => x?.ToString() == "h3") == true || s["sockopt"]?["dialerProxy"] != null || p["proxySettings"] != null)
            throw new InvalidOperationException("SNI Spoofing cannot use UDP or an existing proxy chain.");
    }
    public static (string Address, int Port) Endpoint(JsonObject p)
    {
        var s = p["settings"]!;
        var server = (s["vnext"] as JsonArray ?? s["servers"] as JsonArray)?[0] ?? s;
        return (server["address"]!.ToString(), server["port"]!.GetValue<int>());
    }
    public static string Apply(string json, int port)
    {
        var p = Proxy(json);
        ApplyProxy(p, port);
        return p.Root.ToJsonString();
    }
    private static void ApplyProxy(JsonObject p, int port)
    {
        var (address, _) = Endpoint(p);
        var stream = p["streamSettings"]!.AsObject();
        var tls = (stream["tlsSettings"] ??= new JsonObject()).AsObject();
        if (string.IsNullOrEmpty(tls["serverName"]?.ToString()))
            tls["serverName"] = new[] { stream["wsSettings"]?["host"]?.ToString(), stream["wsSettings"]?["headers"]?["Host"]?.ToString(), stream["xhttpSettings"]?["host"]?.ToString(), address }.First(x => !string.IsNullOrWhiteSpace(x));
        var settings = p["settings"]!;
        var server = (settings["vnext"] as JsonArray ?? settings["servers"] as JsonArray)?[0] ?? settings;
        server["address"] = "127.0.0.1";
        server["port"] = port;
        if (stream["sockopt"] is JsonObject options)
            options.Remove("interface");
    }
    /// <summary>Isolate unsupported test outbounds without rejecting the whole batch.</summary>
    public static async Task<(string Json, Dictionary<string, string> Errors)> ApplyForSpeedtest(
        string json, Func<string, int, Task<int>> forwarder)
    {
        var root = JsonNode.Parse(json)!.AsObject();
        var errors = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in root["outbounds"]!.AsArray().OfType<JsonObject>())
        {
            if (p["protocol"]?.ToString() is "freedom" or "blackhole" or "dns" or "loopback") continue;
            var tag = p["tag"]?.ToString() ?? "";
            try
            {
                ValidateProxy(p);
                var (address, port) = Endpoint(p);
                ApplyProxy(p, await forwarder(address, port));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors[tag] = "SNI: " + ex.Message;
                // Preserve the routing tag, but never silently test this node directly.
                p.Clear();
                p["tag"] = tag;
                p["protocol"] = "blackhole";
                p["settings"] = new JsonObject();
            }
        }
        return (root.ToJsonString(), errors);
    }
    public static bool IsCloudflare(IPAddress ip)
    {
        string[] ranges = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"];
        var bytes = ip.GetAddressBytes();
        foreach (var range in ranges)
        { var parts = range.Split('/'); var net = IPAddress.Parse(parts[0]).GetAddressBytes(); if (net.Length != bytes.Length) continue; int bits = int.Parse(parts[1]); bool match = true; for (int i = 0; i < bytes.Length && bits > 0; i++, bits -= 8) { int mask = 255 << Math.Max(0, 8 - bits); if ((bytes[i] & mask) != (net[i] & mask)) { match = false; break; } } if (match) return true; }
        return false;
    }
}
