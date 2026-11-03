using System.Text.Json.Nodes;
using ServiceLib.Services;

const string warp = """{"protocol":"masque","settings":{"address":"162.159.198.2","port":443},"streamSettings":{"network":"masque","security":"tls","sockopt":{"dialerProxy":"stale"}}}""";
const string source = """{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443}]},"streamSettings":{"sockopt":{"interface":"en1","tcpFastOpen":true}}},{"tag":"direct","protocol":"freedom","settings":{}}],"routing":{"rules":[{"outboundTag":"direct","ip":["geoip:private"]}]},"dns":{"servers":["1.1.1.1"]}}""";
void Check(bool ok, string message) { if (!ok) throw new Exception(message); }
void Reject(string config, string profile, string message)
{
    try { WarpChainConfig.Apply(config, profile); }
    catch (InvalidOperationException) { return; }
    throw new Exception(message);
}
var before = JsonNode.Parse(source)!;
var transformed = JsonNode.Parse(WarpChainConfig.Apply(source, warp, "en0"))!;
Check(transformed["outbounds"]![0]!["streamSettings"]!["sockopt"]!["dialerProxy"]!.GetValue<string>() == WarpChainConfig.Tag, "The server must dial through WARP");
Check(transformed["outbounds"]![0]!["streamSettings"]!["sockopt"]!["interface"] == null, "Only WARP binds the physical interface");
Check(transformed["outbounds"]![0]!["streamSettings"]!["sockopt"]!["tcpFastOpen"]!.GetValue<bool>(), "Keep unrelated socket settings");
Check(JsonNode.DeepEquals(before["routing"], transformed["routing"]), "Preserve routing rules");
Check(JsonNode.DeepEquals(before["dns"], transformed["dns"]), "Preserve DNS");
Check(JsonNode.DeepEquals(before["outbounds"]![1], transformed["outbounds"]![1]), "Direct routing must remain direct");
Check(transformed["outbounds"]![2]!["streamSettings"]!["sockopt"]!["interface"]!.GetValue<string>() == "en0", "WARP bypasses the OS tunnel");
Check(transformed["outbounds"]![2]!["streamSettings"]!["sockopt"]!["dialerProxy"] == null, "No WARP recursion");
var chained = JsonNode.Parse(source)!;
chained["outbounds"]![0]!["streamSettings"]!["sockopt"]!["dialerProxy"] = "first-hop";
chained["outbounds"]!.AsArray().Add(JsonNode.Parse("""{"tag":"first-hop","protocol":"socks","settings":{"servers":[{"address":"remote.example","port":1080}]}}"""));
var final = JsonNode.Parse(WarpChainConfig.Apply(chained.ToJsonString(), warp, "en0"))!;
Check(final["outbounds"]![0]!["streamSettings"]!["sockopt"]!["dialerProxy"]!.GetValue<string>() == "first-hop", "Preserve an existing proxy chain");
Check(final["outbounds"]![2]!["streamSettings"]!["sockopt"]!["dialerProxy"]!.GetValue<string>() == WarpChainConfig.Tag, "Attach WARP before the first hop");
Reject(source.Replace("example.com", "127.0.0.1"), warp, "Reject a local helper");
Reject(source.Replace("example.com", "::1"), warp, "Reject an IPv6 local helper");
Reject(source, """{"protocol":"freedom"}""", "Reject a non-WARP profile");
Reject(transformed.ToJsonString(), warp, "Reject duplicate tags");
Reject("""{"outbounds":[{"protocol":"freedom"}]}""", warp, "Reject a config without a proxy");
Console.WriteLine("PASS: WARP chaining, existing chains, direct rules, DNS, interface isolation and invalid profiles");
await WarpRegistrationTests.RunAsync();

SniSpoofTests.Run();
