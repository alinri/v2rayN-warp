using System.Text.Json.Nodes;
using ServiceLib.Services;
public static class SniSpoofTests
{
 public static void Run()
 {
  const string json="""{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"hi.mislog.shop","port":443,"users":[{"id":"test-id"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"hi.mislog.shop","allowInsecure":false},"wsSettings":{"path":"/in/20010","headers":{"Host":"hi.mislog.shop"}},"sockopt":{"interface":"en8","tcpFastOpen":true}}},{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"outboundTag":"direct","domain":["example.org"]}]}}""";
  var original=JsonNode.Parse(json)!;var transformed=JsonNode.Parse(SniSpoofConfig.Apply(json,40443))!;
  void Check(bool b,string why){if(!b)throw new Exception(why);}
  var proxy=transformed["outbounds"]![0]!;
  Check(proxy["settings"]!["vnext"]![0]!["address"]!.ToString()=="127.0.0.1","rewrite runtime endpoint");
  Check(JsonNode.DeepEquals(proxy["settings"]!["vnext"]![0]!["users"],original["outbounds"]![0]!["settings"]!["vnext"]![0]!["users"]),"preserve credentials");
  Check(JsonNode.DeepEquals(proxy["streamSettings"]!["tlsSettings"],original["outbounds"]![0]!["streamSettings"]!["tlsSettings"]),"preserve real SNI and certificate verification");
  Check(JsonNode.DeepEquals(proxy["streamSettings"]!["wsSettings"],original["outbounds"]![0]!["streamSettings"]!["wsSettings"]),"preserve WS host and path");
  Check(proxy["streamSettings"]!["sockopt"]!["tcpFastOpen"]!.GetValue<bool>(),"preserve unrelated socket settings");
  Check(JsonNode.DeepEquals(transformed["routing"],original["routing"]),"preserve routing");
  Check(SniSpoofConfig.Proxy(json)["settings"]!["vnext"]![0]!["address"]!.ToString()=="hi.mislog.shop","do not mutate source");
  foreach(var ip in new[]{"104.21.56.43","172.67.177.94","2606:4700:3032::1"})Check(SniSpoofConfig.IsCloudflare(System.Net.IPAddress.Parse(ip)),"accept Cloudflare "+ip);
  foreach(var ip in new[]{"127.0.0.1","198.18.0.1","91.107.177.38","104.0.0.1","::1"})Check(!SniSpoofConfig.IsCloudflare(System.Net.IPAddress.Parse(ip)),"reject non Cloudflare "+ip);
  foreach(var bad in new[]{json.Replace("\"ws\"","\"grpc\""),json.Replace("\"tls\"","\"reality\"")}){
   bool rejected=false;try{SniSpoofConfig.Proxy(bad);}catch(InvalidOperationException){rejected=true;}Check(rejected,"reject incompatible transport");
  }
  var absent=json.Replace("\"serverName\":\"hi.mislog.shop\",","");Check(JsonNode.Parse(SniSpoofConfig.Apply(absent,40443))!["outbounds"]![0]!["streamSettings"]!["tlsSettings"]!["serverName"]!.ToString()=="hi.mislog.shop","preserve effective SNI before loopback rewrite");
  var emptyHost=absent.Replace("\"wsSettings\":{", "\"wsSettings\":{\"host\":\"\",");Check(JsonNode.Parse(SniSpoofConfig.Apply(emptyHost,40443))!["outbounds"]![0]!["streamSettings"]!["tlsSettings"]!["serverName"]!.ToString()=="hi.mislog.shop","ignore empty host when preserving effective SNI");
  var xhttp=json.Replace("\"network\":\"ws\"", "\"network\":\"xhttp\"");Check(SniSpoofConfig.Endpoint(SniSpoofConfig.Proxy(SniSpoofConfig.Apply(xhttp,40444))).Port==40444,"XHTTP endpoint rewrite");
  Console.WriteLine("PASS: SNI endpoint isolation, TLS identity, credentials, paths, routing and Cloudflare ranges");
 }
}
