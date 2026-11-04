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
  CheckSpeedtestBatch(json);
  Console.WriteLine("PASS: SNI endpoint isolation, TLS identity, credentials, paths, routing and Cloudflare ranges");
 }
 private static void CheckSpeedtestBatch(string json)
 {
  void Check(bool value,string why) { if(!value) throw new Exception(why); }
  var source=JsonNode.Parse(json)!;
  var ws=source["outbounds"]![0]!.DeepClone();ws["tag"]="proxy40001";
  var xhttp=ws.DeepClone();xhttp["tag"]="proxy40002";xhttp["streamSettings"]!["network"]="xhttp";
  xhttp["settings"]!["vnext"]![0]!["address"]="other.cloudflare.example";
  xhttp["streamSettings"]!["tlsSettings"]!["serverName"]="other.cloudflare.example";
  var unsupported=ws.DeepClone();unsupported["tag"]="proxy40003";unsupported["streamSettings"]!["security"]="reality";
  var failed=ws.DeepClone();failed["tag"]="proxy40004";failed["settings"]!["vnext"]![0]!["address"]="unresolvable.example";
  source["outbounds"]=new JsonArray(ws,xhttp,unsupported,failed,new JsonObject{["tag"]="direct",["protocol"]="freedom"});
  source["routing"]=new JsonObject{["rules"]=new JsonArray(new JsonObject{["outboundTag"]="proxy40002",["inboundTag"]=new JsonArray("mixed40002")})};
  var before=source.ToJsonString();var calls=new List<string>();
  var result=SniSpoofConfig.ApplyForSpeedtest(before,(address,port)=> {
   calls.Add(address);Check(port==443,"forward original destination port");
   if(address=="unresolvable.example") throw new IOException("DNS failure fixture");
   return Task.FromResult(address=="hi.mislog.shop"?45001:45002);
  }).GetAwaiter().GetResult();
  var output=JsonNode.Parse(result.Json)!;
  Check(output["outbounds"]![0]!["settings"]!["vnext"]![0]!["port"]!.GetValue<int>()==45001,"WS batch forwarder");
  Check(output["outbounds"]![1]!["settings"]!["vnext"]![0]!["port"]!.GetValue<int>()==45002,"separate destination forwarder");
  for(int i=0;i<2;i++) {
   Check(JsonNode.DeepEquals(source["outbounds"]![i]!["settings"]!["vnext"]![0]!["users"],output["outbounds"]![i]!["settings"]!["vnext"]![0]!["users"]),"preserve each node credentials");
   Check(JsonNode.DeepEquals(source["outbounds"]![i]!["streamSettings"]!["tlsSettings"],output["outbounds"]![i]!["streamSettings"]!["tlsSettings"]),"preserve each node TLS identity");
  }
  Check(JsonNode.DeepEquals(source["routing"],output["routing"]),"keep independent test routing");
  Check(output["outbounds"]![2]!["protocol"]!.ToString()=="blackhole" && output["outbounds"]![3]!["protocol"]!.ToString()=="blackhole","block incompatible/failed nodes without direct fallback");
  Check(result.Errors.Keys.Order().SequenceEqual(new[]{"proxy40003","proxy40004"}),"return per-node errors without failing compatible nodes");
  Check(calls.Count==3,"unsupported node must not create a listener");
  Check(output["outbounds"]![4]!["protocol"]!.ToString()=="freedom","preserve service outbound");
  Check(source.ToJsonString()==before,"batch source never mutated");
  Console.WriteLine("PASS: mixed WS/XHTTP speedtest batches, per-node error isolation and original routing/TLS");
 }

}
