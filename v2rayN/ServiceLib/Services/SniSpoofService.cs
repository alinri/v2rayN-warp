using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
namespace ServiceLib.Services;
/// <summary>Owns isolated probes and the elevated packet injector; stored profiles are never rewritten.</summary>
public static class SniSpoofService
{
    static SniSpoofService()
    {
        networkStamp = PhysicalStamp();
        NetworkChange.NetworkAddressChanged += (_, _) => { var stamp = PhysicalStamp(); if (stamp == networkStamp) return; networkStamp = stamp; Invalidate(); if (AppManager.Instance.Config?.SniSpoofItem.Enabled == true) AppEvents.ReloadRequested.Publish(); };
    }
    private static string networkStamp = "";
    private static string PhysicalStamp() => string.Join(";", NetworkInterface.GetAllNetworkInterfaces().Where(x => x.OperationalStatus == OperationalStatus.Up && x.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211).Select(x => x.Name + ":" + string.Join(",", x.GetIPProperties().UnicastAddresses.Select(a => a.Address.ToString()))).Order());
    public static bool PreviousWarp { get; set; }
    private static bool ControlAlive
    {
        get
        {
            try
            { return control is { Connected: true } && !(control.Client.Poll(0, SelectMode.SelectRead) && control.Client.Available == 0); }
            catch (SocketException) { return false; }
            catch (ObjectDisposedException) { return false; }
        }
    }
    public static bool HasActiveSession => activeId.Length > 0 && ControlAlive;
    public static ConcurrentQueue<string> Results { get; } = new();
    public static event Action<string>? StatusChanged;
    public static string Status { get; private set; } = "SNI: off";
    private static void Show(string s) { Status = s; StatusChanged?.Invoke(s); }
    private static readonly SemaphoreSlim Gate = new(1);
    private static CancellationTokenSource? scan;
    private static TcpClient? control;
    private static StreamReader? reader;
    private static StreamWriter? writer;
    private static Process? launcher;
    private static Task<string>? launcherError;
    private static string? sessionDir;
    private static string? activeKey;
    private static int activePort;
    private static string activeId = "";
    private static readonly List<string> retiredIds = new();
    public static bool Supported => !(OperatingSystem.IsWindows() && System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64);
    public static void NotifyFailure(string message) => Show("SNI: " + message);
    public static void Cancel() { scan?.Cancel(); }
    public static void Invalidate() { Cancel(); activeKey = null; }
    private static string Helper { get { var bundled = Utils.GetBaseDirectory(Path.Combine("bin", "sni", Utils.GetExeName("sni-spoof-helper"))); return File.Exists(bundled) ? bundled : Utils.GetBinPath(Utils.GetExeName("sni-spoof-helper"), "sni"); } }
    private static string Xray => CoreInfoManager.Instance.GetCoreExecFile(CoreInfoManager.Instance.GetCoreInfo(ECoreType.Xray), out _);
    private static int Port() { var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); var p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p; }
    private static Process Start(string exe, params string[] args)
    {
        var info = new ProcessStartInfo(exe) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        foreach (var argument in args) info.ArgumentList.Add(argument);
        if (Path.GetFileNameWithoutExtension(exe) == "xray")
        {
            // Use exactly the same geodata/certificate environment as the main core.
            info.WorkingDirectory = Utils.GetBinConfigPath();
            foreach (var item in CoreInfoManager.Instance.GetCoreInfo(ECoreType.Xray)!.Environment)
                info.Environment[item.Key] = item.Value;
        }
        var process = Process.Start(info)!;
        if (exe == "/usr/bin/osascript") launcherError = process.StandardError.ReadToEndAsync();
        else _ = process.StandardError.ReadToEndAsync();
        return process;
    }

    private static int GetInterfaceIndex(string iface, AddressFamily family) { var props = NetworkInterface.GetAllNetworkInterfaces().First(x => x.Name == iface).GetIPProperties(); return family == AddressFamily.InterNetwork ? props.GetIPv4Properties().Index : props.GetIPv6Properties().Index; }
    private static string Interface()
    {
        if (OperatingSystem.IsMacOS())
        { using var p = Start("/sbin/route", "-n", "get", "default"); var t = p.StandardOutput.ReadToEnd(); var line = t.Split('\n').FirstOrDefault(x => x.TrimStart().StartsWith("interface:")); var n = line?.Split(':')[1].Trim(); if (n?.StartsWith("en") == true) return n; }
        return NetworkInterface.GetAllNetworkInterfaces().Where(x => x.OperationalStatus == OperationalStatus.Up && x.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211).OrderByDescending(x => x.GetIPProperties().GatewayAddresses.Count).FirstOrDefault()?.Name ?? throw new InvalidOperationException("No physical Internet interface.");
    }
    private static async Task<JsonNode> Command(object command, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(8));
        ct = timeout.Token;
        await writer!.WriteLineAsync(JsonSerializer.Serialize(command));
        await writer.FlushAsync(ct);
        var line = await reader!.ReadLineAsync(ct);
        var result = JsonNode.Parse(line ?? throw new IOException("SNI helper stopped"))!;
        if (result["ok"]?.GetValue<bool>() != true)
            throw new InvalidOperationException(result["error"]?.ToString() ?? "SNI helper failed");
        return result;
    }
    private static async Task Broker(CancellationToken ct)
    {
        if (ControlAlive)
            return;
        control?.Dispose();
        activeId = "";
        activeKey = null;
        CleanupSession();
        if (!File.Exists(Helper))
            throw new InvalidOperationException("SNI helper is missing. Install a build including the SNI helper.");
        sessionDir = Path.Combine(Path.GetTempPath(), "v2rayn-sni-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sessionDir);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(sessionDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var file = Path.Combine(sessionDir, "session.json");
        PrivateWarpProfileStore.Save(file, JsonSerializer.Serialize(new { port = ((IPEndPoint)listener.LocalEndpoint).Port, token }), false);
        Show("SNI: approve packet-helper access in the system dialog");
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                string Q(string v) => "'" + v.Replace("'", "'\\''") + "'";
                var cmd = Q(Helper) + " --broker " + Q(file) + " >/dev/null 2>&1 &";
                launcher = Start("/usr/bin/osascript", "-e", "do shell script " + ("\"" + cmd.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"") + " with administrator privileges");
            }
            else
            {
                var si = new ProcessStartInfo(Helper) { UseShellExecute = true, Verb = "runas" };
                si.ArgumentList.Add("--broker");
                si.ArgumentList.Add(file);
                launcher = Process.Start(si);
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(90));
            var accept = listener.AcceptTcpClientAsync(timeout.Token).AsTask();
            if (OperatingSystem.IsMacOS() && launcher != null)
            {
                var exit = launcher.WaitForExitAsync(timeout.Token);
                if (await Task.WhenAny(accept, exit) == exit && launcher.HasExited && launcher.ExitCode != 0)
                    throw new InvalidOperationException("macOS helper authorization failed: " + (launcherError == null ? "osascript failed" : (await launcherError).Trim()));
            }
            while (true)
            { var peer = await accept; var r = new StreamReader(peer.GetStream()); var hello = await r.ReadLineAsync(timeout.Token); if (JsonNode.Parse(hello ?? "{}")?["token"]?.ToString() == token) { control = peer; reader = r; writer = new StreamWriter(peer.GetStream()) { AutoFlush = true }; break; } peer.Dispose(); accept = listener.AcceptTcpClientAsync(timeout.Token).AsTask(); }
        }
        finally { listener.Stop(); }
    }
    private sealed class Trial : IDisposable
    {
        public required string Id, Sni, File; public required int Port; public required Process Core; public List<double> Speeds = new();
        public HttpClient Client = new();
        public void Dispose() { Client.Dispose(); try { if (!Core.HasExited) Core.Kill(true); } catch { } Core.Dispose(); try { System.IO.File.Delete(File); } catch { } }
    }
    private static async Task<bool> Download(Trial t, CancellationToken ct)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(12));
        var sw = Stopwatch.StartNew();
        try
        { using var response = await t.Client.GetAsync("https://speed.cloudflare.com/__down?bytes=1048576", HttpCompletionOption.ResponseHeadersRead, limit.Token); if (response.StatusCode != HttpStatusCode.OK) return false; await using var stream = await response.Content.ReadAsStreamAsync(limit.Token); var buffer = new byte[16384]; int n, total = 0; while ((n = await stream.ReadAsync(buffer, limit.Token)) > 0) { total += n; if (total > 1048576) return false; } if (total != 1048576) return false; t.Speeds.Add(1048576 / sw.Elapsed.TotalSeconds); return true; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
        catch (HttpRequestException) { return false; }
    }
    private static async Task<bool> Initial(Trial t, CancellationToken ct)
    {
        try
        { using var c = CancellationTokenSource.CreateLinkedTokenSource(ct); c.CancelAfter(TimeSpan.FromSeconds(30)); using var response = await t.Client.GetAsync("https://example.com/", c.Token); if (response.StatusCode != HttpStatusCode.OK) return false; if (!await Download(t, c.Token)) return false; using var upload = await t.Client.PostAsync("https://speed.cloudflare.com/__up", new ByteArrayContent(new byte[65536]), c.Token); return upload.StatusCode == HttpStatusCode.OK; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
        catch (HttpRequestException) { return false; }
    }
    public static async Task<string> Prepare(string json, CancellationToken cancellation = default)
    {
        await Gate.WaitAsync(cancellation);
        var trials = new List<Trial>();
        try
        {
            if (!Supported)
                throw new InvalidOperationException("SNI Spoofing is unavailable on Windows ARM64.");
            var proxy = SniSpoofConfig.Proxy(json);
            var (address, port) = SniSpoofConfig.Endpoint(proxy);
            if (port != 443)
                throw new InvalidOperationException("SNI Spoofing requires Cloudflare port 443.");
            var iface = Interface();
            var key = address + ":" + port + ":" + iface + ":" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(proxy.ToJsonString())));
            if (key == activeKey && ControlAlive)
                return SniSpoofConfig.Apply(json, activePort);
            scan = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            scan.CancelAfter(TimeSpan.FromMinutes(5));
            var ct = scan.Token;
            Results.Clear();
            Show("SNI: resolving Cloudflare destination");
            var localAddresses = NetworkInterface.GetAllNetworkInterfaces().First(x => x.Name == iface).GetIPProperties().UnicastAddresses.Select(x => x.Address).Where(x => !IPAddress.IsLoopback(x) && !x.IsIPv6LinkLocal).ToArray();
            var ips = (await Dns.GetHostAddressesAsync(address, ct)).Where(SniSpoofConfig.IsCloudflare).Where(x => localAddresses.Any(a => a.AddressFamily == x.AddressFamily)).GroupBy(x => x.AddressFamily).OrderBy(x => x.Key == AddressFamily.InterNetwork ? 0 : 1).Select(x => x.First()).Take(2).ToArray();
            if (ips.Length == 0)
                throw new InvalidOperationException("DNS did not return a public Cloudflare address.");
            await Broker(ct);
            var candidates = new List<(string Sni, IPAddress Ip, double Ms)>();
            foreach (var ip in ips)
            { Show("SNI: scanning candidates on " + ip); using var proc = Start(Helper, "--scan", new IPEndPoint(ip, 443).ToString(), AppManager.Instance.Config.SniSpoofItem.LastSelectedSni, iface, GetInterfaceIndex(iface, ip.AddressFamily).ToString(), localAddresses.First(x => x.AddressFamily == ip.AddressFamily).ToString()); try { while (await proc.StandardOutput.ReadLineAsync(ct) is { } line) { var item = JsonNode.Parse(line)!; Results.Enqueue(item["sni"] + ": " + (item["ok"]!.GetValue<bool>() ? "initial TLS passed" : "initial TLS failed")); if (item["ok"]!.GetValue<bool>()) candidates.Add((item["sni"]!.ToString(), ip, item["ms"]!.GetValue<double>())); Show($"SNI: scanning ({candidates.Count} candidates)"); } } finally { if (!proc.HasExited) proc.Kill(true); } }
            foreach (var candidate in candidates.OrderBy(x => x.Ms).DistinctBy(x => x.Sni).Take(3))
            {
                ct.ThrowIfCancellationRequested();
                Show("SNI: checking real transfer — " + candidate.Sni);
                var id = Guid.NewGuid().ToString("N");
                var local = Port();
                await Command(new { cmd = "start", id, listen = "127.0.0.1:" + local, connect = new IPEndPoint(candidate.Ip, 443).ToString(), sni = candidate.Sni, @interface = iface, interfaceIndex = GetInterfaceIndex(iface, candidate.Ip.AddressFamily), localIp = NetworkInterface.GetAllNetworkInterfaces().First(x => x.Name == iface).GetIPProperties().UnicastAddresses.First(x => x.Address.AddressFamily == candidate.Ip.AddressFamily && !IPAddress.IsLoopback(x.Address) && !x.Address.IsIPv6LinkLocal).Address.ToString() }, ct);
                var cfg = JsonNode.Parse(SniSpoofConfig.Apply(json, local))!.AsObject();
                var socks = Port();
                cfg["inbounds"] = new JsonArray(new JsonObject { ["listen"] = "127.0.0.1", ["port"] = socks, ["protocol"] = "socks", ["settings"] = new JsonObject { ["udp"] = false } });
                cfg["log"] = new JsonObject { ["loglevel"] = "none" };
                cfg.Remove("api");
                cfg.Remove("stats");
                cfg["routing"] = new JsonObject { ["rules"] = new JsonArray(new JsonObject { ["type"] = "field", ["network"] = "tcp,udp", ["outboundTag"] = proxy["tag"]!.ToString() }) };
                var file = Path.Combine(sessionDir!, id + ".json");
                PrivateWarpProfileStore.Save(file, cfg.ToJsonString(), false);
                var core = Start(Xray, "run", "-config", file);
                var t = new Trial { Id = id, Sni = candidate.Sni, Port = local, File = file, Core = core, Client = new HttpClient(new SocketsHttpHandler { Proxy = new WebProxy("socks5://127.0.0.1:" + socks), UseProxy = true }) { Timeout = TimeSpan.FromSeconds(12) } };
                trials.Add(t);
                await Task.Delay(300, ct);
                if (core.HasExited)
                    throw new InvalidOperationException("The temporary Xray core could not start (exit " + core.ExitCode + "). Check bundled core/geodata files.");
                var initial = await Initial(t, ct);
                Results.Enqueue(candidate.Sni + ": " + (initial ? "transfer passed" : "transfer failed"));
                if (!initial)
                {
                    var diagnostics = await Command(new { cmd = "diagnostics" }, ct);
                    foreach (var line in diagnostics["lines"]!.AsArray().TakeLast(12)) Results.Enqueue(line!.ToString());
                    await Command(new { cmd = "stop", id }, ct); t.Dispose(); trials.Remove(t);
                }
            }
            if (trials.Count == 0)
                throw new InvalidOperationException("No SNI passed actual transfer tests.");
            Show("SNI: checking stability after 30 seconds idle");
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            var passed = new List<Trial>();
            foreach (var t in trials.OrderByDescending(x => x.Speeds.Average()).Take(2))
            { var stable = await Download(t, ct) && await Download(t, ct); Results.Enqueue(t.Sni + (stable ? ": idle stability passed" : ": idle stability failed")); if (stable) passed.Add(t); }
            var winner = passed.OrderByDescending(x => x.Speeds.Order().ElementAt(x.Speeds.Count / 2)).ThenBy(x => x.Sni, StringComparer.Ordinal).FirstOrDefault() ?? throw new InvalidOperationException("No SNI passed the idle stability test.");
            if (activeId.Length > 0)
                retiredIds.Add(activeId);
            activeId = winner.Id;
            activePort = winner.Port;
            activeKey = key;
            AppManager.Instance.Config.SniSpoofItem.LastSelectedSni = winner.Sni;
            await ConfigHandler.SaveConfig(AppManager.Instance.Config);
            foreach (var t in trials.Where(x => x != winner))
                await Command(new { cmd = "stop", id = t.Id }, ct);
            Results.Enqueue("Selected: " + winner.Sni + " — median download " + (winner.Speeds.Order().ElementAt(winner.Speeds.Count / 2) / 1048576).ToString("F2") + " MiB/s");
            Show("Selected fake SNI: " + winner.Sni);
            return SniSpoofConfig.Apply(json, activePort);
        }
        catch (Exception ex)
        {
            if (!HasActiveSession)
            { try { if (ControlAlive) await Command(new { cmd = "shutdown" }, CancellationToken.None); } catch { } control?.Dispose(); control = null; activeId = ""; activeKey = null; CleanupSession(); }
            Show("SNI: " + (ex is OperationCanceledException ? "Scan cancelled" : ex.Message));
            throw;
        }
        finally { foreach (var t in trials) { t.Dispose(); if (t.Id != activeId && ControlAlive) { try { await Command(new { cmd = "stop", id = t.Id }, CancellationToken.None); } catch { } } } scan?.Dispose(); scan = null; Gate.Release(); }
    }
    public static string ApplyVerified(string json) { if (activeKey == null || !HasActiveSession) throw new InvalidOperationException("SNI: select this profile and scan first."); var p = SniSpoofConfig.Proxy(json); var (a, port) = SniSpoofConfig.Endpoint(p); if (!activeKey.StartsWith(a + ":" + port + ":" + Interface() + ":", StringComparison.Ordinal)) throw new InvalidOperationException("SNI: this destination needs its own scan."); return SniSpoofConfig.Apply(json, activePort); }
    // Called after the old main core stops, so probes never interrupt its connections.
    public static async Task RetirePrevious()
    {
        await Gate.WaitAsync();
        try
        { foreach (var id in retiredIds) { try { if (ControlAlive) await Command(new { cmd = "stop", id }, CancellationToken.None); } catch { } } retiredIds.Clear(); }
        finally { Gate.Release(); }
    }
    private static void CleanupSession()
    {
        if (sessionDir == null)
            return;
        try
        { Directory.Delete(sessionDir, true); }
        catch { }
        sessionDir = null;
    }
    public static async Task Stop() { Cancel(); await Gate.WaitAsync(); try { if (ControlAlive) { try { await Command(new { cmd = "shutdown" }, CancellationToken.None); } catch { } } control?.Dispose(); control = null; activeKey = null; activeId = ""; retiredIds.Clear(); CleanupSession(); Show("SNI: off"); } finally { Gate.Release(); } }
}
