using System.Net.Http;

namespace ServiceLib.Services;

public static class WarpProfileCreationService
{
    public static async Task<string> CreateAsync(bool acceptedTerms, bool useProxy,
        IProgress<string> progress, CancellationToken cancellationToken, string? licenseKey = null)
    {
        if (!acceptedTerms) throw new InvalidOperationException("Accept Cloudflare's WARP terms first.");
        var core = CoreInfoManager.Instance.GetCoreExecFile(CoreInfoManager.Instance.GetCoreInfo(ECoreType.Xray), out _);
        if (string.IsNullOrEmpty(core)) throw new InvalidOperationException("The Xray core is missing.");
        progress.Report("Preparing a fresh device key…");
        using var bootstrap = new Process { StartInfo = new ProcessStartInfo(core)
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
        }};
        bootstrap.StartInfo.ArgumentList.Add("wg");
        bootstrap.Start();
        using var keyTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        keyTimeout.CancelAfter(TimeSpan.FromSeconds(10));
        string output;
        try
        {
            var stdout = bootstrap.StandardOutput.ReadToEndAsync(keyTimeout.Token);
            var stderr = bootstrap.StandardError.ReadToEndAsync(keyTimeout.Token);
            await bootstrap.WaitForExitAsync(keyTimeout.Token);
            output = await stdout;
            _ = await stderr;
        }
        finally { if (!bootstrap.HasExited) bootstrap.Kill(true); }
        if (bootstrap.ExitCode != 0)
            throw new InvalidOperationException("Xray could not prepare a WARP registration key.");
        var publicKey = WarpRegistrationClient.ParseBootstrapPublicKey(output);
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = useProxy,
            ConnectTimeout = TimeSpan.FromSeconds(15), MaxResponseHeadersLength = 32 };
        if (useProxy) handler.Proxy = new WebProxy("http://127.0.0.1:" + AppManager.Instance.GetLocalPort(EInboundProtocol.socks));
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(40) };
        return await new WarpRegistrationClient(client).RegisterAsync(publicKey, acceptedTerms, progress, cancellationToken, licenseKey);
    }

    public static async Task<string> TestAsync(string profile, CancellationToken cancellationToken)
    {
        var outbound = JsonNode.Parse(profile)!.AsObject();
        var physical = WarpChainService.PhysicalInterface();
        if (outbound["streamSettings"] is not JsonObject stream)
            throw new InvalidOperationException("Invalid WARP profile.");
        stream["sockopt"] = new JsonObject { ["interface"] = physical };
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var config = new JsonObject
        {
            ["log"] = new JsonObject { ["loglevel"] = "none" },
            ["inbounds"] = new JsonArray(new JsonObject { ["listen"] = "127.0.0.1", ["port"] = port,
                ["protocol"] = "socks", ["settings"] = new JsonObject { ["udp"] = false } }),
            ["outbounds"] = new JsonArray(outbound)
        };
        var path = Utils.GetTempPath("warp-test-" + Guid.NewGuid().ToString("N") + ".private.json");
        var core = CoreInfoManager.Instance.GetCoreExecFile(CoreInfoManager.Instance.GetCoreInfo(ECoreType.Xray), out _);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(25));
        using var process = new Process { StartInfo = new ProcessStartInfo(core)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true } };
        try
        {
            PrivateWarpProfileStore.Save(path, config.ToJsonString());
            process.StartInfo.ArgumentList.Add("run");
            process.StartInfo.ArgumentList.Add("-c");
            process.StartInfo.ArgumentList.Add(path);
            process.Start();
            _ = process.StandardOutput.ReadToEndAsync(timeout.Token);
            _ = process.StandardError.ReadToEndAsync(timeout.Token);
            for (var attempt = 0; ; attempt++)
            {
                timeout.Token.ThrowIfCancellationRequested();
                if (process.HasExited) throw new InvalidOperationException("The Xray core could not start the WARP test.");
                try
                {
                    using var socket = new TcpClient();
                    await socket.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
                    break;
                }
                catch (SocketException) when (attempt < 40) { await Task.Delay(100, timeout.Token); }
            }
            using var client = new HttpClient(new SocketsHttpHandler
            {
                Proxy = new WebProxy("socks5://127.0.0.1:" + port), UseProxy = true, AllowAutoRedirect = false
            });
            using var response = await client.GetAsync("https://www.cloudflare.com/cdn-cgi/trace", timeout.Token);
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException("The WARP connectivity test failed.");
            var trace = await response.Content.ReadAsStringAsync(timeout.Token);
            return WarpProfilePolicy.ValidateTrace(profile, trace);
        }
        finally
        {
            try { if (process.Id > 0 && !process.HasExited) { process.Kill(true); await process.WaitForExitAsync(); } }
            catch (InvalidOperationException) { }
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
