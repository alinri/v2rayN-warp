using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ServiceLib.Services;

internal static class WarpRegistrationTests
{
    private sealed class Handler : HttpMessageHandler
    {
        public int Posts, Patches, Deletes, Puts, Gets;
        public bool InvalidPeer;
        public bool Blocked;
        public bool LicenseRejected, InactivePlus, ExplicitLicenseFailure;
        public const string License = "AAAAAAAA-BBBBBBBB-CCCCCCCC";
        public string? DevicePublicKey;
        public string? EdgePublicKey;
        public string DeviceId = Guid.NewGuid().ToString();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Assert(request.RequestUri!.Host == "api.cloudflareclient.com", "Only Cloudflare receives registration");
            Assert(request.Headers.Contains("CF-Client-Version"), "Send the API client revision");
            if (request.Method == HttpMethod.Post)
            {
                Posts++;
                if (Blocked) return new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent("private-body-must-not-appear") };
                var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!;
                Assert(Convert.FromBase64String(body["key"]!.GetValue<string>()).Length == 32, "Bootstrap key format");
                Assert(DateTimeOffset.TryParse(body["tos"]!.GetValue<string>(), out _), "Explicit accepted terms timestamp");
                Assert(!body.ToJsonString().Contains("privateKey"), "Do not transmit private keys");
                return Json(new JsonObject { ["id"] = DeviceId, ["token"] = "fake-test-token" });
            }
            Assert(request.Headers.Authorization?.Parameter == "fake-test-token", "Enrollment uses the returned token");
            if (request.RequestUri.AbsolutePath.EndsWith("/" + DeviceId + "/account"))
            {
                if (request.Method == HttpMethod.Put)
                {
                    Puts++;
                    var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!;
                    Assert(body.AsObject().Count == 1 && body["license"]!.GetValue<string>() == License,
                        "Send only the license to the newly created device account");
                    Assert(Patches > 0, "Enroll the new device key before attaching the subscription");
                    if (LicenseRejected) return new HttpResponseMessage(HttpStatusCode.BadRequest)
                        { Content = new StringContent("secret-license-response-" + License) };
                    if (ExplicitLicenseFailure) return Json(new JsonObject { ["success"] = false });
                    // The real API can omit success and return account fields directly.
                    return Json(new JsonObject { ["id"] = "fake-account", ["warp_plus"] = true });
                }
                Assert(request.Method == HttpMethod.Get, "Never remove a subscription or alter other devices");
                Gets++;
                Assert(Puts == 1, "Read back the account after linking the license");
                return Json(new JsonObject { ["id"] = "fake-account", ["warp_plus"] = !InactivePlus, ["license"] = License });
            }
            Assert(request.RequestUri.AbsolutePath.EndsWith("/" + DeviceId), "Operate only on the newly created device");
            if (request.Method == HttpMethod.Delete) { Deletes++; return new HttpResponseMessage(HttpStatusCode.NoContent); }
            Patches++;
            var enroll = JsonNode.Parse(await request.Content!.ReadAsStringAsync(token))!;
            Assert(enroll["key_type"]!.GetValue<string>() == "secp256r1", "MASQUE key type");
            Assert(enroll["tunnel_type"]!.GetValue<string>() == "masque", "MASQUE enrollment");
            Assert(!enroll.ToJsonString().Contains("privateKey"), "Private device key stays local");
            DevicePublicKey = enroll["key"]!.GetValue<string>();
            using var edge = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            EdgePublicKey = Convert.ToBase64String(edge.ExportSubjectPublicKeyInfo());
            return Json(new JsonObject { ["config"] = new JsonObject
            {
                ["interface"] = new JsonObject { ["addresses"] = new JsonObject { ["v4"] = "172.16.0.2", ["v6"] = "2606:4700:110::2" } },
                ["peers"] = new JsonArray(new JsonObject
                {
                    ["public_key"] = InvalidPeer ? "invalid" : EdgePublicKey,
                    ["endpoint"] = new JsonObject { ["v4"] = "162.159.198.1:0" }
                })
            }});
        }

        private static HttpResponseMessage Json(JsonNode data) => new(HttpStatusCode.OK)
            { Content = new StringContent(data.ToJsonString(), Encoding.UTF8, "application/json") };
    }

    private static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }

    public static async Task RunAsync()
    {
        var bootstrap = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Assert(WarpRegistrationClient.ParseBootstrapPublicKey("PrivateKey: secret-test-only\nPassword (PublicKey): " + bootstrap + "\nHash32: ignored\n") == bootstrap,
            "Parse current Xray wg output without reading the private key or hash");
        Assert(WarpRegistrationClient.ParseBootstrapPublicKey("PublicKey: " + bootstrap + "\r\n") == bootstrap, "Parse legacy Xray public-key label");
        try { WarpRegistrationClient.ParseBootstrapPublicKey("PrivateKey: ignored\nHash32: ignored\n"); throw new Exception("Never use a private key as public key"); }
        catch (InvalidOperationException) { }
        using var handler = new Handler();
        using var http = new HttpClient(handler);
        var registrar = new WarpRegistrationClient(http);
        try { await registrar.RegisterAsync(bootstrap, false, null, default); throw new Exception("Terms must be accepted first"); }
        catch (InvalidOperationException) { }
        Assert(handler.Posts == 0, "No request before terms acceptance");
        var json = await registrar.RegisterAsync(bootstrap, true, null, default);
        var profile = JsonNode.Parse(json)!;
        var warp = profile["streamSettings"]!["masqueSettings"]!["warp"]!;
        using var deviceKey = ECDsa.Create();
        deviceKey.ImportPkcs8PrivateKey(Convert.FromBase64String(warp["privateKey"]!.GetValue<string>()), out _);
        Assert(Convert.ToBase64String(deviceKey.ExportSubjectPublicKeyInfo()) == handler.DevicePublicKey, "Saved private key matches enrolled public key");
        Assert(warp["publicKey"]!.GetValue<string>() == handler.EdgePublicKey, "Pin the authenticated endpoint key");
        Assert(profile["settings"]!["port"]!.GetValue<int>() == 443, "MASQUE uses HTTPS, not the bootstrap WireGuard port");
        Assert(profile["settings"]!["address"]!.GetValue<string>() == "162.159.198.2", "Use the H2 TCP edge instead of the enrolled QUIC edge");
        Assert(profile["streamSettings"]!["tlsSettings"]!["alpn"]![0]!.GetValue<string>() == "h2", "HTTP/2 profile");
        Assert(profile["streamSettings"]!["tlsSettings"]!["fingerprint"]!.GetValue<string>() == "safari", "Non-Chrome fingerprint");
        Assert(warp["address"]![0]!.GetValue<string>() == "172.16.0.2/32", "Normalize tunnel prefixes");
        Assert(handler.Posts == 1 && handler.Patches == 1 && handler.Deletes == 0, "Register once and enroll once");
        Assert(!json.Contains("fake-test-token"), "Do not persist the registration API token");
        Assert(handler.Puts == 0 && handler.Gets == 0, "Free registration does not access subscription endpoints");
        handler.InvalidPeer = true;
        try { await registrar.RegisterAsync(bootstrap, true, null, default); throw new Exception("Invalid peer must fail"); }
        catch (FormatException) { }
        Assert(handler.Deletes == 1, "Clean up only the failed new registration");
        handler.Blocked = true;
        var requests = handler.Posts;
        try { await registrar.RegisterAsync(bootstrap, true, null, default); throw new Exception("HTTP error must fail"); }
        catch (InvalidOperationException ex) { Assert(!ex.Message.Contains("private-body"), "Do not display API response bodies"); }
        Assert(handler.Posts == requests + 1, "Never retry account creation silently");

        using var plusHandler = new Handler();
        using var plusHttp = new HttpClient(plusHandler);
        var plusRegistrar = new WarpRegistrationClient(plusHttp);
        try { await plusRegistrar.RegisterAsync(bootstrap, false, null, default, Handler.License); throw new Exception("Plus also requires terms"); }
        catch (InvalidOperationException) { }
        try { await plusRegistrar.RegisterAsync(bootstrap, true, null, default, "key with whitespace"); throw new Exception("Validate license before registering"); }
        catch (InvalidOperationException) { }
        Assert(plusHandler.Posts == 0, "No device created for missing consent or malformed license");
        var plusJson = await plusRegistrar.RegisterAsync(bootstrap, true, null, default, " " + Handler.License + " ");
        Assert(WarpProfilePolicy.RequestsPlus(plusJson), "Remember the licensed profile in its saved outbound tag");
        Assert(!WarpProfilePolicy.RequestsPlus(json), "Existing free profiles remain compatible");
        Assert(plusHandler.Posts == 1 && plusHandler.Patches == 1 && plusHandler.Puts == 1 && plusHandler.Gets == 1 && plusHandler.Deletes == 0,
            "Register a separate device, bind the paid license once, then confirm its account");
        Assert(!plusJson.Contains(Handler.License) && !plusJson.Contains("fake-test-token"), "Neither license nor token is saved in the profile");
        Assert(WarpProfilePolicy.ValidateTrace(plusJson, "ip=192.0.2.1\r\nwarp=plus\r\n") == "WARP+", "Require live Plus confirmation");
        Assert(WarpProfilePolicy.ValidateTrace(json, "warp=on\n") == "WARP", "Free WARP still works");
        Assert(WarpProfilePolicy.ValidateTrace(json, "warp=plus\n") == "WARP+", "Display actual Plus mode for unmarked imports");
        Assert(WarpProfilePolicy.ValidateTrace(plusJson, "warp=on\n") == "WARP (license accepted; Plus not confirmed)",
            "Accept a working licensed WARP connection and label its observed tier honestly");
        foreach (var trace in new[] { "warp=off\n", "other=warp=plus\n", "warp=plus-extra\n" })
        {
            try { WarpProfilePolicy.ValidateTrace(plusJson, trace); throw new Exception("Reject a non-WARP connection"); }
            catch (InvalidOperationException) { }
        }
        const string proxyConfig = """{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443}]}}]}""";
        var chainedPlus = JsonNode.Parse(WarpChainConfig.Apply(proxyConfig, plusJson, "en0"))!;
        Assert(chainedPlus["outbounds"]![1]!["tag"]!.GetValue<string>() == WarpChainConfig.Tag,
            "Plus profile uses the normal runtime chain tag");
        Assert(chainedPlus["outbounds"]![0]!["streamSettings"]!["sockopt"]!["dialerProxy"]!.GetValue<string>() == WarpChainConfig.Tag,
            "Plus stays before the selected proxy");

        using (var acceptedHandler = new Handler { InactivePlus = true })
        using (var acceptedHttp = new HttpClient(acceptedHandler))
        {
            var accepted = await new WarpRegistrationClient(acceptedHttp).RegisterAsync(bootstrap, true, null, default, Handler.License);
            Assert(WarpProfilePolicy.RequestsPlus(accepted) && acceptedHandler.Deletes == 0,
                "An accepted license is usable even when the account does not advertise Plus");
        }
        foreach (var failure in new[] { "http", "explicit" })
        {
            using var failedHandler = new Handler
                { LicenseRejected = failure == "http", InactivePlus = failure == "inactive", ExplicitLicenseFailure = failure == "explicit" };
            using var failedHttp = new HttpClient(failedHandler);
            try
            {
                await new WarpRegistrationClient(failedHttp).RegisterAsync(bootstrap, true, null, default, Handler.License);
                throw new Exception("Unconfirmed WARP+ must not produce a profile");
            }
            catch (InvalidOperationException ex)
            {
                Assert(!ex.Message.Contains(Handler.License) && !ex.Message.Contains("secret-license-response"), "Hide license and response bodies on failure");
            }
            Assert(failedHandler.Posts == 1 && failedHandler.Puts == 1 && failedHandler.Deletes == 1,
                "Do not retry license attachment; cleanup removes only the new device");
        }

        var directory = Path.Combine(Path.GetTempPath(), "warp-store-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "warp-entry.private.json");
            Assert(PrivateWarpProfileStore.Save(path, "old-profile") == null, "No backup is needed for first save");
            var backup = PrivateWarpProfileStore.Save(path, "new-profile");
            Assert(File.ReadAllText(path) == "new-profile" && File.ReadAllText(backup!) == "old-profile", "Atomic replacement preserves old profile");
            Assert(!Directory.EnumerateFiles(directory, "*.tmp").Any(), "No leftover temporary files");
            var count = Directory.EnumerateFiles(directory).Count();
            Assert(PrivateWarpProfileStore.Save(path, "runtime-config", backupExisting: false) == null
                && Directory.EnumerateFiles(directory).Count() == count, "Runtime regeneration does not accumulate private backups");
            if (!OperatingSystem.IsWindows())
            {
                Assert(File.GetUnixFileMode(path) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "Private profile permissions");
                Assert(File.GetUnixFileMode(backup!) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "Private backup permissions");
            }
        }
        finally { Directory.Delete(directory, true); }
        Console.WriteLine("PASS: consent, MASQUE enrollment, WARP+ account linking and independent proof, credential isolation, cleanup and private backups");
    }
}
