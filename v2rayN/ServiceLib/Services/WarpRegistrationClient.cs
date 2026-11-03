using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ServiceLib.Services;

/// <summary>Enroll a separate P-256 WARP MASQUE device. Never modifies an existing registration.</summary>
public sealed class WarpRegistrationClient(HttpClient client)
{
    private const string Api = "https://api.cloudflareclient.com/v0a4471/";

    public static string ParseBootstrapPublicKey(string output)
    {
        var match = System.Text.RegularExpressions.Regex.Match(output,
            @"(?m)^(?:PublicKey|Password \(PublicKey\)):\s*([A-Za-z0-9+/_=-]+)[ \t]*\r?$");
        if (!match.Success) throw new InvalidOperationException("Xray did not return a WARP registration public key.");
        var text = match.Groups[1].Value.Replace('-', '+').Replace('_', '/');
        text = text.PadRight((text.Length + 3) / 4 * 4, '=');
        var key = Convert.FromBase64String(text);
        if (key.Length != 32) throw new InvalidOperationException("Xray returned an invalid WARP registration key.");
        return Convert.ToBase64String(key);
    }

    public async Task<string> RegisterAsync(string bootstrapPublicKey, bool acceptedTerms,
        IProgress<string>? progress, CancellationToken cancellationToken, string? licenseKey = null)
    {
        if (!acceptedTerms) throw new InvalidOperationException("Accept Cloudflare's WARP terms before creating a registration.");
        licenseKey = licenseKey?.Trim();
        var plus = !string.IsNullOrEmpty(licenseKey);
        if (plus && (licenseKey!.Length > 256 || licenseKey.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new InvalidOperationException("Enter the WARP+ license key from your Cloudflare account, without spaces.");
        if (Convert.FromBase64String(bootstrapPublicKey).Length != 32)
            throw new InvalidOperationException("The bootstrap key is invalid.");
        using var deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        progress?.Report("Registering a new WARP device…");
        var registration = await RequestAsync(HttpMethod.Post, "reg", null, new JsonObject
        {
            ["key"] = bootstrapPublicKey,
            ["tos"] = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
            ["type"] = "PC", ["model"] = "v2rayN WARP", ["name"] = "v2rayN WARP"
        }, cancellationToken);
        var id = registration["id"]?.GetValue<string>();
        var token = registration["token"]?.GetValue<string>();
        if (!Guid.TryParse(id, out _) || string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException("Cloudflare returned an incomplete registration. The current WARP configuration was not changed.");
        try
        {
            progress?.Report("Enrolling the WARP HTTP/2 key…");
            var enrolled = await RequestAsync(HttpMethod.Patch, "reg/" + id, token, new JsonObject
            {
                ["key"] = Convert.ToBase64String(deviceKey.ExportSubjectPublicKeyInfo()),
                ["key_type"] = "secp256r1", ["tunnel_type"] = "masque", ["name"] = "v2rayN WARP"
            }, cancellationToken);
            var config = enrolled["config"];
            var peer = config?["peers"]?.AsArray().FirstOrDefault()
                ?? throw new InvalidOperationException("Cloudflare did not return a MASQUE peer.");
            var publicKey = peer["public_key"]?.GetValue<string>() ?? "";
            // This key is received over authenticated HTTPS and pins the MASQUE edge certificate.
            using var edgeKey = ECDsa.Create();
            var edgeDer = publicKey.Contains("BEGIN PUBLIC KEY", StringComparison.Ordinal)
                ? Convert.FromBase64String(string.Concat(publicKey.Split('\n').Where(x => !x.StartsWith("-----")).Select(x => x.Trim())))
                : Convert.FromBase64String(publicKey);
            edgeKey.ImportSubjectPublicKeyInfo(edgeDer, out var consumed);
            if (consumed != edgeDer.Length || edgeKey.KeySize != 256)
                throw new InvalidOperationException("Cloudflare returned an invalid MASQUE endpoint key.");
            var addresses = new JsonArray();
            foreach (var family in new[] { "v4", "v6" })
            {
                var value = config?["interface"]?["addresses"]?[family]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(value)) continue;
                var bare = value.Split('/')[0];
                if (!IPAddress.TryParse(bare, out var address))
                    throw new InvalidOperationException("Cloudflare returned an invalid tunnel address.");
                addresses.Add(address + (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "/32" : "/128"));
            }
            if (addresses.Count == 0) throw new InvalidOperationException("Cloudflare did not assign a tunnel address.");
            if (plus)
            {
                progress?.Report("Connecting this new device to your WARP+ subscription…");
                var linked = await RequestAsync(HttpMethod.Put, "reg/" + id + "/account", token,
                    new JsonObject { ["license"] = licenseKey }, cancellationToken);
                if (linked["success"]?.GetValue<bool>() == false)
                    throw new InvalidOperationException("Cloudflare did not accept the WARP+ license. Your active profile was not changed.");
                // Successful PUT responses do not necessarily contain a success field.
                // Read the account independently; a paid key must never silently yield a free profile.
                var account = await RequestAsync(HttpMethod.Get, "reg/" + id + "/account", token, null, cancellationToken);
                if (account["warp_plus"]?.GetValue<bool>() != true)
                    throw new InvalidOperationException("Cloudflare has not enabled WARP+ for this device. Check your subscription and available device slots. Your active profile was not changed.");
            }
            // The enrollment response may list a QUIC endpoint. H2 has its own TCP edge.
            const string endpointH2 = "162.159.198.2";
            return new JsonObject
            {
                ["tag"] = plus ? WarpProfilePolicy.PlusTag : WarpChainConfig.Tag, ["protocol"] = "masque",
                ["settings"] = new JsonObject { ["address"] = endpointH2, ["port"] = 443 },
                ["streamSettings"] = new JsonObject
                {
                    ["network"] = "masque", ["security"] = "tls",
                    ["tlsSettings"] = new JsonObject
                    {
                        ["serverName"] = "consumer-masque.cloudflareclient.com",
                        ["alpn"] = new JsonArray("h2"), ["fingerprint"] = "safari"
                    },
                    ["masqueSettings"] = new JsonObject { ["warp"] = new JsonObject
                    {
                        ["privateKey"] = Convert.ToBase64String(deviceKey.ExportPkcs8PrivateKey()),
                        ["publicKey"] = Convert.ToBase64String(edgeDer), ["address"] = addresses
                    }}
                }
            }.ToJsonString(new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerOptions.Default) { WriteIndented = true });
        }
        catch
        {
            // Cleanup is confined to the device created by this call, never the active device.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await RequestAsync(HttpMethod.Delete, "reg/" + id, token, null, cleanup.Token); }
            catch { /* Do not log a registration token or Cloudflare response body. */ }
            throw;
        }
    }

    private async Task<JsonNode> RequestAsync(HttpMethod method, string path, string? token,
        JsonObject? body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, Api + path);
        request.Headers.Add("CF-Client-Version", "a-6.35-4471");
        request.Headers.UserAgent.ParseAdd("WARP for Android");
        if (token != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body != null) request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(response.StatusCode == HttpStatusCode.TooManyRequests
                ? "Cloudflare rate-limited registration. Wait before trying again."
                : path.EndsWith("/account", StringComparison.Ordinal)
                ? $"Cloudflare rejected the WARP+ request (HTTP {(int)response.StatusCode}). Check the license and available device slots. Your active profile was not changed."
                : $"Cloudflare rejected WARP registration (HTTP {(int)response.StatusCode}). Try registering through a working proxy.");
        if (method == HttpMethod.Delete) return new JsonObject();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var data = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken)) != 0)
        {
            if (data.Length + count > 128 * 1024) throw new InvalidOperationException("Cloudflare returned an oversized registration response.");
            data.Write(buffer, 0, count);
        }
        return JsonNode.Parse(data.ToArray())
            ?? throw new InvalidOperationException("Cloudflare returned an empty registration response.");
    }
}
