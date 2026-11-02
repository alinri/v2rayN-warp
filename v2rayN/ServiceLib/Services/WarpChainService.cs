namespace ServiceLib.Services;

public static class WarpChainService
{
    public static string ProfilePath(Config config) => Utils.GetConfigPath(config.WarpChainItem.ProfileFile);

    public static string ReadProfile(Config config)
    {
        var path = ProfilePath(config);
        if (!File.Exists(path))
            throw new InvalidOperationException("WARP profile is missing. Click Create WARP first.");
        return File.ReadAllText(path);
    }

    public static string PhysicalInterface()
    {
        var physical = NetworkInterface.GetAllNetworkInterfaces()
            .Where(x => x.OperationalStatus == OperationalStatus.Up
                && (x.NetworkInterfaceType == NetworkInterfaceType.Ethernet
                    || x.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                && x.GetIPProperties().UnicastAddresses.Any(a => !IPAddress.IsLoopback(a.Address)
                    && a.Address.AddressFamily == AddressFamily.InterNetwork))
            .OrderBy(x => x.Name, StringComparer.Ordinal).FirstOrDefault()?.Name;
        if (physical == null)
            throw new InvalidOperationException("WARP needs an active Ethernet or Wi-Fi connection.");
        return physical;
    }

    public static string Apply(Config config, string json) => WarpChainConfig.Apply(json, ReadProfile(config), PhysicalInterface());
}
