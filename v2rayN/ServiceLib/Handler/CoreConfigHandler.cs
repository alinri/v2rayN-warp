namespace ServiceLib.Handler;

/// <summary>
/// Core configuration file processing class
/// </summary>
public static class CoreConfigHandler
{
    private static readonly string _tag = "CoreConfigHandler";

    public static async Task<RetResult> GenerateClientConfig(ProfileItem node, string? fileName)
    {
        var config = AppManager.Instance.Config;
        var result = new RetResult();

        if (node.ConfigType == EConfigType.Custom)
        {
            result = node.CoreType switch
            {
                ECoreType.mihomo => await new CoreConfigClashService(config).GenerateClientCustomConfig(node, fileName),
                ECoreType.sing_box => await new CoreConfigSingboxService(config).GenerateClientCustomConfig(node, fileName),
                _ => await GenerateClientCustomConfig(node, fileName)
            };
        }
        else if (AppManager.Instance.GetCoreType(node, node.ConfigType) == ECoreType.sing_box)
        {
            result = await new CoreConfigSingboxService(config).GenerateClientConfigContent(node);
        }
        else
        {
            result = await new CoreConfigV2rayService(config).GenerateClientConfigContent(node);
        }
        if (result.Success != true)
        {
            return result;
        }
        if (config.SniSpoofItem.Enabled && Path.GetFileName(fileName) != Global.CorePreConfigFileName)
        {
            try
            {
                if (node.ConfigType == EConfigType.Custom || AppManager.Instance.GetCoreType(node, node.ConfigType) != ECoreType.Xray)
                    throw new InvalidOperationException("SNI Spoofing requires a regular Xray profile.");
                result.Data = await SniSpoofService.Prepare(result.Data!.ToString()!);
            }
            catch (Exception ex)
            {
                if (!SniSpoofService.HasActiveSession)
                { config.SniSpoofItem.Enabled = false; config.WarpChainItem.Enabled = SniSpoofService.PreviousWarp; await ConfigHandler.SaveConfig(config); }
                SniSpoofService.NotifyFailure(ex.Message);
                return new RetResult(false, "SNI: " + ex.Message);
            }
        }
        // The TUN pre-service only feeds the main Xray core over loopback.
        if (config.WarpChainItem.Enabled && !config.SniSpoofItem.Enabled && Path.GetFileName(fileName) != Global.CorePreConfigFileName)
        {
            result = ApplyWarp(config, result, AppManager.Instance.GetCoreType(node, node.ConfigType), node.ConfigType == EConfigType.Custom);
            if (!result.Success)
                return result;
        }
        if (fileName.IsNotEmpty() && result.Data != null)
        {
            if (config.WarpChainItem.Enabled || config.SniSpoofItem.Enabled)
                PrivateWarpProfileStore.Save(fileName!, result.Data.ToString()!, backupExisting: false);
            else
                await File.WriteAllTextAsync(fileName, result.Data.ToString());
        }

        return result;
    }

    private static RetResult ApplyWarp(Config config, RetResult result, ECoreType coreType, bool custom = false)
    {
        if (!result.Success || !config.WarpChainItem.Enabled)
            return result;
        if (coreType != ECoreType.Xray || custom)
            return new RetResult(false, "WARP needs a regular Xray profile. Select Xray as the core.");
        try
        {
            result.Data = WarpChainService.Apply(config, result.Data!.ToString()!);
            return result;
        }
        catch (Exception ex)
        {
            return new RetResult(false, ex is InvalidOperationException ? ex.Message : "Cannot load the private WARP profile. Check its format and permissions.");
        }
    }

    private static async Task<RetResult> GenerateClientCustomConfig(ProfileItem node, string? fileName)
    {
        var ret = new RetResult();
        try
        {
            if (node == null || fileName is null)
            {
                ret.Msg = ResUI.CheckServerSettings;
                return ret;
            }

            if (File.Exists(fileName))
            {
                File.SetAttributes(fileName, FileAttributes.Normal); //If the file has a read-only attribute, direct deletion will fail
                File.Delete(fileName);
            }

            var addressFileName = node.Address;
            if (!File.Exists(addressFileName))
            {
                addressFileName = Utils.GetConfigPath(addressFileName);
            }
            if (!File.Exists(addressFileName))
            {
                ret.Msg = ResUI.FailedGenDefaultConfiguration;
                return ret;
            }
            File.Copy(addressFileName, fileName);
            File.SetAttributes(fileName, FileAttributes.Normal); //Copy will keep the attributes of addressFileName, so we need to add write permissions to fileName just in case of addressFileName is a read-only file.

            //check again
            if (!File.Exists(fileName))
            {
                ret.Msg = ResUI.FailedGenDefaultConfiguration;
                return ret;
            }

            ret.Msg = string.Format(ResUI.SuccessfulConfiguration, "");
            ret.Success = true;
            return await Task.FromResult(ret);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            ret.Msg = ResUI.FailedGenDefaultConfiguration;
            return ret;
        }
    }

    public static async Task<RetResult> GenerateClientSpeedtestConfig(Config config, string fileName, List<ServerTestItem> selecteds, ECoreType coreType)
    {
        var result = new RetResult();
        if (coreType == ECoreType.sing_box)
        {
            result = await new CoreConfigSingboxService(config).GenerateClientSpeedtestConfig(selecteds);
        }
        else if (coreType == ECoreType.Xray)
        {
            result = await new CoreConfigV2rayService(config).GenerateClientSpeedtestConfig(selecteds);
        }
        if (config.SniSpoofItem.Enabled && result.Success)
        {
            try
            { result.Data = SniSpoofService.ApplyVerified(result.Data!.ToString()!); }
            catch (Exception ex) { return new RetResult(false, ex.Message); }
        }
        result = ApplyWarp(config, result, coreType);
        if (result.Success != true)
        {
            return result;
        }
        if (config.WarpChainItem.Enabled || config.SniSpoofItem.Enabled)
            PrivateWarpProfileStore.Save(fileName, result.Data.ToString()!, backupExisting: false);
        else
            await File.WriteAllTextAsync(fileName, result.Data.ToString());
        return result;
    }

    public static async Task<RetResult> GenerateClientSpeedtestConfig(Config config, ProfileItem node, ServerTestItem testItem, string fileName)
    {
        var result = new RetResult();
        var initPort = AppManager.Instance.GetLocalPort(EInboundProtocol.speedtest);
        var port = Utils.GetFreePort(initPort + testItem.QueueNum);
        testItem.Port = port;

        if (AppManager.Instance.GetCoreType(node, node.ConfigType) == ECoreType.sing_box)
        {
            result = await new CoreConfigSingboxService(config).GenerateClientSpeedtestConfig(node, port);
        }
        else
        {
            result = await new CoreConfigV2rayService(config).GenerateClientSpeedtestConfig(node, port);
        }
        if (config.SniSpoofItem.Enabled && result.Success)
        {
            try
            { result.Data = SniSpoofService.ApplyVerified(result.Data!.ToString()!); }
            catch (Exception ex) { return new RetResult(false, ex.Message); }
        }
        result = ApplyWarp(config, result, AppManager.Instance.GetCoreType(node, node.ConfigType));
        if (result.Success != true)
        {
            return result;
        }

        if (config.WarpChainItem.Enabled || config.SniSpoofItem.Enabled)
            PrivateWarpProfileStore.Save(fileName, result.Data.ToString()!, backupExisting: false);
        else
            await File.WriteAllTextAsync(fileName, result.Data.ToString());
        return result;
    }
}
