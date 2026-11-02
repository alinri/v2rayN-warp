namespace ServiceLib.ViewModels;

public class WarpProfileViewModel : ReactiveObject
{
    [Reactive] public bool TermsAccepted { get; set; }
    [Reactive] public bool UseCurrentProxy { get; set; } = true;
    [Reactive] public bool IsBusy { get; set; }
    [Reactive] public bool HasCandidate { get; set; }
    [Reactive] public bool TestPassed { get; set; }
    [Reactive] public string Status { get; set; } = "Create a new WARP HTTP/2 profile. Your active configuration stays in place until you choose Use this config.";
    public ReactiveCommand<Unit, Unit> CreateCmd { get; }
    public ReactiveCommand<Unit, Unit> TestCmd { get; }
    public ReactiveCommand<Unit, Unit> UseCmd { get; }
    private string? _candidate;
    private CancellationTokenSource? _cancellation;

    public WarpProfileViewModel()
    {
        var draft = Utils.GetConfigPath("warp-draft.private.json");
        var existing = false;
        if (!File.Exists(draft))
        {
            draft = WarpChainService.ProfilePath(AppManager.Instance.Config);
            existing = true;
        }
        if (File.Exists(draft))
        {
            try
            {
                var json = File.ReadAllText(draft);
                if (JsonNode.Parse(json)?["protocol"]?.GetValue<string>() == "masque")
                {
                    _candidate = json;
                    HasCandidate = true;
                    Status = existing ? "Your current WARP profile is loaded for testing. Choose Create to register a separate new profile."
                        : "A saved WARP draft is ready. Test it before using it.";
                }
            }
            catch { Status = "The saved draft could not be read. You can create a new profile."; }
        }
        CreateCmd = ReactiveCommand.CreateFromTask(CreateAsync,
            this.WhenAnyValue(x => x.TermsAccepted, x => x.IsBusy, (accepted, busy) => accepted && !busy));
        TestCmd = ReactiveCommand.CreateFromTask(TestAsync,
            this.WhenAnyValue(x => x.HasCandidate, x => x.IsBusy, (exists, busy) => exists && !busy));
        UseCmd = ReactiveCommand.CreateFromTask(UseAsync,
            this.WhenAnyValue(x => x.TestPassed, x => x.IsBusy, (passed, busy) => passed && !busy));
    }

    private async Task CreateAsync()
    {
        if (!TermsAccepted || IsBusy) return;
        IsBusy = true;
        TestPassed = false;
        _cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try
        {
            var progress = new Progress<string>(message => Status = message);
            _candidate = await WarpProfileCreationService.CreateAsync(TermsAccepted, UseCurrentProxy, progress, _cancellation.Token);
            PrivateWarpProfileStore.Save(Utils.GetConfigPath("warp-draft.private.json"), _candidate);
            HasCandidate = true;
            await TestCandidateAsync(_cancellation.Token);
        }
        catch (OperationCanceledException) { Status = "Creation or test was cancelled or timed out. The active WARP profile was not changed."; }
        catch (Exception ex) { Status = FriendlyError(ex); }
        finally { IsBusy = false; _cancellation.Dispose(); _cancellation = null; }
    }

    private async Task TestAsync()
    {
        if (!HasCandidate || IsBusy) return;
        IsBusy = true;
        TestPassed = false;
        _cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await TestCandidateAsync(_cancellation.Token); }
        catch (OperationCanceledException) { Status = "WARP test timed out or was cancelled. Try again on a working connection."; }
        catch (Exception ex) { Status = FriendlyError(ex); }
        finally { IsBusy = false; _cancellation.Dispose(); _cancellation = null; }
    }

    private async Task TestCandidateAsync(CancellationToken cancellationToken)
    {
        Status = "Testing the new WARP connection directly over Ethernet/Wi-Fi…";
        await WarpProfileCreationService.TestAsync(_candidate!, cancellationToken);
        TestPassed = true;
        Status = "WARP test passed. Choose Use this config to activate this profile; the previous one will be backed up.";
    }

    private Task UseAsync()
    {
        if (!TestPassed || _candidate == null || IsBusy) return Task.CompletedTask;
        try
        {
            var config = AppManager.Instance.Config;
            PrivateWarpProfileStore.Save(WarpChainService.ProfilePath(config), _candidate);
            Status = config.WarpChainItem.Enabled
                ? "Saved privately. The previous profile was backed up. Reconnecting through the new WARP profile…"
                : "Saved privately. Tick WARP in the main window to use this profile.";
            if (config.WarpChainItem.Enabled) AppEvents.ReloadRequested.Publish();
            NoticeManager.Instance.SendMessageEx("New WARP profile saved. Previous profile backed up.");
        }
        catch { Status = "Could not save the WARP profile. Check the app's private data folder permissions."; }
        return Task.CompletedTask;
    }

    public void Cancel() => _cancellation?.Cancel();

    private static string FriendlyError(Exception exception) => exception is InvalidOperationException
        ? exception.Message
        : "WARP creation or testing failed. Check your connection or try registering through a working proxy. The active profile was not changed.";
}
