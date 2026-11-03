using System.Diagnostics;

namespace v2rayN.Desktop.Views;

public partial class WarpProfileWindow : ReactiveWindow<WarpProfileViewModel>
{
    public WarpProfileWindow()
    {
        InitializeComponent();
        ViewModel = new WarpProfileViewModel();
        DataContext = ViewModel;
        this.WhenActivated(disposables =>
        {
            this.Bind(ViewModel, vm => vm.TermsAccepted, view => view.chkAcceptTerms.IsChecked).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.UseCurrentProxy, view => view.chkUseProxy.IsChecked).DisposeWith(disposables);
            this.Bind(ViewModel, vm => vm.LicenseKey, view => view.txtWarpLicense.Text).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.CreateCmd, view => view.btnCreate).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.TestCmd, view => view.btnTest).DisposeWith(disposables);
            this.BindCommand(ViewModel, vm => vm.UseCmd, view => view.btnUse).DisposeWith(disposables);
        });
        btnClose.Click += (_, _) => Close();
        Closing += (_, _) => ViewModel.Cancel();
        btnTerms.Click += (_, _) => Process.Start(new ProcessStartInfo("https://www.cloudflare.com/application/terms/") { UseShellExecute = true });
    }
}
