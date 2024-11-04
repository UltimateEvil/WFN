
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Mapsui.Extensions;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

using Wokhan.UI.Extensions;
using Wokhan.WindowsFirewallNotifier.Common.Config;
using Wokhan.WindowsFirewallNotifier.Common.Helpers;
using Wokhan.WindowsFirewallNotifier.Common.Logging;
using Wokhan.WindowsFirewallNotifier.Common.Processes;
using Wokhan.WindowsFirewallNotifier.Common.Security;
using Wokhan.WindowsFirewallNotifier.Common.UI.ViewModels;

namespace Wokhan.WindowsFirewallNotifier.Console.UI.Pages;

[ObservableObject]
public sealed partial class EventsLog : Page, IDisposable
{

    private readonly CancellationTokenSource runningUpdates = new();
    public EventLogAsyncReader<LoggedConnection>? EventsReader { get; set; }

    [ObservableProperty]
    public ICollectionView? dataView;

    public int TCPOnlyOrAll
    {
        get => IsTCPOnlyEnabled ? 1 : 0;
        set => IsTCPOnlyEnabled = (value == 1);
    }

    public bool IsTCPOnlyEnabled
    {
        get => Settings.Default.FilterTcpOnlyEvents;
        set
        {
            if (IsTCPOnlyEnabled != value)
            {
                Settings.Default.FilterTcpOnlyEvents = value;
                Settings.Default.Save();
                ResetTcpFilter();
            }
        }
    }

    [ObservableProperty]
    private string _textFilter = String.Empty;
    partial void OnTextFilterChanged(string value) => ResetTextFilter();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LocateCommand))]
    private LoggedConnection? selectedItem;

    public EventsLog()
    {
        VirtualizedQueryableExtensions.Init(Dispatcher);

        if (UAC.CheckProcessElevated())
        {
            Loaded += (s, e) => StartHandlingSecurityLogEvents();
            Unloaded += (s, e) => StopHandlingSecurityLogEvents();
        }

        InitializeComponent();

        if (!Settings.Default.EnableDnsResolver)
        {
            RemoteHostCol.Visibility = Visibility.Hidden;
        }
    }

    private void StartHandlingSecurityLogEvents()
    {
        try
        {
            var old = EventsReader;
            EventsReader = new EventLogAsyncReader<LoggedConnection>(EventLogAsyncReader.EVENTLOG_SECURITY, LoggedConnection.CreateFromEventLogEntry)
            {
                FilterPredicate = EventLogAsyncReader.IsFirewallEvent
            };
            OnPropertyChanged(nameof(EventsReader));
            DataView = CollectionViewSource.GetDefaultView(EventsReader.Entries);
            runningUpdates.Cancel();
            old?.Dispose();
        }
        catch (Exception exc)
        {
            LogHelper.Error("Unable to connect to the event log", exc);
            throw;
        }
    }

    private void StopHandlingSecurityLogEvents()
    {
        var old = EventsReader;
        DataView = null;
        EventsReader = null;
        runningUpdates.Cancel();
        old?.Dispose();
    }

    public void Dispose()
    {
        runningUpdates.Cancel();
        DataView?.DisposeIfDisposable();
        EventsReader?.Dispose();
        runningUpdates.Dispose();
    }

    [RelayCommand(CanExecute = nameof(LocateCanExecute))]
    private void Locate()
    {
        ProcessHelper.StartShellExecutable("explorer.exe", "/select," + SelectedItem!.Path, true);
    }

    public bool LocateCanExecute => SelectedItem is not null;

    [RelayCommand]
    private void OpenEventsLogViewer()
    {
        ProcessHelper.StartShellExecutable("eventvwr.msc", showMessageBox: true);
    }

    [RelayCommand]
    private void Refresh()
    {
        StartHandlingSecurityLogEvents();
    }


    private bool TcpFilterPredicate(object entryAsObject) => ((LoggedConnection)entryAsObject).Protocol == "TCP";
    private bool FilterTextPredicate(object entryAsObject)
    {
        var le = (LoggedConnection)entryAsObject;

        // Note: do not use Remote Host, because this will trigger dns resolution over all entries
        return (le.TargetIP?.StartsWith(TextFilter, StringComparison.Ordinal) == true)
            || (le.FileName?.Contains(TextFilter, StringComparison.OrdinalIgnoreCase) == true)
            || (le.ServiceName?.Contains(TextFilter, StringComparison.OrdinalIgnoreCase) == true);
    }

    internal void ResetTcpFilter()
    {
        if (DataView is null)
        {
            return;
        }

        DataView.Filter -= TcpFilterPredicate;
        if (IsTCPOnlyEnabled)
        {
            DataView.Filter += TcpFilterPredicate;
        }
    }



    private int _isResetTextFilterPending;
    internal async void ResetTextFilter()
    {

        if (0 == Interlocked.CompareExchange(ref _isResetTextFilterPending, 1, 0))
        {
            try
            {
                await Task.Delay(500, runningUpdates.Token).ConfigureAwait(true);
            }
            catch (TaskCanceledException) {
                Interlocked.Exchange(ref _isResetTextFilterPending, 0);
                return;
            }
            if (!string.IsNullOrWhiteSpace(TextFilter))
            {
                DataView!.Filter -= FilterTextPredicate;
                DataView.Filter += FilterTextPredicate;
            }
            else
            {
                DataView!.Filter -= FilterTextPredicate;
            }
            Interlocked.Exchange(ref _isResetTextFilterPending,0);
        }
    }
}
