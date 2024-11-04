using AlphaChiTech.Virtualization;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Wokhan.WindowsFirewallNotifier.Common.Security;

public static class EventLogAsyncReader
{
    public static readonly string EVENTLOG_SECURITY = "security";

    public static bool IsFirewallEventSimple(EventLogEntry entry)
    {
        var instanceId = entry.InstanceId;

        // https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection
        return instanceId == 5156 // allowed
            || instanceId == 5157 // block connection
            || instanceId == 5152;// drop packet
    }

    public static bool IsFirewallEvent(EventLogEntry entry)
    {
        var instanceId = entry.InstanceId;

        // https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection
        //5031: The Windows Firewall Service blocked an application from accepting incoming connections on the network.
        //5150: The Windows Filtering Platform blocked a packet.
        //5151: A more restrictive Windows Filtering Platform filter has blocked a packet.
        //5154: The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections.
        //5155: The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections.
        //5156: The Windows Filtering Platform has permitted a connection.
        //5157: The Windows Filtering Platform has blocked a connection.
        //5158: The Windows Filtering Platform has permitted a bind to a local port.
        //5159: The Windows Filtering Platform has blocked a bind to a local port.
        return instanceId == 5157
               || instanceId == 5152
               // Cannot parse this event 
               // || instanceId == 5031
               || instanceId == 5150
               || instanceId == 5151
               || instanceId == 5154
               || instanceId == 5155
               || instanceId == 5156;
    }

    public static string GetEventInstanceIdAsString(long instanceId)
    {
        // https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection
        switch (instanceId)
        {
            case 5157:
                return "Block: connection";
            case 5152:
                return "Block: packet (WFP)";
            case 5031:
                return "Block: app connection"; //  Firewall blocked an application from accepting incoming connections on the network.
            case 5150:
                return "Block: packet";
            case 5151:
                return "Block: packet (other FW)";
            case 5154:
                return "Allow: listen";
            case 5155:
                return "Block: listen";
            case 5156:
                return "Allow: connection";
            default:
                return $"[UNKNOWN] eventId: {instanceId}";
        }
    }

    public static bool IsFirewallEventAllowed(long instanceId)
    {
        return instanceId == 5156;
    }
}

public sealed class EventLogAsyncReader<T> : IPagedSourceProviderAsync<T>, INotifyPropertyChanged, IDisposable where T : class, new()
{
    private readonly CancellationTokenSource runningUpdates = new();
    public Func<EventLogEntry, bool>? FilterPredicate { get; set; }

    public event EntryWrittenEventHandler EntryWritten
    {
        add { eventLog.EntryWritten += value; }
        remove { eventLog.EntryWritten -= value; }
    }

    private readonly EventLog eventLog;

    public EventLogAsyncReader(string eventLogName, Func<EventLogEntry, int, T?> projection, int pageSize = 20)
    {
        eventLog = new EventLog(eventLogName);
        _projection = projection;


        paginationManager = new PaginationManager<T>(this, pageSize: pageSize);

        Entries = new VirtualizingObservableCollection<T>(paginationManager);

        eventLog.EnableRaisingEvents = true;
    }


    private readonly Func<EventLogEntry, int, T?> _projection;
    public Func<int, T>? PlaceHolderCreator { get; set; }
    private readonly Dictionary<int, int> filteredPagesMap = [];

    public int Count => eventLog.Entries.Count;

    public int CurrentPageOffset { get; private set; }

    public void OnReset(int count)
    {
        firstEventTimeWritten = DateTime.Now;
        NewEntriesCount = 0;
        NewMatchingEntriesCount = 0;
        firstLoad = true;
        filteredPagesMap.Clear();
    }

    public int IndexOf(T item)
    {
        return 0;
    }

    public async Task<PagedSourceItemsPacket<T>> GetItemsAtAsync(int pageoffset, int count, bool usePlaceholder)
    {
        try
        {
            return await Task.Run(() => GetItemsAt(pageoffset, count, usePlaceholder), runningUpdates.Token).ConfigureAwait(false);
        }
        catch (ObjectDisposedException) {
            //FIXME: the task was queued just as the object is getting disposed of. 
            return await Task.FromResult<PagedSourceItemsPacket<T>>(
                new PagedSourceItemsPacket<T>
                {
                    Items = []
                }
                );
        }
    }

    private readonly T placeHolder = new T();
    private int matchesCount;
    private bool firstLoad = true;
    private DateTime firstEventTimeWritten;
    private readonly PaginationManager<T> paginationManager;

    public event PropertyChangedEventHandler? PropertyChanged;

    public int NewMatchingEntriesCount { get; private set; }
    public int NewEntriesCount { get; private set; }

    public VirtualizingObservableCollection<T> Entries { get; }
    
    //public bool AutoUpdate { get; set; }

    public T GetPlaceHolder(int index, int _ignored, int _alsoignored)
    {
        return PlaceHolderCreator?.Invoke(index) ?? placeHolder;
    }

    public async Task<int> GetCountAsync()
    {
        return await Task.FromResult(Count).ConfigureAwait(false);
    }

    public async Task<int> IndexOfAsync(T item)
    {
        return 0;
    }

    public PagedSourceItemsPacket<T> GetItemsAt(int pageoffset, int count, bool usePlaceholder)
    {
        if (firstLoad)
        {
            firstLoad = false;
            eventLog.EntryWritten -= DefaultEntryWrittenEventHandler;
            eventLog.EntryWritten += DefaultEntryWrittenEventHandler;
            firstEventTimeWritten = DateTime.Now;
        }

        pageoffset = filteredPagesMap.GetValueOrDefault(pageoffset, pageoffset);

        var ret = new PagedSourceItemsPacket<T>
        {
            LoadedAt = DateTime.Now
        };
        if (usePlaceholder)
        {
            ret.Items = Enumerable.Range(0, count).Select((_, i) => GetPlaceHolder(pageoffset + i, 0, 0));
        }
        else
        {
            ret.Items = GetAsEnumerable(pageoffset, count);
        }

        return ret;
    }

    private IEnumerable<T> GetAsEnumerable(int pageoffset, int count)
    {
        var cpt = 0;
        if (pageoffset == 0)
        {
            firstEventTimeWritten = eventLog.Entries[0].TimeWritten;
        }

        var totalCount = eventLog.Entries.Count;
        for (var i = pageoffset + 1; i < totalCount && cpt < count; i++)
        {
            T? ret = null;
            try
            {
                EventLogEntry entry = eventLog.Entries[^(i + NewEntriesCount)];//TODO
                if (FilterPredicate?.Invoke(entry) ?? true)
                {
                    matchesCount++;
                    cpt++;
                    if (cpt == count - 1)
                    {
                        filteredPagesMap.Add(pageoffset + count, i);
                    }

                    ret = _projection(entry, matchesCount);
                }
                else
                {
                    continue;
                }
            }
            catch (IndexOutOfRangeException)
            {
                // Ignore
                continue;
            }

            if (ret is not null)
            {
                yield return ret;
            }
        }
    }

    private void DefaultEntryWrittenEventHandler(object sender, EntryWrittenEventArgs e)
    {
        if (e.Entry.TimeWritten <= firstEventTimeWritten)
        {
            return;
        }

        NewEntriesCount++;

        if (FilterPredicate?.Invoke(e.Entry) ?? true)
        {
            NewMatchingEntriesCount++;

            // TODO: fix and enable back. As of now AutoUpdate cannot be used.
            //if (AutoUpdate)
            //{
            //    NewEntriesCount = 0;
            //    paginationManager.AddOrUpdateAdjustment(0, -1);
            //    NewMatchingEntriesCount = 0;
            //}
        }

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(NewEntriesCount)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(NewMatchingEntriesCount)));
    }

    public void Dispose()
    {
        runningUpdates.Cancel();
        eventLog.EnableRaisingEvents = false;
        eventLog.Dispose();
        runningUpdates.Dispose();
    }


    public void StopRaisingEvents()
    {
        eventLog.EnableRaisingEvents = false;
    }

    public void StartRaisingEvents()
    {
        eventLog.EnableRaisingEvents = true;
    }
}
