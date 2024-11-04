﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Xml;

using Wokhan.WindowsFirewallNotifier.Common.Logging;

/// <summary>
/// NetshHelper executes netsh commands and parses the resulting xml content.
/// Author: harrwiss / Nov 2019
/// </summary>
namespace Wokhan.WindowsFirewallNotifier.Common.Net.WFP;

/// <summary>
/// Helper for executing netsh commands and parsing the results.
/// </summary>
public static class NetshHelper
{
    private static bool HasLoaded = false;
    private static XmlDocument? FiltersXmlDoc;
    private static XmlDocument? WFPStateXmlDoc;

    private static FilterResult FILTER_RESULT_ERROR = new FilterResult
    {
        FilterId = 0,
        Name = "No filter found",
        Description = "",
        HasErrors = true
    };

    private static readonly object InitLocker = new();

    private static void Init(bool refreshData = false)
    {
        if (!HasLoaded || refreshData) //quick, lock-free exit.
        {
            lock (InitLocker)
            {
                if (!HasLoaded || refreshData)
                {
                    // Use parallel tasks to speed things up a bit
                    var tFilters = Task.Run(() => FiltersXmlDoc = LoadWfpFilters()); // firewall filters
                    var tStates = Task.Run(() => WFPStateXmlDoc = LoadWfpState()); // all filters added by other provider e.g. firewall apps

                    Task.WaitAll(tFilters, tStates);
                }
                HasLoaded = true;
            }
        }
    }

    public static FilterResult FindMatchingFilterInfo(int filterId, bool refreshData = false)
    {
        Init(refreshData);
        if (FiltersXmlDoc is not null)
        {
            FilterResult? fr = FindFilterId(filterId);
            if (fr is null && WFPStateXmlDoc is not null)
            {
                fr = FindWfpStateFilterId(filterId);
            }
            return fr ?? FILTER_RESULT_ERROR;
        }
        return FILTER_RESULT_ERROR;
    }

    //TODO: set visibility for NetshHelperTest only and set as private
    public static FilterResult FindMatchingFilterByKey(string filterKey, bool refreshData = false)
    {
        Init(refreshData);
        if (FiltersXmlDoc is not null)
        {
            FilterResult? fr = FindFilterKey(filterKey);
            if (fr is null && WFPStateXmlDoc is not null)
            {
                fr = FindWfpStateFilterKey(filterKey);
            }
            return fr ?? FILTER_RESULT_ERROR;
        }
        return FILTER_RESULT_ERROR;
    }

    private static XmlDocument? LoadWfpFilters()
    {
        XmlDocument? xmlDoc = null;
        var sys32Folder = Environment.GetFolderPath(Environment.SpecialFolder.System);
        RunResult rr = RunCommandCapturing(sys32Folder + @"\netsh.exe", [@"wfp", @"show", @"filters", @"file=-"]);
        if (rr.exitCode == 0)
        {
            xmlDoc = SafeLoadXml(rr.outputData.ToString());
        }
        else
        {
            LogHelper.Info($"netsh error: exitCode={rr.exitCode}\noutput: {(rr.outputData.Length > 0 ? rr.outputData.ToString().Substring(0, Math.Min(rr.outputData.Length - 1, 300)) : String.Empty)}...\nerror: { rr.errorData?.ToString() }");
        }
        return xmlDoc;
    }

    private static XmlDocument? LoadWfpState()
    {
        XmlDocument? xmlDoc = null;
        var sys32Folder = Environment.GetFolderPath(Environment.SpecialFolder.System);
        RunResult rr = RunCommandCapturing(sys32Folder + @"\netsh.exe", [@"wfp", @"show", @"state", @"file=-"]);
        if (rr.exitCode == 0)
        {
            xmlDoc = SafeLoadXml(rr.outputData.ToString());
        }
        else
        {
            LogHelper.Info($"netsh error: exitCode={rr.exitCode}\noutput: {(rr.outputData.Length > 0 ? rr.outputData.ToString().Substring(0, Math.Min(rr.outputData.Length - 1, 300)) : String.Empty)}...\nerror: { rr.errorData?.ToString() }");
        }
        return xmlDoc;
    }

    private static FilterResult? FindFilterId(int filterId)
    {
        if (FiltersXmlDoc is null)
            return null;

        XmlNode root = FiltersXmlDoc.DocumentElement;
        var nsmgr = new XmlNamespaceManager(FiltersXmlDoc.NameTable);
        try
        {
            XmlNode filtersNode = root.FirstChild;
            XmlNode filter = filtersNode.SelectSingleNode("item[filterId=" + filterId + "]", nsmgr);
            FilterResult? fr = null;
            if (filter is not null)
            {
                fr = new FilterResult();
                XmlNode displayData = filter["displayData"];
                fr.FilterId = filterId;
                fr.Name = displayData["name"].InnerText;
                fr.Description = displayData["description"].InnerText;
                fr.FoundIn = FiltersContextEnum.FILTERS;
            }
            return fr;
        }
        catch (Exception e)
        {
            LogHelper.Error(e.Message, e);
        }
        return null;
    }

    private static FilterResult? FindFilterKey(string filterKey)
    {
        if (FiltersXmlDoc is null)
            return null;

        XmlNode root = FiltersXmlDoc.DocumentElement;
        var nsmgr = new XmlNamespaceManager(FiltersXmlDoc.NameTable);

        try
        {
            XmlNode filtersNode = root.FirstChild;
            XmlNode filter = filtersNode.SelectSingleNode("item[filterKey='" + filterKey + "']", nsmgr);
            FilterResult? fr = null;
            if (filter is not null)
            {
                XmlNode displayData = filter["displayData"];
                fr = new FilterResult
                {
                    FilterId = int.Parse(filter["filterId"].InnerText),
                    Name = displayData["name"].InnerText,
                    Description = displayData["description"].InnerText,
                    FoundIn = FiltersContextEnum.FILTERS
                };
            }
            return fr;
        }
        catch (Exception e)
        {
            LogHelper.Error(e.Message, e);
        }
        return null;
    }

    private static FilterResult? FindWfpStateFilterKey(string filterKey)
    {
        if (WFPStateXmlDoc is null)
            return null;

        XmlNode root = WFPStateXmlDoc.DocumentElement;
        var nsmgr = new XmlNamespaceManager(WFPStateXmlDoc.NameTable);
        try
        {
            // / wfpstate / layers / item[14] / filters / item[1] / filterKey
            XmlNode filtersNode = root.SelectSingleNode("layers");
            XmlNode filter = filtersNode.SelectSingleNode("//filters/item[filterKey='" + filterKey + "']", nsmgr);
            FilterResult? fr = null;
            if (filter is not null)
            {
                XmlNode displayData = filter["displayData"];
                fr = new FilterResult
                {
                    FilterId = int.Parse(filter["filterId"].InnerText),
                    Name = displayData["name"].InnerText,
                    Description = displayData["description"].InnerText,
                    FoundIn = FiltersContextEnum.WFPSTATE
                };
            }
            return fr;

        }
        catch (Exception e)
        {
            LogHelper.Error(e.Message, e);
        }
        return null;
    }

    private static FilterResult? FindWfpStateFilterId(int filterId)
    {
        if (WFPStateXmlDoc is null)
            return null;

        XmlNode root = WFPStateXmlDoc.DocumentElement;
        var nsmgr = new XmlNamespaceManager(WFPStateXmlDoc.NameTable);
        try
        {
            XmlNode filtersNode = root.SelectSingleNode("layers");
            XmlNode filter = filtersNode.SelectSingleNode("//filters/item[filterId=" + filterId + "]", nsmgr);
            FilterResult? fr = null;
            if (filter is not null)
            {
                XmlNode displayData = filter["displayData"];
                fr = new FilterResult
                {
                    Name = displayData["name"].InnerText,
                    Description = displayData["description"].InnerText,
                    FoundIn = FiltersContextEnum.WFPSTATE
                };
            }
            return fr;
        }
        catch (Exception e)
        {
            LogHelper.Error(e.Message, e);
        }
        return null;
    }

    private class RunResult
    {
        internal int dataLineCnt;
        internal StringBuilder errorData = new StringBuilder();
        internal StringBuilder outputData = new StringBuilder();
        internal int exitCode = -1;
    }

    private static RunResult RunCommandCapturing(string command, IEnumerable<string> args, string? workingDir = null)
    {
        var rr = new RunResult();
        try
        {
            using var p = new Process();
            // set start info
            p.StartInfo = new ProcessStartInfo(command, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                UseShellExecute = false,
                WorkingDirectory = string.IsNullOrWhiteSpace(workingDir) ? Path.GetTempPath() : workingDir,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                Verb = @"RunAs"
            };
            bool ReadSinceLast = true;

            // note: outputData.appendLine should not be used because it can cause a break in the middle of an output line when the buffer is reached
            //TODO: reading line by line is extreamely slow. Replace by a custom buffer-based read.
            p.OutputDataReceived += (sender, arg) => {
                ReadSinceLast = true;
                rr.outputData.Append(arg.Data); rr.dataLineCnt++; 
            };
            p.ErrorDataReceived += (sender, arg) => {
                ReadSinceLast = true;
                rr.errorData.AppendLine(arg.Data);
            };
            p.EnableRaisingEvents = false;
            //p.Exited += onProcessExit;
            p.Start();
            p.StandardInput.Close();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            while (ReadSinceLast) {
                ReadSinceLast = false;
                if (p.WaitForExit(10000))
                {
                    rr.exitCode = p.ExitCode;
                    break;
                }
            }
            if (!p.HasExited) {
                p.Kill();
                var msg = $"Process didn't respond after 10s, killing it now. Command: {p.StartInfo.FileName} / Args: {String.Join(' ', p.StartInfo.ArgumentList)}";
                LogHelper.Error(msg, null);
                rr.errorData.AppendLine(msg);
            }
        }
        catch (Exception ex)
        {
            LogHelper.Error(ex.Message, ex);
            rr.errorData.AppendLine(ex.Message);
        }
        return rr;
    }

    private static XmlDocument? SafeLoadXml(string xml)
    {
        XmlDocument? xmlDoc = null;
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings() { XmlResolver = null });

            // CA3075 - Unclear message: Unsafe overload of 'LoadXml' 
            // see: https://github.com/dotnet/roslyn-analyzers/issues/2477
            xmlDoc = new XmlDocument() { XmlResolver = null };
            xmlDoc.Load(reader);
        }
        catch (Exception xe)
        {
            xmlDoc = null;
            LogHelper.Error(xe.Message, xe);
        }

        return xmlDoc;
    }

}
