using DomainDetective.PowerShell;
using DomainDetective.Monitoring;
using DnsClientX;
using Pwsh = System.Management.Automation.PowerShell;
using System.IO;

namespace DomainDetective.Tests;

public class TestCmdletStartDnsPropagationMonitor {
    [Fact]
    public void RunsWithBuiltinServersWhenNoFile() {
        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletStartDnsPropagationMonitor).Assembly.Location).Invoke();
        ps.Commands.Clear();
        ps.AddCommand("Start-DnsPropagationMonitor")
            .AddParameter("DomainName", "example.com")
            .AddParameter("RecordType", DnsRecordType.A)
            .AddParameter("IntervalSeconds", 1);
        var results = ps.Invoke();
        Assert.Empty(ps.Streams.Error);
        Assert.Single(results);
        var monitor = Assert.IsType<DnsPropagationMonitor>(results[0].BaseObject);
        monitor.Stop();
        var analysisField = typeof(DnsPropagationMonitor).GetField("_analysis", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var analysis = (DnsPropagationAnalysis?)analysisField?.GetValue(monitor);
        Assert.NotNull(analysis);
        Assert.NotEmpty(analysis!.Servers);
    }

    [Fact]
    public void RunsWithServersFileParameterSet() {
        var file = Path.GetTempFileName();
        File.WriteAllText(file, "[{\"IPAddress\":\"192.0.2.1\",\"Enabled\":true}]");
        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletStartDnsPropagationMonitor).Assembly.Location).Invoke();
        ps.Commands.Clear();
        ps.AddCommand("Start-DnsPropagationMonitor")
            .AddParameter("DomainName", "example.com")
            .AddParameter("RecordType", DnsRecordType.A)
            .AddParameter("ServersFile", file)
            .AddParameter("IntervalSeconds", 1);
        var results = ps.Invoke();
        File.Delete(file);
        Assert.Empty(ps.Streams.Error);
        Assert.Single(results);
        var monitor = Assert.IsType<DnsPropagationMonitor>(results[0].BaseObject);
        monitor.Stop();
        var analysisField = typeof(DnsPropagationMonitor).GetField("_analysis", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var analysis = (DnsPropagationAnalysis?)analysisField?.GetValue(monitor);
        Assert.NotNull(analysis);
        Assert.Single(analysis!.Servers);
        Assert.Equal("192.0.2.1", analysis.Servers[0].IPAddress.ToString());
    }
}
