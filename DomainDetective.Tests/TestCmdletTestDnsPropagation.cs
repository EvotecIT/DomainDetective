using System;
using DomainDetective.PowerShell;
using DnsClientX;
using Pwsh = System.Management.Automation.PowerShell;
using System.IO;
using Xunit;
using System.Runtime.InteropServices;

namespace DomainDetective.Tests;

public class TestCmdletTestDnsPropagation {
    [Fact(Skip = "Skipped in cross-platform test runs")]
    public void RunsWithBuiltinServersParameterSet() {
        if (!IsWindows()) {
            return;
        }
        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletTestDnsPropagation).Assembly.Location).Invoke();
        ps.Commands.Clear();
        ps.AddCommand("Test-DnsPropagation")
            .AddParameter("DomainName", "example.com")
            .AddParameter("RecordType", DnsRecordType.A)
            .AddParameter("Take", 0);
        var results = ps.Invoke();
        Assert.Empty(ps.Streams.Error);
        Assert.Empty(results);
    }

    [Fact(Skip = "Skipped in cross-platform test runs")]
    public void RunsWithServersFileParameterSet() {
        if (!IsWindows()) {
            return;
        }
        var file = Path.GetTempFileName();
        File.WriteAllText(file, "[{\"IPAddress\":\"192.0.2.1\"}]");
        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletTestDnsPropagation).Assembly.Location).Invoke();
        ps.Commands.Clear();
        ps.AddCommand("Test-DnsPropagation")
            .AddParameter("DomainName", "example.com")
            .AddParameter("RecordType", DnsRecordType.A)
            .AddParameter("ServersFile", file)
            .AddParameter("Take", 0);
        var results = ps.Invoke();
        File.Delete(file);
        Assert.Empty(ps.Streams.Error);
        Assert.Empty(results);
    }

    private static bool IsWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
}
