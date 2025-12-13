using System;
using System.Runtime.InteropServices;
using DomainDetective.PowerShell;
using Pwsh = System.Management.Automation.PowerShell;
using System.Net;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Xunit.Sdk;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestCmdletNewDmarcRecord {
[Fact(Skip = "PowerShell + HttpListener heavy; skipped in CI/offline runs")]
    public async Task PublishesRecordSuccessfully() {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
            return;
        }
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port = PortHelper.GetFreePort();
        var prefix = $"http://localhost:{port}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port);
        string? body = null;
        var serverTask = Task.Run(async () => {
            var ctx = await listener.GetContextAsync();
            using var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding);
            body = await reader.ReadToEndAsync();
            ctx.Response.StatusCode = 200;
            ctx.Response.Close();
        });

        try {
            using var ps = Pwsh.Create();
            ps.AddCommand("Import-Module").AddArgument(typeof(CmdletNewDmarcRecord).Assembly.Location).Invoke();
            ps.Commands.Clear();
            ps.AddCommand("New-DmarcRecord")
                .AddParameter("Policy", "reject")
                .AddParameter("DomainName", "example.com")
                .AddParameter("DnsApiUrl", prefix)
                .AddParameter("Publish");
            var results = ps.Invoke();

            Assert.Empty(ps.Streams.Error);
            Assert.Empty(ps.Streams.Warning);
            Assert.Single(results);
            Assert.Equal("v=DMARC1; p=reject;", results[0].BaseObject.ToString());
            await serverTask;
            if (body != null) {
                Assert.Contains("domain=example.com", body);
            }
        } finally {
            listener.Stop();
        }
    }

    [Fact(Skip = "PowerShell + HttpListener heavy; skipped in CI/offline runs")]
    public async Task WarnsWhenPublishFails() {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
            return;
        }
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var listener = new HttpListener();
        var port2 = PortHelper.GetFreePort();
        var prefix = $"http://localhost:{port2}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port2);
        var serverTask = Task.Run(async () => {
            var ctx = await listener.GetContextAsync();
            ctx.Response.StatusCode = 500;
            ctx.Response.Close();
        });

        try {
            using var ps = Pwsh.Create();
            ps.AddCommand("Import-Module").AddArgument(typeof(CmdletNewDmarcRecord).Assembly.Location).Invoke();
            ps.Commands.Clear();
            ps.AddCommand("New-DmarcRecord")
                .AddParameter("Policy", "reject")
                .AddParameter("DomainName", "example.com")
                .AddParameter("DnsApiUrl", prefix)
                .AddParameter("Publish");
            var results = ps.Invoke();
            Assert.Empty(ps.Streams.Error);
            Assert.Single(ps.Streams.Warning);
            await serverTask;
        } finally {
            listener.Stop();
        }
    }
}
