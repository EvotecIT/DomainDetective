using DomainDetective.PowerShell;
using Pwsh = System.Management.Automation.PowerShell;
using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestCmdletNewDmarcRecord {
    [Fact]
    public async Task PublishesRecordViaDnsApi() {
        using var listener = new HttpListener();
        int port = PortHelper.GetFreePort();
        string prefix = $"http://localhost:{port}/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        var requestTask = Task.Run(async () => {
            var ctx = await listener.GetContextAsync();
            using var reader = new StreamReader(ctx.Request.InputStream);
            string body = await reader.ReadToEndAsync();
            ctx.Response.StatusCode = 200;
            ctx.Response.Close();
            return body;
        });

        using var ps = Pwsh.Create();
        ps.AddCommand("Import-Module").AddArgument(typeof(CmdletNewDmarcRecord).Assembly.Location).Invoke();
        ps.Commands.Clear();
        ps.AddCommand("New-DmarcRecord")
            .AddParameter("Policy", "reject")
            .AddParameter("DomainName", "example.com")
            .AddParameter("DnsApiUrl", new Uri(prefix))
            .AddParameter("Publish");
        var results = ps.Invoke();
        string body = await requestTask;
        listener.Stop();

        Assert.Empty(ps.Streams.Error);
        Assert.Single(results);
        Assert.Contains("domain=example.com", body);
        Assert.Contains("record=v%3DDMARC1%3B+p%3Dreject%3B", body);
    }
}