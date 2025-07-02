using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Monitoring;

namespace DomainDetective.Tests;

public class TestDnsPropagationMonitor {
    private class CaptureNotifier : INotificationSender {
        public readonly List<string> Messages = new();
        public Task SendAsync(string message, CancellationToken ct = default) {
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task SendsNotificationOnDiscrepancy() {
        var notifier = new CaptureNotifier();
        var monitor = new DnsPropagationMonitor {
            Domain = "example.com",
            RecordType = DnsClientX.DnsRecordType.A,
            Notifier = notifier,
            QueryOverride = (_, _) => Task.FromResult(new List<DnsPropagationResult> {
                new() { Server = new PublicDnsEntry { IPAddress = IPAddress.Parse("1.1.1.1"), Enabled = true }, RecordType = DnsClientX.DnsRecordType.A, Records = new[] {"1.2.3.4"}, Success = true },
                new() { Server = new PublicDnsEntry { IPAddress = IPAddress.Parse("8.8.8.8"), Enabled = true }, RecordType = DnsClientX.DnsRecordType.A, Records = new[] {"5.6.7.8"}, Success = true }
            })
        };

        await monitor.RunAsync();
        Assert.Contains(notifier.Messages, m => m.Contains("discrepancy"));
    }

    [Fact]
    public async Task HonorsCountryFilterAndCustomServers() {
        var passed = new List<PublicDnsEntry>();
        var json = "[ { \"Country\": \"US\", \"IPAddress\": \"1.1.1.1\", \"Enabled\": true }, { \"Country\": \"DE\", \"IPAddress\": \"2.2.2.2\", \"Enabled\": true } ]";
        var file = System.IO.Path.GetTempFileName();
        try {
            System.IO.File.WriteAllText(file, json);
            var monitor = new DnsPropagationMonitor {
                Domain = "example.com",
                RecordType = DnsClientX.DnsRecordType.A,
                Country = "US",
                QueryOverride = (servers, _) => { passed.AddRange(servers); return Task.FromResult(new List<DnsPropagationResult>()); }
            };
            monitor.LoadServers(file);
            using (File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
            monitor.AddServer(new PublicDnsEntry { IPAddress = IPAddress.Parse("3.3.3.3"), Enabled = true });
            await monitor.RunAsync();
            Assert.Equal(2, passed.Count);
            Assert.Contains(passed, p => p.IPAddress.Equals(IPAddress.Parse("1.1.1.1")));
            Assert.Contains(passed, p => p.IPAddress.Equals(IPAddress.Parse("3.3.3.3")));
        } finally {
            System.IO.File.Delete(file);
        }
    }
}
