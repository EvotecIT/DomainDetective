using DnsClientX;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestMailDomainClassifier {
    private static Func<string, DnsRecordType, Task<DnsAnswer[]>> MakeOverride(Dictionary<(string name, DnsRecordType type), DnsAnswer[]> map) =>
        (name, type) => Task.FromResult(map.TryGetValue((name, type), out var v) ? v : Array.Empty<DnsAnswer>());

    [Fact]
    public async Task Classify_Parked_NullMX_NoSending() {
        var hc = new DomainDetective.DomainHealthCheck();
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
            [("parked.test", DnsRecordType.MX)] = new[]{ new DnsAnswer{ DataRaw = "0 .", Type = DnsRecordType.MX } },
            [("parked.test", DnsRecordType.TXT)] = new[]{ new DnsAnswer{ DataRaw = "v=spf1 -all", Type = DnsRecordType.TXT } }
        };
        hc.DnsConfiguration.QueryDnsOverride = MakeOverride(map);
        var classifier = new DomainDetective.MailDomainClassifier(hc, new InternalLogger(false));
        var result = await classifier.ClassifyAsync("parked.test");
        Assert.Equal(DomainDetective.Definitions.MailDomainClassificationCategory.Parked, result.Classification);
        Assert.True(result.Signals.HasNullMX);
        Assert.False(result.Signals.EffectiveSpfSends);
    }

    [Fact]
    public async Task Classify_SendingOnly_NullMX_WithSpfAuth() {
        var hc = new DomainDetective.DomainHealthCheck();
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
            [("senderonly.test", DnsRecordType.MX)] = new[]{ new DnsAnswer{ DataRaw = "0 .", Type = DnsRecordType.MX } },
            [("senderonly.test", DnsRecordType.TXT)] = new[]{ new DnsAnswer{ DataRaw = "v=spf1 ip4:192.0.2.0/24 -all", Type = DnsRecordType.TXT } }
        };
        hc.DnsConfiguration.QueryDnsOverride = MakeOverride(map);
        var classifier = new DomainDetective.MailDomainClassifier(hc, new InternalLogger(false));
        var result = await classifier.ClassifyAsync("senderonly.test");
        Assert.Equal(DomainDetective.Definitions.MailDomainClassificationCategory.SendingOnly, result.Classification);
        Assert.True(result.Signals.EffectiveSpfSends);
    }

    [Fact]
    public async Task Classify_ReceivingOnly_MX_Present_NoSending() {
        var hc = new DomainDetective.DomainHealthCheck();
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
            [("rxonly.test", DnsRecordType.MX)] = new[]{ new DnsAnswer{ DataRaw = "10 mx.rxonly.test", Type = DnsRecordType.MX } },
            [("mx.rxonly.test", DnsRecordType.A)] = new[]{ new DnsAnswer{ DataRaw = "198.51.100.10", Type = DnsRecordType.A } },
            [("rxonly.test", DnsRecordType.TXT)] = new[]{ new DnsAnswer{ DataRaw = "v=spf1 -all", Type = DnsRecordType.TXT } }
        };
        hc.DnsConfiguration.QueryDnsOverride = MakeOverride(map);
        var classifier = new DomainDetective.MailDomainClassifier(hc, new InternalLogger(false));
        var result = await classifier.ClassifyAsync("rxonly.test");
        Assert.Equal(DomainDetective.Definitions.MailDomainClassificationCategory.ReceivingOnly, result.Classification);
        Assert.True(result.Signals.HasMX);
        Assert.False(result.Signals.EffectiveSpfSends);
    }

    [Fact]
    public async Task Classify_SendingAndReceiving_MX_And_Spf() {
        var hc = new DomainDetective.DomainHealthCheck();
        var map = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
            [("both.test", DnsRecordType.MX)] = new[]{ new DnsAnswer{ DataRaw = "10 mx.both.test", Type = DnsRecordType.MX } },
            [("mx.both.test", DnsRecordType.A)] = new[]{ new DnsAnswer{ DataRaw = "198.51.100.7", Type = DnsRecordType.A } },
            [("both.test", DnsRecordType.TXT)] = new[]{ new DnsAnswer{ DataRaw = "v=spf1 ip4:198.51.100.0/24 -all", Type = DnsRecordType.TXT } },
            [("both.test", DnsRecordType.A)] = new[]{ new DnsAnswer{ DataRaw = "198.51.100.7", Type = DnsRecordType.A } },
            [("both.test", DnsRecordType.AAAA)] = Array.Empty<DnsAnswer>()
        };
        hc.DnsConfiguration.QueryDnsOverride = MakeOverride(map);
        var classifier = new DomainDetective.MailDomainClassifier(hc, new InternalLogger(false));
        var result = await classifier.ClassifyAsync("both.test");
        Assert.Equal(DomainDetective.Definitions.MailDomainClassificationCategory.SendingAndReceiving, result.Classification);
        Assert.True(result.Signals.HasMX);
        Assert.True(result.Signals.EffectiveSpfSends);
    }
}
