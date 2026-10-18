using System;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;

namespace DomainDetective.Tests;

public class TestApexAddressCertainty {
    [Fact]
    public async Task NullMxRemainsConclusiveWhenApexAddressExists() {
        using var health = new DomainHealthCheck();
        health.ApexAddressAnalysis.QueryRpkiOverride = _ => Task.FromResult(("192.0.2.0/24", 64496, false));
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(new DnsResponse {
            Status = DnsResponseCode.NoError,
            Answers = name != "sender.example" ? Array.Empty<DnsAnswer>() : type switch {
                DnsRecordType.MX => new[] { new DnsAnswer { Type = type, DataRaw = "0 ." } },
                DnsRecordType.A => new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } },
                DnsRecordType.TXT => new[] { new DnsAnswer { Type = type, DataRaw = "v=spf1 ip4:192.0.2.0/24 -all" } },
                _ => Array.Empty<DnsAnswer>()
            }
        });
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await health.Verify("sender.example", new[] { HealthCheckType.MAILCLASSIFICATION }, cancellationToken: guard.Token);
        Assert.True(health.MailDomainClassification!.Signals.HasNullMX);
        Assert.True(health.MailDomainClassification.Signals.HasAorAAAA);
        Assert.Equal(MailDomainClassificationCategory.SendingOnly, health.MailDomainClassification.Classification);
    }

    [Theory]
    [InlineData(DnsRecordType.A)]
    [InlineData(DnsRecordType.AAAA)]
    public async Task SuccessfulAddressFamilySurvivesSiblingFailureAndNextRunResetsCertainty(DnsRecordType successful) {
        bool emptyRun = false;
        using var health = new DomainHealthCheck();
        var analysis = health.ApexAddressAnalysis;
        analysis.QueryRpkiOverride = _ => Task.FromResult(("192.0.2.0/24", 64496, false));
        analysis.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => Task.FromResult(new DnsResponse {
            Status = !emptyRun && (type == DnsRecordType.A || type == DnsRecordType.AAAA) && type != successful
                ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError,
            Answers = !emptyRun && type == successful
                ? new[] { new DnsAnswer { Type = type, DataRaw = successful == DnsRecordType.A ? "192.0.2.1" : "2001:db8::1" } }
                : Array.Empty<DnsAnswer>()
        });
        await analysis.AnalyzeAsync("fixture.example");
        Assert.True(analysis.HasAnyAddress);
        Assert.True(analysis.AddressPresence);
        Assert.False(analysis.AddressLookupComplete);
        Assert.Single(analysis.AddressLookupFailures);
        Assert.Contains("incomplete", Views.Converters.Convert(analysis).Summary);
        var drift = DesiredStateEvaluator.Evaluate("fixture.example", health, new DesiredStateProfile {
            ApexAddress = new DesiredStateApexAddressPolicy { MinDistinctSubnetCountV4 = 2, MinDistinctSubnetCountV6 = 2 }
        });
        Assert.Contains(drift.Assessments, item => item.Code == "DesiredState.ApexAddress.Incomplete");
        Assert.Contains(drift.Assessments, item => item.Code == (successful == DnsRecordType.A
            ? DesiredStateCodes.ApexAddressSubnetDiversityTooLowV4 : DesiredStateCodes.ApexAddressSubnetDiversityTooLowV6));
        Assert.DoesNotContain(drift.Assessments, item => item.Code == (successful == DnsRecordType.A
            ? DesiredStateCodes.ApexAddressSubnetDiversityTooLowV6 : DesiredStateCodes.ApexAddressSubnetDiversityTooLowV4));
        emptyRun = true;
        await analysis.AnalyzeAsync("fixture.example");
        Assert.False(analysis.AddressPresence);
        Assert.True(analysis.AddressLookupComplete);
        Assert.Empty(analysis.AddressLookupFailures);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedApexResolutionDoesNotEstablishSendingOnly(bool explicitNullMx) {
        using var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => Task.FromResult(new DnsResponse {
            Status = name == "sender.example" && (type == DnsRecordType.A || type == DnsRecordType.AAAA)
                ? DnsResponseCode.ServerFailure : DnsResponseCode.NoError,
            Answers = name == "sender.example" && type == DnsRecordType.TXT
                ? new[] { new DnsAnswer { Type = type, DataRaw = "v=spf1 ip4:192.0.2.0/24 -all" } }
                : explicitNullMx && name == "sender.example" && type == DnsRecordType.MX
                    ? new[] { new DnsAnswer { Type = type, DataRaw = "0 ." } } : Array.Empty<DnsAnswer>()
        });
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await health.Verify("sender.example", new[] { HealthCheckType.MAILCLASSIFICATION }, cancellationToken: guard.Token);
        Assert.True(health.MailDomainClassification!.Signals.EffectiveSpfSends);
        Assert.Equal(explicitNullMx ? MailDomainClassificationCategory.SendingOnly : MailDomainClassificationCategory.Unknown,
            health.MailDomainClassification.Classification);
    }
}
