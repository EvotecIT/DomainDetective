using DnsClientX;
using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDnsAmplificationAnalysis
{
    [Fact]
    public async Task FlagsHighRiskWhenOpenRecursionAndLargeUdpResponses()
    {
        var analysis = CreateAnalysis(openRecursion: true);
        await analysis.Analyze("example.com", new InternalLogger(), CancellationToken.None);
        Assert.Contains(analysis.Assessments, a => a.Code == DnsAmplificationCodes.HighRisk && a.Severity == AssessmentSeverity.Error);
    }

    [Fact]
    public async Task FlagsLargeUdpResponseWhenRecursionClosed()
    {
        var analysis = CreateAnalysis(openRecursion: false);
        await analysis.Analyze("example.com", new InternalLogger(), CancellationToken.None);
        Assert.Contains(analysis.Assessments, a => a.Code == DnsAmplificationCodes.EdnsUdpPayloadTooLarge && a.Severity == AssessmentSeverity.Warning);
        Assert.Contains(analysis.Assessments, a => a.Code == DnsAmplificationCodes.LargeUdpResponse && a.Severity == AssessmentSeverity.Warning);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == DnsAmplificationCodes.HighRisk && a.Severity == AssessmentSeverity.Error);
    }

    private static DnsAmplificationAnalysis CreateAnalysis(bool openRecursion)
    {
        return new DnsAmplificationAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS && string.Equals(name, "example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS } });
                }

                if (type == DnsRecordType.A && string.Equals(name, "ns1.example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "192.0.2.1", Type = DnsRecordType.A } });
                }

                return Task.FromResult(Array.Empty<DnsAnswer>());
            },
            QueryUdpOverride = (server, query, ct) =>
            {
                _ = server;
                ct.ThrowIfCancellationRequested();

                var hasEdns = query.Length > 11 && query[11] == 0x01;
                var qtype = ReadQtype(query);

                // Open recursion probe: A query without EDNS.
                if (qtype == (ushort)DnsRecordType.A && !hasEdns)
                {
                    return Task.FromResult<byte[]?>(openRecursion ? BuildHeaderResponse(flagsHi: 0x81, flagsLo: 0x80, length: 12) : BuildHeaderResponse(flagsHi: 0x80, flagsLo: 0x05, length: 12));
                }

                // EDNS baseline (NS query with OPT record).
                if (qtype == (ushort)DnsRecordType.NS && hasEdns)
                {
                    return Task.FromResult<byte[]?>(BuildEdnsOnlyResponse(serverUdpPayloadSize: 4096));
                }

                // Large-answer probe (DNSKEY): large UDP response, not truncated.
                if (qtype == (ushort)DnsRecordType.DNSKEY)
                {
                    return Task.FromResult<byte[]?>(BuildHeaderResponse(flagsHi: 0x80, flagsLo: 0x00, length: 1300));
                }

                // TXT probe: small response.
                if (qtype == (ushort)DnsRecordType.TXT)
                {
                    return Task.FromResult<byte[]?>(BuildHeaderResponse(flagsHi: 0x80, flagsLo: 0x00, length: 120));
                }

                return Task.FromResult<byte[]?>(BuildHeaderResponse(flagsHi: 0x80, flagsLo: 0x00, length: 40));
            }
        };
    }

    private static ushort ReadQtype(byte[] query)
    {
        int offset = 12;
        while (offset < query.Length)
        {
            var len = query[offset++];
            if (len == 0)
            {
                break;
            }
            offset += len;
        }

        if (offset + 1 >= query.Length)
        {
            return 0;
        }

        return (ushort)((query[offset] << 8) | query[offset + 1]);
    }

    private static byte[] BuildHeaderResponse(byte flagsHi, byte flagsLo, int length)
    {
        var resp = new byte[length];
        if (resp.Length < 12)
        {
            return resp;
        }

        resp[2] = flagsHi;
        resp[3] = flagsLo;
        return resp;
    }

    private static byte[] BuildEdnsOnlyResponse(int serverUdpPayloadSize)
    {
        var resp = new byte[23];
        resp[2] = 0x80; // QR=1
        resp[3] = 0x00;
        resp[10] = 0x00;
        resp[11] = 0x01; // ARCOUNT=1

        // OPT RR (root, type=41, class=udp size)
        resp[12] = 0x00;
        resp[13] = 0x00;
        resp[14] = 0x29;
        resp[15] = (byte)(serverUdpPayloadSize >> 8);
        resp[16] = (byte)(serverUdpPayloadSize & 0xFF);
        resp[17] = 0x00;
        resp[18] = 0x00;
        resp[19] = 0x00;
        resp[20] = 0x00;
        resp[21] = 0x00;
        resp[22] = 0x00;
        return resp;
    }
}

