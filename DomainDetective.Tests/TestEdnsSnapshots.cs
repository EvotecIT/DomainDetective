using System;
using System.Collections.Generic;
using DomainDetective;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestEdnsSnapshots
{
    [Fact]
    public void PartitionPositivesAndProblems_AndReferencesPresent()
    {
        var analysis = new EdnsSupportAnalysis { Subject = "example.com" };
        // Pretend we checked three servers for summary and add synthetic assessments
        analysis.ServerSupport["ns1 (192.0.2.1)"] = new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1232, DoBit = true };
        analysis.ServerSupport["ns2 (192.0.2.2)"] = new EdnsSupportInfo { Supported = true, UdpPayloadSize = 1400, DoBit = true };
        analysis.ServerSupport["ns3 (192.0.2.3)"] = new EdnsSupportInfo { Supported = false, UdpPayloadSize = 0 };

        // Info positives
        analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Category = "EDNS", Target = "ns1", Code = EdnsCodes.Supported, Message = "EDNS supported" });
        analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Category = "EDNS", Target = "ns1", Code = EdnsCodes.UdpSizeOk, Message = "UDP size ok" });
        analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Category = "EDNS", Target = "ns1", Code = EdnsCodes.VersionZero, Message = "Version 0" });
        // Problem
        analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Warning, Category = "EDNS", Target = "ns2", Code = EdnsCodes.BufferTooLarge, Message = ">1232" });

        var view = Converters.Convert(analysis);

        // Summary counts from ServerSupport
        Assert.Equal(3, view.TotalChecked);
        Assert.Equal(2, view.SupportedCount);
        Assert.Equal(1, view.NotSupportedCount);

        // Partition checks
        var recCodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in view.Recommendations) recCodes.Add(r.Code);
        Assert.Contains(EdnsCodes.BufferTooLarge, recCodes);
        Assert.DoesNotContain(EdnsCodes.Supported, recCodes);

        var posCodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in view.Positives) posCodes.Add(p.Code);
        Assert.Contains(EdnsCodes.Supported, posCodes);
        Assert.Contains(EdnsCodes.UdpSizeOk, posCodes);
        Assert.Contains(EdnsCodes.VersionZero, posCodes);

        // References include RFC 6891 regardless of positives/problems
        Assert.Contains(view.References, r => r.IndexOf("rfc6891", StringComparison.OrdinalIgnoreCase) >= 0);
    }
}

