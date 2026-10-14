using System.Collections.Generic;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests;

public class TestSnmpRecommendations {
    [Fact]
    public void RegistersCodesWithContent() {
        var map = new Dictionary<string, RecommendationAdvice>();
        new SnmpRecommendations().Register(map);

        Assert.Contains(SnmpCodes.Responds, map.Keys);
        Assert.Contains(SnmpCodes.Disabled, map.Keys);

        var responds = map[SnmpCodes.Responds];
        Assert.Equal("Restrict or disable SNMP access", responds.Title);
        Assert.Contains("Unauthenticated SNMP responses", responds.Why);
        Assert.Contains("Disable SNMP", responds.How);

        var disabled = map[SnmpCodes.Disabled];
        Assert.Equal("No matching SNMP response observed", disabled.Title);
        Assert.Contains("No response to public probes", disabled.Why);
        Assert.Contains("Verify SNMP configuration", disabled.How);
    }
}

