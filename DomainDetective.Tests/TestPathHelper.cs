using DomainDetective.Helpers;
using DomainDetective.TimeSeries.DmarcAggregate;
using DomainDetective.TimeSeries.Registration;
using DomainDetective.TimeSeries.TlsRpt;
using System;
using System.IO;

namespace DomainDetective.Tests;

public class TestPathHelper
{
    [Fact]
    public void CombineUnderRoot_RejectsTraversal()
    {
        var root = Path.Combine(Path.GetTempPath(), "domain-detective-tests");
        Assert.Throws<InvalidOperationException>(() => PathHelper.CombineUnderRoot(root, "..", "escape"));
    }

    [Theory]
    [InlineData("../../etc/passwd")]
    [InlineData("..\\..\\etc\\passwd")]
    public void TimeSeriesStores_RejectTraversalDomain(string domain)
    {
        var root = Path.Combine(Path.GetTempPath(), "domain-detective-tests");

        Assert.Throws<ArgumentException>(() => new DmarcAggregateTimeSeriesStore(root).GetDomainDirectory(domain));
        Assert.Throws<ArgumentException>(() => new RegistrationTimeSeriesStore(root).GetDomainDirectory(domain));
        Assert.Throws<ArgumentException>(() => new TlsRptTimeSeriesStore(root).GetDomainDirectory(domain));
    }
}

