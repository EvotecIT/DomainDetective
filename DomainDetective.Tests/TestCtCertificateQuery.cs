using System;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests;

public class TestCtCertificateQuery
{
    [Fact]
    public void NormalizeTrimsNamesAndDropsInvalidPaging()
    {
        var query = new CtCertificateQuery
        {
            Name = "  www.example.com  ",
            Operations = CtIngestionOperation.None,
            RequireFullCertificate = false,
            ContinuationToken = "  next-page  ",
            PageSize = 0,
            Timeout = TimeSpan.Zero
        };

        CtCertificateQuery normalized = query.Normalize();

        Assert.Equal("www.example.com", normalized.Name);
        Assert.Equal(CtCertificateQueryKind.ExactHostLatest, normalized.QueryKind);
        Assert.Equal(CtIngestionOperation.GetLatestCertificate, normalized.Operations);
        Assert.False(normalized.RequireFullCertificate);
        Assert.Equal("next-page", normalized.ContinuationToken);
        Assert.Null(normalized.PageSize);
        Assert.Null(normalized.Timeout);
    }

    [Theory]
    [InlineData(nameof(CtCertificateQuery.ForExactHostLatest), CtCertificateQueryKind.ExactHostLatest, CtIngestionOperation.GetLatestCertificate, true)]
    [InlineData(nameof(CtCertificateQuery.ForExactHostHistory), CtCertificateQueryKind.ExactHostHistory, CtIngestionOperation.GetCertificateHistory, true)]
    [InlineData(nameof(CtCertificateQuery.ForDomainExpansion), CtCertificateQueryKind.DomainExpansion, CtIngestionOperation.DiscoverSubdomains, false)]
    [InlineData(nameof(CtCertificateQuery.ForDomainTreeCertificates), CtCertificateQueryKind.DomainTreeCertificates, CtIngestionOperation.GetDomainTreeCertificates, true)]
    public void FactoriesDescribeProviderIntent(string factoryName, CtCertificateQueryKind queryKind, CtIngestionOperation operations, bool requireFullCertificate)
    {
        CtCertificateQuery query = factoryName switch
        {
            nameof(CtCertificateQuery.ForExactHostLatest) => CtCertificateQuery.ForExactHostLatest("www.example.com"),
            nameof(CtCertificateQuery.ForExactHostHistory) => CtCertificateQuery.ForExactHostHistory("www.example.com"),
            nameof(CtCertificateQuery.ForDomainExpansion) => CtCertificateQuery.ForDomainExpansion("example.com"),
            nameof(CtCertificateQuery.ForDomainTreeCertificates) => CtCertificateQuery.ForDomainTreeCertificates("example.com"),
            _ => throw new InvalidOperationException("Unexpected CT query factory.")
        };

        Assert.Equal(queryKind, query.QueryKind);
        Assert.Equal(operations, query.Operations);
        Assert.Equal(requireFullCertificate, query.RequireFullCertificate);
    }

    [Fact]
    public void NormalizeResolvesOperationsFromQueryKind()
    {
        var query = new CtCertificateQuery
        {
            Name = "example.com",
            QueryKind = CtCertificateQueryKind.DomainExpansion,
            Operations = CtIngestionOperation.None
        };

        CtCertificateQuery normalized = query.Normalize();

        Assert.Equal(CtCertificateQueryKind.DomainExpansion, normalized.QueryKind);
        Assert.Equal(CtIngestionOperation.DiscoverSubdomains, normalized.Operations);
    }

    [Fact]
    public void NormalizeCorrectsMismatchedQueryKindFromOperations()
    {
        var query = new CtCertificateQuery
        {
            Name = "example.com",
            QueryKind = CtCertificateQueryKind.ExactHostLatest,
            Operations = CtIngestionOperation.GetDomainTreeCertificates
        };

        CtCertificateQuery normalized = query.Normalize();

        Assert.Equal(CtCertificateQueryKind.DomainTreeCertificates, normalized.QueryKind);
        Assert.Equal(CtIngestionOperation.GetDomainTreeCertificates, normalized.Operations);
    }
}
