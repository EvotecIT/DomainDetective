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
        Assert.Equal(CtIngestionOperation.GetLatestCertificate, normalized.Operations);
        Assert.False(normalized.RequireFullCertificate);
        Assert.Equal("next-page", normalized.ContinuationToken);
        Assert.Null(normalized.PageSize);
        Assert.Null(normalized.Timeout);
    }
}
