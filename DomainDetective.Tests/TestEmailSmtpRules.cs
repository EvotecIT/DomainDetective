using System;
using System.IO;
using System.Linq;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestEmailSmtpRules {
    [Fact]
    public void RulesApplyByDomainAndMxSuffix() {
        var temp = Path.GetTempFileName();
        try {
            File.WriteAllText(temp, @"{
  ""byDomain"": {
    ""example.com"": { ""disableCatchAll"": true, ""smtpTimeoutSeconds"": 30 }
  },
  ""byMxSuffix"": {
    "".antispamcloud.com"": { ""disableCatchAll"": true, ""smtpTimeoutSeconds"": 45 }
  }
}");

            var match = EmailSmtpRuleResolver.Resolve("example.com", new[] { "mx01.antispamcloud.com" }, temp, false);

            Assert.NotNull(match);
            Assert.True(match!.DisableCatchAll ?? false);
            Assert.Equal(45, match.SmtpTimeoutSeconds);
        } finally {
            try { File.Delete(temp); } catch { }
        }
    }

    [Fact]
    public void BuiltinRulesLoadWhenEnabled() {
        var match = EmailSmtpRuleResolver.Resolve("gmail.com", Array.Empty<string>(), null, true);

        Assert.NotNull(match);
        Assert.True(match!.DisableCatchAll ?? false);
    }
}
