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
            TryDeleteFile(temp);
        }
    }

    [Fact]
    public void MostSpecificMxSuffixRuleWins() {
        var temp = Path.GetTempFileName();
        try {
            File.WriteAllText(temp, @"{
  ""byMxSuffix"": {
    "".protection.outlook.com"": { ""smtpPortOverride"": 2525 },
    "".mail.protection.outlook.com"": { ""smtpPortOverride"": 25 }
  }
}");

            var match = EmailSmtpRuleResolver.Resolve("example.com", new[] { "mx01.mail.protection.outlook.com" }, temp, false);

            Assert.NotNull(match);
            Assert.Equal(25, match!.SmtpPortOverride);
        } finally {
            TryDeleteFile(temp);
        }
    }

    [Fact]
    public void BuiltinRulesLoadWhenEnabled() {
        var match = EmailSmtpRuleResolver.Resolve("gmail.com", Array.Empty<string>(), null, true);

        Assert.NotNull(match);
        Assert.True(match!.DisableCatchAll ?? false);
    }

    private static void TryDeleteFile(string path) {
        try {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        } catch (IOException) {
            // best-effort cleanup for temporary test files
        } catch (UnauthorizedAccessException) {
            // best-effort cleanup for temporary test files
        }
    }
}
