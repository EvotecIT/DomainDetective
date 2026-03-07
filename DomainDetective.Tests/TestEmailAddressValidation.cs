using DnsClientX;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestEmailAddressValidation {
    private static EmailAddressValidationOptions CreateOptions() => new EmailAddressValidationOptions {
        CheckMx = false,
        CheckSmtp = false,
        CheckGravatar = false,
        CheckHaveIBeenPwned = false
    };

    [Fact]
    public async Task ValidSyntaxParsesDomain() {
        var analysis = new EmailAddressValidationAnalysis();
        await analysis.AnalyzeAsync("user@example.com", CreateOptions(), new InternalLogger(false));

        Assert.True(analysis.Syntax.IsValidSyntax);
        Assert.Equal("example.com", analysis.Syntax.Domain);
        Assert.Equal("user", analysis.Syntax.Username);
    }

    [Fact]
    public async Task RoleAccountIsRisky() {
        var analysis = new EmailAddressValidationAnalysis();
        await analysis.AnalyzeAsync("support@example.com", CreateOptions(), new InternalLogger(false));

        Assert.True(analysis.Misc.IsRoleAccount);
        Assert.Equal(EmailReachabilityStatus.Risky, analysis.IsReachable);
    }

    [Fact]
    public async Task DisposableDomainDetected() {
        var analysis = new EmailAddressValidationAnalysis();
        await analysis.AnalyzeAsync("user@mailinator.com", CreateOptions(), new InternalLogger(false));

        Assert.True(analysis.Misc.IsDisposable);
        Assert.Equal(EmailReachabilityStatus.Risky, analysis.IsReachable);
    }

    [Fact]
    public async Task FreeProviderDetected() {
        var analysis = new EmailAddressValidationAnalysis();
        await analysis.AnalyzeAsync("user@gmail.com", CreateOptions(), new InternalLogger(false));

        Assert.True(analysis.Misc.IsFreeProvider);
        Assert.True(analysis.Misc.IsB2C);
    }

    [Fact]
    public async Task InvalidSyntaxMarkedInvalid() {
        var analysis = new EmailAddressValidationAnalysis();
        await analysis.AnalyzeAsync("not-an-email", CreateOptions(), new InternalLogger(false));

        Assert.False(analysis.Syntax.IsValidSyntax);
        Assert.Equal(EmailReachabilityStatus.Invalid, analysis.IsReachable);
    }

    [Fact]
    public async Task SuggestionProvidedForCommonTypos() {
        var analysis = new EmailAddressValidationAnalysis();
        await analysis.AnalyzeAsync("test@gmali.com", CreateOptions(), new InternalLogger(false));

        Assert.Equal("test@gmail.com", analysis.Syntax.Suggestion);
    }

    [Fact]
    public async Task NullMxMarksDomainAsNotAcceptingMail() {
        var options = CreateOptions();
        options.CheckMx = true;

        var analysis = new EmailAddressValidationAnalysis {
            DnsConfiguration = new DnsConfiguration {
                QueryDnsOverride = (_, recordType) => recordType switch {
                    DnsRecordType.MX => Task.FromResult(new[] { new DnsAnswer { DataRaw = "0 .", Type = DnsRecordType.MX } }),
                    DnsRecordType.A => Task.FromResult(new[] { new DnsAnswer { DataRaw = "192.0.2.10", Type = DnsRecordType.A } }),
                    DnsRecordType.AAAA => Task.FromResult(new[] { new DnsAnswer { DataRaw = "2001:db8::10", Type = DnsRecordType.AAAA } }),
                    _ => Task.FromResult(System.Array.Empty<DnsAnswer>())
                }
            }
        };
        await analysis.AnalyzeAsync("user@example.com", options, new InternalLogger(false));

        Assert.True(analysis.Mx.Checked);
        Assert.True(analysis.Mx.HasNullMx);
        Assert.False(analysis.Mx.AcceptsMail);
        Assert.False(analysis.Mx.UsedApexFallback);
        Assert.Empty(analysis.Mx.Records);
        Assert.Equal(EmailReachabilityStatus.Invalid, analysis.IsReachable);
    }

    [Fact]
    public async Task DisposableOverrideReplacesBuiltin() {
        var temp = System.IO.Path.GetTempFileName();
        try {
            System.IO.File.WriteAllText(temp, "custom-disposable.test");
            var options = CreateOptions();
            options.DisposableDomainsPath = temp;

            var custom = new EmailAddressValidationAnalysis();
            await custom.AnalyzeAsync("user@custom-disposable.test", options, new InternalLogger(false));
            Assert.True(custom.Misc.IsDisposable);

            var builtin = new EmailAddressValidationAnalysis();
            await builtin.AnalyzeAsync("user@mailinator.com", options, new InternalLogger(false));
            Assert.False(builtin.Misc.IsDisposable);
        } finally {
            TryDeleteFile(temp);
        }
    }

    [Fact]
    public async Task B2COverrideReplacesBuiltin() {
        var temp = System.IO.Path.GetTempFileName();
        try {
            System.IO.File.WriteAllText(temp, "custom-b2c.test");
            var options = CreateOptions();
            options.B2CProvidersPath = temp;

            var analysis = new EmailAddressValidationAnalysis();
            await analysis.AnalyzeAsync("user@custom-b2c.test", options, new InternalLogger(false));
            Assert.True(analysis.Misc.IsB2C);
        } finally {
            TryDeleteFile(temp);
        }
    }

    private static void TryDeleteFile(string path) {
        try {
            if (System.IO.File.Exists(path)) {
                System.IO.File.Delete(path);
            }
        } catch (System.IO.IOException) {
            // best-effort cleanup for temporary test files
        } catch (System.UnauthorizedAccessException) {
            // best-effort cleanup for temporary test files
        }
    }
}
