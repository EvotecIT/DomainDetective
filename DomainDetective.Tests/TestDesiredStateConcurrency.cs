using System.Linq;
using System.Threading.Tasks;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestDesiredStateConcurrency {
    [Fact]
    public async Task ResolveProfile_IsThreadSafe() {
        var config = new DesiredStateConfiguration {
            Defaults = new DesiredStateProfile {
                Dmarc = new DesiredStateDmarcPolicy { Enabled = true }
            },
            Overrides = new System.Collections.Generic.List<DesiredStateOverride> {
                new DesiredStateOverride {
                    Match = new DesiredStateMatch {
                        DomainPatterns = new[] { "*.example.com" },
                        Classifications = new[] { MailDomainClassificationCategory.SendingOnly }
                    },
                    Profile = new DesiredStateProfile {
                        Spf = new DesiredStateSpfPolicy { Enabled = true }
                    }
                }
            }
        };

        var tasks = Enumerable.Range(0, 32)
            .Select(_ => Task.Run(() => config.ResolveProfile("mail.example.com", MailDomainClassificationCategory.SendingOnly)))
            .ToArray();

        var results = await Task.WhenAll(tasks);
        Assert.All(results, profile => Assert.NotNull(profile));
    }
}
