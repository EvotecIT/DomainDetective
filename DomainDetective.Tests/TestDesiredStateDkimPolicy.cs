using DomainDetective.DesiredState;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestDesiredStateDkimPolicy {
    [Fact]
    public void NormalizeDefaults_Resets_Invalid_MinKeyBits() {
        var policy = new DesiredStateDkimPolicy { MinKeyBits = -1 };
        policy.NormalizeDefaults();
        Assert.Null(policy.MinKeyBits);

        policy.MinKeyBits = 20000;
        policy.NormalizeDefaults();
        Assert.Null(policy.MinKeyBits);

        policy.MinKeyBits = 2048;
        policy.NormalizeDefaults();
        Assert.Equal(2048, policy.MinKeyBits);
    }
}
