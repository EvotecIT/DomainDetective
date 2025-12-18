using DomainDetective.PowerShell;
using Xunit;

namespace DomainDetective.Tests;

public class TestInvokeDomainWizardSelection
{
    [Fact]
    public void FullPreset_IncludesOptionalChecksWithoutPrompt()
    {
        var result = CmdletInvokeDomainWizard.GetOptionalChecksBehavior(1);

        Assert.True(result.RunHttp);
        Assert.True(result.CheckTakeover);
        Assert.False(result.PromptForOptionalChecks);
    }

    [Fact]
    public void CustomPreset_PromptsForOptionalChecks()
    {
        var result = CmdletInvokeDomainWizard.GetOptionalChecksBehavior(4);

        Assert.False(result.RunHttp);
        Assert.False(result.CheckTakeover);
        Assert.True(result.PromptForOptionalChecks);
    }

    [Fact]
    public void OtherPresets_DoNotIncludeOptionalChecks()
    {
        var result = CmdletInvokeDomainWizard.GetOptionalChecksBehavior(0);

        Assert.False(result.RunHttp);
        Assert.False(result.CheckTakeover);
        Assert.False(result.PromptForOptionalChecks);
    }
}

