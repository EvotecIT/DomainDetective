namespace DomainDetective.Tests;

/// <summary>Helper methods for dynamically skipping tests.</summary>
public static class Skip
{
    /// <summary>Skips the test if the condition is true.</summary>
    /// <param name="condition">Condition that triggers skipping.</param>
    /// <param name="reason">Reason to show in test output.</param>
    public static void If(bool condition, string? reason = null)
    {
        if (condition)
        {
            throw Xunit.Sdk.SkipException.ForSkip(reason ?? string.Empty);
        }
    }

    /// <summary>Skips the test if the condition is false.</summary>
    /// <param name="condition">Condition that prevents skipping.</param>
    /// <param name="reason">Reason to show in test output.</param>
    public static void IfNot(bool condition, string? reason = null)
    {
        if (!condition)
        {
            throw Xunit.Sdk.SkipException.ForSkip(reason ?? string.Empty);
        }
    }
}
