using System;
using Xunit;

namespace DomainDetective.Tests;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class IntegrationFactAttribute : FactAttribute {
    public IntegrationFactAttribute() {
        if (!IsEnabled()) {
            Skip = "Integration tests are opt-in. Set DOMAINDETECTIVE_INTEGRATION=1 to enable.";
        }
    }

    private static bool IsEnabled() {
        var flag = Environment.GetEnvironmentVariable("DOMAINDETECTIVE_INTEGRATION");
        return string.Equals(flag, "1", StringComparison.OrdinalIgnoreCase);
    }
}
