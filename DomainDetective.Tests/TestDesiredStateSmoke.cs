using System;
using System.Linq;
using System.Reflection;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;

namespace DomainDetective.Tests;

public sealed class TestDesiredStateSmoke {
    [Fact]
    public void Evaluate_AllPoliciesEnabled_DoesNotThrow() {
        var profile = new DesiredStateProfile();

        var policyProps = typeof(DesiredStateProfile)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(p => p.CanWrite)
            .Where(p => p.PropertyType.Namespace == typeof(DesiredStateProfile).Namespace)
            .Where(p => p.PropertyType.Name.StartsWith("DesiredState", StringComparison.Ordinal) && p.PropertyType.Name.EndsWith("Policy", StringComparison.Ordinal))
            .ToArray();

        foreach (var prop in policyProps) {
            object policy;
            try {
                policy = Activator.CreateInstance(prop.PropertyType) ?? throw new InvalidOperationException($"Activator.CreateInstance returned null for '{prop.PropertyType.FullName}'.");
            } catch (Exception ex) {
                throw new InvalidOperationException($"Failed to create desired state policy '{prop.PropertyType.FullName}'.", ex);
            }

            var enabledProp = prop.PropertyType.GetProperty("Enabled", BindingFlags.Instance | BindingFlags.Public);
            if (enabledProp != null && enabledProp.PropertyType == typeof(bool?) && enabledProp.CanWrite) {
                enabledProp.SetValue(policy, true);
            }

            prop.SetValue(profile, policy);
        }

        profile.Normalize();

        var cfg = new DesiredStateConfiguration {
            Defaults = profile
        };

        var effective = cfg.ResolveProfile("example.com", MailDomainClassificationCategory.SendingAndReceiving);
        var health = new DomainHealthCheck();

        _ = DesiredStateEvaluator.Evaluate("example.com", health, effective, MailDomainClassificationCategory.SendingAndReceiving);
    }
}

