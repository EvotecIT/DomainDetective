using DomainDetective.Helpers;
using System;
using System.Management.Automation;

namespace DomainDetective.PowerShell;

/// <summary>Validates that a parameter value is a syntactically valid DNS domain name (IDN-aware).</summary>
/// <para>Uses <see cref="DomainHelper.ValidateIdn(string)"/> for validation.</para>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field)]
public sealed class ValidateDomainNameAttribute : ValidateArgumentsAttribute
{
    /// <summary>Validates the bound parameter value.</summary>
    /// <param name="arguments">The value being bound.</param>
    /// <param name="engineIntrinsics">PowerShell engine services.</param>
    protected override void Validate(object arguments, EngineIntrinsics engineIntrinsics)
    {
        if (arguments is null)
        {
            throw new ValidationMetadataException("Domain name cannot be null.");
        }

        if (arguments is string value)
        {
            ValidateOne(value);
            return;
        }

        if (arguments is string[] values)
        {
            foreach (var item in values)
            {
                ValidateOne(item);
            }
            return;
        }

        throw new ValidationMetadataException($"Domain name must be a string or string[]. Got: {arguments.GetType().FullName}");
    }

    private static void ValidateOne(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ValidationMetadataException("Domain name cannot be empty.");
        }

        try
        {
            _ = DomainHelper.ValidateIdn(value);
        }
        catch (ArgumentException ex)
        {
            throw new ValidationMetadataException(ex.Message, ex);
        }
    }
}
