using System;
using System.Collections.Generic;
using System.Management.Automation;
using DomainDetective.Helpers;

namespace DomainDetective.PowerShell;

internal static class DesiredStateCmdletValidation {
    internal static string[]? NormalizeDomainSuffixes(PSCmdlet cmdlet, string parameterName, string[]? suffixes) {
        if (cmdlet == null) {
            throw new ArgumentNullException(nameof(cmdlet));
        }
        if (string.IsNullOrWhiteSpace(parameterName)) {
            throw new ArgumentException("Parameter name cannot be empty.", nameof(parameterName));
        }
        if (suffixes == null) {
            return null;
        }

        var normalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in suffixes) {
            if (string.IsNullOrWhiteSpace(s)) {
                ThrowInvalidSuffix(cmdlet, parameterName, s, "Domain suffix cannot be empty.");
            }

            string value;
            try {
                value = DomainHelper.ValidateIdn(s);
            } catch (Exception ex) {
                ThrowInvalidSuffix(cmdlet, parameterName, s, $"Invalid domain suffix '{s}': {ex.Message}", ex);
                return null;
            }

            normalized.Add(value);
        }

        if (normalized.Count == 0) {
            return Array.Empty<string>();
        }

        var output = new string[normalized.Count];
        normalized.CopyTo(output);
        return output;
    }

    private static void ThrowInvalidSuffix(PSCmdlet cmdlet, string parameterName, string? value, string message, Exception? exception = null) {
        var ex = exception ?? new ArgumentException(message, parameterName);
        var err = new ErrorRecord(ex, "InvalidDomainSuffix", ErrorCategory.InvalidArgument, value);
        cmdlet.ThrowTerminatingError(err);
    }
}
