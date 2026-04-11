using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Provides safe default certificate transparency provider profiles.
/// </summary>
public static class CtProviderProfiles
{
    /// <summary>crt.sh HTTPS provider identifier.</summary>
    public const string CrtShHttpProviderId = "crt.sh";

    /// <summary>crt.sh PostgreSQL provider identifier.</summary>
    public const string CrtShPostgreSqlProviderId = "crt.sh-db";

    /// <summary>CertSpotter provider identifier.</summary>
    public const string CertSpotterProviderId = "certspotter";

    /// <summary>Native CT log provider identifier.</summary>
    public const string NativeCtProviderId = "native-ct";

    /// <summary>
    /// Creates the conservative default profile for crt.sh HTTPS queries.
    /// </summary>
    public static CtProviderProfile CreateCrtShHttp()
    {
        return new CtProviderProfile
        {
            ProviderId = CrtShHttpProviderId,
            DisplayName = "crt.sh HTTPS",
            Capabilities = CtProviderCapabilities.SubdomainExpansion |
                           CtProviderCapabilities.ExactHostLookup,
            RateLimit = new CtProviderRateLimitProfile
            {
                MaxRequestsPerMinute = 5,
                MaxConcurrentRequests = 1,
                MinimumRequestSpacing = TimeSpan.FromSeconds(15),
                RequestTimeout = TimeSpan.FromSeconds(30),
                RetryBaseDelay = TimeSpan.FromSeconds(2),
                RetryMaxDelay = TimeSpan.FromSeconds(30),
                CooldownAfterRateLimit = TimeSpan.FromMinutes(5)
            },
            Notes = "Public crt.sh HTTPS has historically been heavily loaded; keep this profile conservative and configurable."
        };
    }

    /// <summary>
    /// Creates a crt.sh HTTPS profile from certificate inventory capture options.
    /// </summary>
    /// <param name="options">Certificate inventory capture options.</param>
    public static CtProviderProfile CreateCrtShHttp(CertificateInventoryCaptureOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        CtProviderProfile defaults = CreateCrtShHttp();
        return new CtProviderProfile
        {
            ProviderId = defaults.ProviderId,
            DisplayName = defaults.DisplayName,
            Capabilities = defaults.Capabilities,
            RateLimit = new CtProviderRateLimitProfile
            {
                MaxRequestsPerMinute = defaults.RateLimit.MaxRequestsPerMinute,
                MaxConcurrentRequests = defaults.RateLimit.MaxConcurrentRequests,
                MinimumRequestSpacing = options.PassiveCtCrtShMinimumSpacing,
                RequestTimeout = options.PassiveCtRequestTimeout,
                RetryBaseDelay = options.PassiveCtRetryBaseDelay,
                RetryMaxDelay = options.PassiveCtRetryMaxDelay,
                CooldownAfterRateLimit = options.PassiveCtSourceCooldown,
                MaximumRequestsPerRun = options.PassiveCtCrtShMaximumRequestsPerRun > 0
                    ? options.PassiveCtCrtShMaximumRequestsPerRun
                    : null
            },
            Notes = defaults.Notes
        };
    }

    /// <summary>
    /// Creates the conservative default profile for crt.sh PostgreSQL queries.
    /// </summary>
    public static CtProviderProfile CreateCrtShPostgreSql()
    {
        return new CtProviderProfile
        {
            ProviderId = CrtShPostgreSqlProviderId,
            DisplayName = "crt.sh PostgreSQL",
            Capabilities = CtProviderCapabilities.SubdomainExpansion |
                           CtProviderCapabilities.ExactHostLookup |
                           CtProviderCapabilities.CertificateHistory |
                           CtProviderCapabilities.DomainTreeHistory |
                           CtProviderCapabilities.FullCertificateDer,
            RateLimit = new CtProviderRateLimitProfile
            {
                MaxConcurrentRequests = 2,
                RequestTimeout = TimeSpan.FromSeconds(30),
                RetryBaseDelay = TimeSpan.FromSeconds(2),
                RetryMaxDelay = TimeSpan.FromSeconds(30),
                CooldownAfterRateLimit = TimeSpan.FromMinutes(5)
            },
            Notes = "Default concurrency stays below the public crt.sh PostgreSQL per-IP connection limit discussed by crt.sh operators."
        };
    }

    /// <summary>
    /// Creates a crt.sh PostgreSQL profile from certificate inventory capture options.
    /// </summary>
    /// <param name="options">Certificate inventory capture options.</param>
    public static CtProviderProfile CreateCrtShPostgreSql(CertificateInventoryCaptureOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        CtProviderProfile defaults = CreateCrtShPostgreSql();
        return new CtProviderProfile
        {
            ProviderId = defaults.ProviderId,
            DisplayName = defaults.DisplayName,
            Capabilities = defaults.Capabilities,
            RateLimit = new CtProviderRateLimitProfile
            {
                MaxConcurrentRequests = Math.Max(1, options.CrtShPostgreSqlMaximumConcurrentRequests),
                RequestTimeout = TimeSpan.FromSeconds(Math.Max(1, options.CrtShPostgreSqlCommandTimeoutSeconds)),
                RetryBaseDelay = defaults.RateLimit.RetryBaseDelay,
                RetryMaxDelay = defaults.RateLimit.RetryMaxDelay,
                CooldownAfterRateLimit = defaults.RateLimit.CooldownAfterRateLimit
            },
            Notes = defaults.Notes
        };
    }

    /// <summary>
    /// Creates the default profile for CertSpotter CT Search API queries.
    /// </summary>
    public static CtProviderProfile CreateCertSpotter()
    {
        return new CtProviderProfile
        {
            ProviderId = CertSpotterProviderId,
            DisplayName = "CertSpotter",
            Capabilities = CtProviderCapabilities.SubdomainExpansion |
                           CtProviderCapabilities.ExactHostLookup |
                           CtProviderCapabilities.FullCertificateDer |
                           CtProviderCapabilities.Pagination |
                           CtProviderCapabilities.AuthenticationRecommended,
            RateLimit = new CtProviderRateLimitProfile
            {
                MaxConcurrentRequests = 1,
                MinimumRequestSpacing = TimeSpan.FromSeconds(15),
                RequestTimeout = TimeSpan.FromSeconds(30),
                RetryBaseDelay = TimeSpan.FromSeconds(2),
                RetryMaxDelay = TimeSpan.FromSeconds(30),
                CooldownAfterRateLimit = TimeSpan.FromMinutes(5)
            },
            Notes = "CertSpotter supports paging and cert_der expansion; production use should provide an API token and configured budget."
        };
    }

    /// <summary>
    /// Creates a CertSpotter profile from certificate inventory capture options.
    /// </summary>
    /// <param name="options">Certificate inventory capture options.</param>
    public static CtProviderProfile CreateCertSpotter(CertificateInventoryCaptureOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        CtProviderProfile defaults = CreateCertSpotter();
        return new CtProviderProfile
        {
            ProviderId = defaults.ProviderId,
            DisplayName = defaults.DisplayName,
            Capabilities = defaults.Capabilities,
            RateLimit = new CtProviderRateLimitProfile
            {
                MaxConcurrentRequests = defaults.RateLimit.MaxConcurrentRequests,
                MinimumRequestSpacing = options.PassiveCtCertSpotterMinimumSpacing,
                RequestTimeout = options.PassiveCtRequestTimeout,
                RetryBaseDelay = options.PassiveCtRetryBaseDelay,
                RetryMaxDelay = options.PassiveCtRetryMaxDelay,
                CooldownAfterRateLimit = options.PassiveCtSourceCooldown,
                MaximumRequestsPerRun = options.PassiveCtCertSpotterMaximumRequestsPerRun > 0
                    ? options.PassiveCtCertSpotterMaximumRequestsPerRun
                    : null
            },
            Notes = defaults.Notes
        };
    }

    /// <summary>
    /// Creates the default profile for direct native CT log ingestion.
    /// </summary>
    public static CtProviderProfile CreateNativeCtLogs()
    {
        return new CtProviderProfile
        {
            ProviderId = NativeCtProviderId,
            DisplayName = "Native CT Logs",
            Capabilities = CtProviderCapabilities.SubdomainExpansion |
                           CtProviderCapabilities.FullCertificateDer |
                           CtProviderCapabilities.DurableCursor |
                           CtProviderCapabilities.NativeLogIngestion,
            RateLimit = new CtProviderRateLimitProfile
            {
                MaxConcurrentRequests = 4,
                RequestTimeout = TimeSpan.FromSeconds(30),
                RetryBaseDelay = TimeSpan.FromSeconds(1),
                RetryMaxDelay = TimeSpan.FromSeconds(30),
                CooldownAfterRateLimit = TimeSpan.FromMinutes(10)
            },
            Notes = "Native CT is suited to cursor-based ingestion and local indexing, not ad-hoc full-history domain search."
        };
    }

    /// <summary>
    /// Creates a native CT log profile from certificate inventory capture options.
    /// </summary>
    /// <param name="options">Certificate inventory capture options.</param>
    public static CtProviderProfile CreateNativeCtLogs(CertificateInventoryCaptureOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        CtProviderProfile defaults = CreateNativeCtLogs();
        int maxConcurrentLogs = options.DiscoveryParallelism <= 0
            ? 1
            : (options.NativeCtMaxLogs > 0
                ? Math.Min(options.DiscoveryParallelism, options.NativeCtMaxLogs)
                : options.DiscoveryParallelism);
        return new CtProviderProfile
        {
            ProviderId = defaults.ProviderId,
            DisplayName = defaults.DisplayName,
            Capabilities = defaults.Capabilities,
            RateLimit = new CtProviderRateLimitProfile
            {
                MaxConcurrentRequests = Math.Max(1, maxConcurrentLogs),
                MinimumRequestSpacing = options.NativeCtRequestDelay,
                RequestTimeout = options.NativeCtRequestTimeout,
                RetryBaseDelay = options.NativeCtRetryBaseDelay,
                RetryMaxDelay = options.NativeCtRetryMaxDelay,
                CooldownAfterRateLimit = options.NativeCtCircuitBreakerDuration
            },
            Notes = defaults.Notes
        };
    }

    /// <summary>
    /// Creates all default CT provider profiles from certificate inventory capture options.
    /// </summary>
    /// <param name="options">Certificate inventory capture options.</param>
    public static IReadOnlyList<CtProviderProfile> CreateFromCertificateInventoryOptions(CertificateInventoryCaptureOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        return new[]
        {
            CreateCrtShHttp(options),
            CreateCrtShPostgreSql(options),
            CreateCertSpotter(options),
            CreateNativeCtLogs(options)
        };
    }
}
