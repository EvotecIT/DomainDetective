using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    private readonly object _executionLock = new object();
    private Task? _spfTask;
    private Task<DnsAnswer[]>? _mxRecordsTask;
    private Task<string[]>? _mxHostsTask;
    private Dictionary<SmtpTlsExecutionKey, Task>? _smtpTlsTasks;
    private Task? _reverseDnsTask;
    private Task? _daneTask;
    private string? _daneKey;
    private string? _cacheDomain;

    private void ResetExecutionState() {
        lock (_executionLock) {
            _spfTask = null;
            _mxRecordsTask = null;
            _mxHostsTask = null;
            _smtpTlsTasks = null;
            _reverseDnsTask = null;
            _daneTask = null;
            _daneKey = null;
            _cacheDomain = null;
            MailDomainClassification = null;
        }
    }

    private void EnsureCacheDomain(string domainName) {
        lock (_executionLock) {
            EnsureCacheDomainLocked(domainName);
        }
    }

    private void EnsureCacheDomainLocked(string domainName) {
        if (!string.Equals(_cacheDomain, domainName, StringComparison.OrdinalIgnoreCase)) {
            _spfTask = null;
            _mxRecordsTask = null;
            _mxHostsTask = null;
            _smtpTlsTasks = null;
            _reverseDnsTask = null;
            _daneTask = null;
            _daneKey = null;
            _cacheDomain = domainName;
        }
    }

    private Task<DnsAnswer[]> GetMxRecordsAsync(string domainName, CancellationToken cancellationToken) {
        if (!ExecutionOptions.EnableSharedMxCache) {
            return DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
        }
        lock (_executionLock) {
            EnsureCacheDomainLocked(domainName);
            if (_mxRecordsTask == null) {
                _mxRecordsTask = DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            }
            return _mxRecordsTask;
        }
    }

    private Task<string[]> GetMxHostsAsync(string domainName, CancellationToken cancellationToken) {
        if (!ExecutionOptions.EnableSharedMxCache) {
            return BuildMxHostsAsync(domainName, cancellationToken);
        }
        lock (_executionLock) {
            EnsureCacheDomainLocked(domainName);
            if (_mxHostsTask == null) {
                _mxHostsTask = BuildMxHostsAsync(domainName, cancellationToken);
            }
            return _mxHostsTask;
        }
    }

    private async Task<string[]> BuildMxHostsAsync(string domainName, CancellationToken cancellationToken) {
        var mxRecords = await GetMxRecordsAsync(domainName, cancellationToken);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ordered = new List<string>();
        foreach (var host in CertificateAnalysis.ExtractMxHosts(mxRecords)) {
            if (!string.IsNullOrWhiteSpace(host) && seen.Add(host)) {
                ordered.Add(host);
            }
        }
        return ordered.ToArray();
    }

    private Task EnsureSmtpTlsAsync(string domainName, int port, CancellationToken cancellationToken) {
        lock (_executionLock) {
            EnsureCacheDomainLocked(domainName);
            _smtpTlsTasks ??= new Dictionary<SmtpTlsExecutionKey, Task>();
            var resolver = OutboundAddressResolver ?? SmtpTlsAnalysis.OutboundAddressResolver;
            var key = new SmtpTlsExecutionKey(port, SmtpTlsAnalysis.AddressFamily, resolver);
            if (!_smtpTlsTasks.TryGetValue(key, out var task)) {
                task = VerifySmtpTlsInternal(domainName, port, cancellationToken);
                _smtpTlsTasks[key] = task;
            }
            return task;
        }
    }

    private readonly struct SmtpTlsExecutionKey : IEquatable<SmtpTlsExecutionKey> {
        private readonly int _port;
        private readonly MailTransportAddressFamily _addressFamily;
        private readonly Delegate? _resolver;

        public SmtpTlsExecutionKey(int port, MailTransportAddressFamily addressFamily, Delegate? resolver) {
            _port = port;
            _addressFamily = addressFamily;
            _resolver = resolver;
        }

        public bool Equals(SmtpTlsExecutionKey other) =>
            _port == other._port &&
            _addressFamily == other._addressFamily &&
            ReferenceEquals(_resolver, other._resolver);

        public override bool Equals(object? obj) =>
            obj is SmtpTlsExecutionKey other && Equals(other);

        public override int GetHashCode() {
            unchecked {
                var hash = (_port * 397) ^ (int)_addressFamily;
                return (hash * 397) ^ (_resolver == null ? 0 : RuntimeHelpers.GetHashCode(_resolver));
            }
        }
    }

    private Task EnsureReverseDnsAsync(string domainName, CancellationToken cancellationToken) {
        lock (_executionLock) {
            EnsureCacheDomainLocked(domainName);
            if (_reverseDnsTask == null) {
                _reverseDnsTask = VerifyReverseDnsInternal(domainName, cancellationToken);
            }
            return _reverseDnsTask;
        }
    }

    private Task EnsureDaneAsync(string domainName, ServiceType[]? serviceTypes, int[]? ports, CancellationToken cancellationToken) {
        lock (_executionLock) {
            EnsureCacheDomainLocked(domainName);
            var key = BuildDaneKey(serviceTypes, ports);
            if (_daneTask == null || !string.Equals(_daneKey, key, StringComparison.OrdinalIgnoreCase)) {
                _daneKey = key;
                _daneTask = VerifyDaneInternal(domainName, serviceTypes, ports, cancellationToken);
            }
            return _daneTask;
        }
    }

    private static string BuildDaneKey(ServiceType[]? serviceTypes, int[]? ports) {
        if (ports != null && ports.Length > 0) {
            var distinctPorts = new SortedSet<int>(ports);
            return "ports:" + string.Join(",", distinctPorts);
        }
        var types = (serviceTypes != null && serviceTypes.Length > 0)
            ? serviceTypes
            : new[] { ServiceType.SMTP, ServiceType.HTTPS };
        var distinctTypes = new SortedSet<int>(types.Select(t => (int)t));
        return "types:" + string.Join(",", distinctTypes);
    }

    internal Task<DnsAnswer[]> GetMxRecordsAsyncForTest(string domainName, CancellationToken cancellationToken)
        => GetMxRecordsAsync(domainName, cancellationToken);

    private Task EnsureSpfAsync(string domainName, CancellationToken cancellationToken) {
        lock (_executionLock) {
            EnsureCacheDomainLocked(domainName);
            if (_spfTask == null) {
                _spfTask = VerifySPF(domainName, cancellationToken);
            }
            return _spfTask;
        }
    }
}
