using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DBAClientX;
using DomainDetective.CtSql;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestCrtShPostgreSqlCertificateTransparencyProvider {
    [Fact]
    public async Task QueryExactHostLatest_UsesSqlFtsAndReturnsOneTypedCertificate() {
        const string hostName = "api.example.test";
        byte[] certificateDer = CreateCertificate(hostName, out X509Certificate2 certificate);
        using (certificate) {
            var fakeClient = new FakeCrtShPostgreSqlQueryClient(
                new object?[] {
                    certificateDer,
                    new DateTimeOffset(2026, 4, 11, 12, 0, 0, TimeSpan.Zero),
                    hostName,
                    certificate.Issuer,
                    certificate.SerialNumber,
                    new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                    new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
                    new[] { hostName, "www.example.test" }
                });
            using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(new CertificateInventoryCaptureOptions(), fakeClient);

            CtCertificateQueryResult result = await provider.QueryAsync(
                CtCertificateQuery.ForExactHostLatest("API.EXAMPLE.TEST."));

            Assert.Equal(CtProviderProfiles.CrtShPostgreSqlProviderId, result.ProviderId);
            CtCertificateRecord record = Assert.Single(result.Certificates);
            Assert.Equal(CtProviderProfiles.CrtShPostgreSqlProviderId, record.ProviderId);
            Assert.Equal(certificate.SerialNumber, record.ProviderCertificateId);
            Assert.Equal(certificate.Thumbprint, record.Sha1Fingerprint);
            Assert.NotNull(record.Sha256Fingerprint);
            Assert.True(record.HasFullCertificate);
            Assert.Contains(hostName, result.DiscoveredNames, StringComparer.OrdinalIgnoreCase);
            Assert.NotNull(result.ProviderState);
            Assert.Equal(1, result.ProviderState!.SuccessfulRequestCount);

            FakeCrtShPostgreSqlQuery query = Assert.Single(fakeClient.Queries);
            Assert.Contains("identities(c.certificate)", query.Sql, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("LIMIT @limit", query.Sql, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("certificate_identity", query.Sql, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(hostName, query.Parameters["host"]);
            Assert.Equal("*.example.test", query.Parameters["wildcardHost"]);
            Assert.Equal(1, query.Parameters["limit"]);
        }
    }

    [Fact]
    public async Task QueryExactHostHistory_HonorsPageSizeAndWildcardMatches() {
        const string hostName = "mail.example.test";
        byte[] certificateDer = CreateCertificate("*.example.test", out X509Certificate2 certificate);
        using (certificate) {
            var fakeClient = new FakeCrtShPostgreSqlQueryClient(
                new object?[] {
                    certificateDer,
                    new DateTimeOffset(2026, 4, 10, 12, 0, 0, TimeSpan.Zero),
                    "*.example.test",
                    certificate.Issuer,
                    certificate.SerialNumber,
                    new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                    new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
                    new[] { "*.example.test" }
                });
            using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(new CertificateInventoryCaptureOptions(), fakeClient);
            CtCertificateQuery query = new() {
                Name = hostName,
                QueryKind = CtCertificateQueryKind.ExactHostHistory,
                Operations = CtIngestionOperation.GetCertificateHistory,
                RequireFullCertificate = true,
                PageSize = 25
            };

            CtCertificateQueryResult result = await provider.QueryAsync(query);

            Assert.Single(result.Certificates);
            Assert.Contains("*.example.test", result.DiscoveredNames, StringComparer.OrdinalIgnoreCase);
            FakeCrtShPostgreSqlQuery executedQuery = Assert.Single(fakeClient.Queries);
            Assert.Contains("lower(@wildcardHost)", executedQuery.Sql, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("*.example.test", executedQuery.Parameters["wildcardHost"]);
            Assert.Equal(25, executedQuery.Parameters["limit"]);
        }
    }

    [Fact]
    public async Task QueryExactHostLatest_SurfaceMalformedDerAsDiagnostics() {
        const string hostName = "bad-der.example.test";
        var fakeClient = new FakeCrtShPostgreSqlQueryClient(
            new object?[] {
                new byte[] { 1, 2, 3 },
                new DateTimeOffset(2026, 4, 10, 12, 0, 0, TimeSpan.Zero),
                hostName,
                "CN=Test Issuer",
                "1234",
                new DateTimeOffset(2026, 4, 1, 0, 0, 0, TimeSpan.Zero),
                new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero),
                new[] { hostName }
            });
        using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(new CertificateInventoryCaptureOptions(), fakeClient);

        CtCertificateQueryResult result = await provider.QueryAsync(CtCertificateQuery.ForExactHostLatest(hostName));

        CtCertificateRecord record = Assert.Single(result.Certificates);
        Assert.False(record.HasFullCertificate);
        string diagnostic = Assert.Single(record.Diagnostics);
        Assert.Contains("could not be parsed", diagnostic, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(hostName, record.Subject);
        Assert.Equal("1234", record.SerialNumber);
    }

    [Fact]
    public async Task QueryDomainExpansion_UsesNameOnlySqlByDefault() {
        var fakeClient = new FakeCrtShPostgreSqlQueryClient(
            new object?[] { "www.example.test" },
            new object?[] { "*.example.test" },
            new object?[] { "WWW.EXAMPLE.TEST" });
        using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(new CertificateInventoryCaptureOptions(), fakeClient);
        CtCertificateQuery query = new() {
            Name = "Example.Test",
            QueryKind = CtCertificateQueryKind.DomainExpansion,
            Operations = CtIngestionOperation.DiscoverSubdomains,
            RequireFullCertificate = false,
            PageSize = 10
        };

        CtCertificateQueryResult result = await provider.QueryAsync(query);

        Assert.Empty(result.Certificates);
        Assert.Equal(new[] { "*.example.test", "www.example.test" }, result.DiscoveredNames);
        FakeCrtShPostgreSqlQuery sql = Assert.Single(fakeClient.Queries);
        Assert.Contains("SELECT DISTINCT lower(candidate_name)", sql.Sql, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("identities(c.certificate)", sql.Sql, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificate_identity", sql.Sql, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("example.test", sql.Parameters["domain"]);
        Assert.Equal("%.example.test", sql.Parameters["domainSuffix"]);
        Assert.Equal(10, sql.Parameters["limit"]);
    }

    [Fact]
    public async Task QueryDomainExpansion_WithFullCertificateUsesDomainTreeCertificateQuery() {
        const string hostName = "www.example.test";
        byte[] certificateDer = CreateCertificate(hostName, out X509Certificate2 certificate);
        using (certificate) {
            var fakeClient = new FakeCrtShPostgreSqlQueryClient(
                new object?[] {
                    certificateDer,
                    new DateTimeOffset(2026, 4, 9, 12, 0, 0, TimeSpan.Zero),
                    hostName,
                    certificate.Issuer,
                    certificate.SerialNumber,
                    new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                    new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
                    new[] { hostName }
                });
            using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(new CertificateInventoryCaptureOptions(), fakeClient);

            CtCertificateQueryResult result = await provider.QueryAsync(CtCertificateQuery.ForDomainExpansion("example.test", requireFullCertificate: true));

            CtCertificateRecord record = Assert.Single(result.Certificates);
            Assert.True(record.HasFullCertificate);
            Assert.Contains(hostName, result.DiscoveredNames, StringComparer.OrdinalIgnoreCase);
            Assert.Contains("SELECT", fakeClient.Queries[0].Sql, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("c.certificate", fakeClient.Queries[0].Sql, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void QueryBuilders_UseSupportedCertificateFtsPath() {
        string expansion = CrtShPostgreSqlCertificateTransparencyProvider.BuildDomainExpansionNamesQuery();
        string domainTree = CrtShPostgreSqlCertificateTransparencyProvider.BuildDomainTreeCertificateQuery();
        string exact = CrtShPostgreSqlCertificateTransparencyProvider.BuildExactHostCertificateQuery();

        Assert.Contains("identities(c.certificate)", expansion, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("identities(c.certificate)", domainTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("identities(c.certificate)", exact, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("LIMIT @limit", expansion, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("LIMIT @limit", domainTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("LIMIT @limit", exact, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("@wildcardHost", exact, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificate_identity", expansion, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificate_identity", domainTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("certificate_identity", exact, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("WITH ranked_certificates AS", domainTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("WITH ranked_certificates AS", exact, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("FROM ranked_certificates rc", domainTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("FROM ranked_certificates rc", exact, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task QueryAsync_MapsOperationCanceledToTimeoutWhenCallerDidNotCancel() {
        using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(
            new CertificateInventoryCaptureOptions(),
            new FakeCrtShPostgreSqlQueryClient(new OperationCanceledException()));

        CtProviderQueryException exception = await Assert.ThrowsAsync<CtProviderQueryException>(
            () => provider.QueryAsync(CtCertificateQuery.ForExactHostLatest("api.example.test")));

        Assert.Equal(CtProviderOutcomeKind.Timeout, exception.OutcomeKind);
        Assert.Equal("timeout", exception.ProviderErrorCode);
    }

    [Theory]
    [InlineData("40001", CtProviderOutcomeKind.TransientFailure, true)]
    [InlineData("57P03", CtProviderOutcomeKind.TransientFailure, true)]
    [InlineData("53300", CtProviderOutcomeKind.TransientFailure, true)]
    [InlineData("57014", CtProviderOutcomeKind.Timeout, false)]
    [InlineData("28P01", CtProviderOutcomeKind.PermanentFailure, false)]
    [InlineData("XX999", CtProviderOutcomeKind.PermanentFailure, false)]
    public async Task QueryAsync_MapsPostgreSqlStateToTypedProviderOutcome(
        string sqlState,
        CtProviderOutcomeKind expectedOutcome,
        bool expectedRetryAfter) {
        using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(
            new CertificateInventoryCaptureOptions(),
            new FakeCrtShPostgreSqlQueryClient(CreateQueryException(sqlState)));

        CtProviderQueryException exception = await Assert.ThrowsAsync<CtProviderQueryException>(
            () => provider.QueryAsync(CtCertificateQuery.ForExactHostLatest("api.example.test")));

        Assert.Equal(expectedOutcome, exception.OutcomeKind);
        Assert.Equal(sqlState, exception.ProviderErrorCode);
        Assert.Equal(expectedRetryAfter, exception.RetryAfter.HasValue);
    }

    [Fact]
    public async Task QueryAsync_MapsNetworkUnreachableToTransientFailure() {
        using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(
            new CertificateInventoryCaptureOptions(),
            new FakeCrtShPostgreSqlQueryClient(new DbaQueryExecutionException(
                "failed",
                "SELECT 1",
                new FakeTransientConnectException(
                    "Failed to connect to [2a0e:ac00:c7:d449::5bc7:d449]:5432",
                    new SocketException((int)SocketError.NetworkUnreachable)))));

        CtProviderQueryException exception = await Assert.ThrowsAsync<CtProviderQueryException>(
            () => provider.QueryAsync(CtCertificateQuery.ForExactHostLatest("api.example.test")));

        Assert.Equal(CtProviderOutcomeKind.TransientFailure, exception.OutcomeKind);
        Assert.Equal("network-unreachable", exception.ProviderErrorCode);
        Assert.True(exception.RetryAfter.HasValue);
    }

    [Fact]
    public async Task QueryAsync_MapsConnectTimeoutToTransientFailure() {
        using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(
            new CertificateInventoryCaptureOptions(),
            new FakeCrtShPostgreSqlQueryClient(new DbaQueryExecutionException(
                "failed",
                "SELECT 1",
                new FakeTransientConnectException(
                    "Failed to connect to 91.199.212.73:5432",
                    new TimeoutException("Timeout during connection attempt")))));

        CtProviderQueryException exception = await Assert.ThrowsAsync<CtProviderQueryException>(
            () => provider.QueryAsync(CtCertificateQuery.ForExactHostLatest("api.example.test")));

        Assert.Equal(CtProviderOutcomeKind.TransientFailure, exception.OutcomeKind);
        Assert.Equal("connect-timeout", exception.ProviderErrorCode);
        Assert.True(exception.RetryAfter.HasValue);
    }

    [Fact]
    public async Task QueryAsync_MapsTransientConnectFailureWithoutSocketCode() {
        using var provider = new CrtShPostgreSqlCertificateTransparencyProvider(
            new CertificateInventoryCaptureOptions(),
            new FakeCrtShPostgreSqlQueryClient(new DbaQueryExecutionException(
                "failed",
                "SELECT 1",
                new FakeTransientConnectException(
                    "Failed to connect to crt.sh PostgreSQL endpoint",
                    new InvalidOperationException("transport failed before socket classification")))));

        CtProviderQueryException exception = await Assert.ThrowsAsync<CtProviderQueryException>(
            () => provider.QueryAsync(CtCertificateQuery.ForExactHostLatest("api.example.test")));

        Assert.Equal(CtProviderOutcomeKind.TransientFailure, exception.OutcomeKind);
        Assert.Equal("connect-failure", exception.ProviderErrorCode);
        Assert.True(exception.RetryAfter.HasValue);
    }

    [Fact]
    public void BuildCrtShPostgreSqlConnectionString_PrefersResolvedIpv4Address() {
        string connectionString = CrtShPostgreSqlCertificateTransparencyProvider.BuildCrtShPostgreSqlConnectionString(
            new CertificateInventoryCaptureOptions {
                CrtShPostgreSqlCommandTimeoutSeconds = 9
            },
            _ => new[] {
                IPAddress.Parse("2a0e:ac00:c7:d449::5bc7:d449"),
                IPAddress.Parse("91.199.212.73")
            });
        var builder = new DbConnectionStringBuilder {
            ConnectionString = connectionString
        };

        Assert.Equal("91.199.212.73", builder["Host"]);
        Assert.Equal("9", builder["Timeout"].ToString());
        Assert.Equal("9", builder["Command Timeout"].ToString());
    }

    [Fact]
    public void BuildCrtShPostgreSqlConnectionString_FallsBackToPinnedIpv4WhenDnsFails() {
        string connectionString = CrtShPostgreSqlCertificateTransparencyProvider.BuildCrtShPostgreSqlConnectionString(
            new CertificateInventoryCaptureOptions(),
            _ => throw new SocketException((int)SocketError.HostNotFound));
        var builder = new DbConnectionStringBuilder {
            ConnectionString = connectionString
        };

        Assert.Equal(CrtShPostgreSqlCertificateTransparencyProvider.DefaultCrtShPostgreSqlPinnedIpv4Address, builder["Host"]);
    }

    private static byte[] CreateCertificate(string commonName, out X509Certificate2 certificate) {
        RSA rsa = RSA.Create(2048);
        try {
            var request = new CertificateRequest(
                $"CN={commonName}",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            certificate = request.CreateSelfSigned(
                new DateTimeOffset(2026, 4, 1, 0, 0, 0, TimeSpan.Zero),
                new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero));
            return certificate.Export(X509ContentType.Cert);
        } finally {
            rsa.Dispose();
        }
    }

    private static DbaQueryExecutionException CreateQueryException(string sqlState)
        => new("failed", "SELECT 1", new FakeSqlStateException(sqlState));

    private sealed class FakeSqlStateException : Exception {
        public FakeSqlStateException(string sqlState)
            : base("Fake PostgreSQL provider exception.") {
            SqlState = sqlState;
        }

        public string SqlState { get; }
    }

    private sealed class FakeTransientConnectException : Exception {
        public FakeTransientConnectException(string message, Exception innerException)
            : base(message, innerException) {
        }

        public bool IsTransient => true;
    }

    private sealed class FakeCrtShPostgreSqlQueryClient : ICrtShPostgreSqlQueryClient {
        private readonly List<object?[]> _rows;
        private readonly Exception? _exception;

        public FakeCrtShPostgreSqlQueryClient(params object?[][] rows) {
            _rows = rows.ToList();
        }

        public FakeCrtShPostgreSqlQueryClient(Exception exception) {
            _rows = new List<object?[]>();
            _exception = exception;
        }

        public List<FakeCrtShPostgreSqlQuery> Queries { get; } = new();

        public Task<IReadOnlyList<T>> QueryAsync<T>(
            string connectionString,
            string query,
            Func<IDataRecord, T> map,
            IReadOnlyDictionary<string, object?> parameters,
            CancellationToken cancellationToken) {
            Queries.Add(new FakeCrtShPostgreSqlQuery(
                connectionString,
                query,
                new Dictionary<string, object?>(parameters, StringComparer.OrdinalIgnoreCase)));
            if (_exception != null) {
                throw _exception;
            }

            // Tests pass a single static rowset; add explicit batches if a future case issues multiple distinct SQL queries.
            IReadOnlyList<T> mappedRows = _rows
                .Select(row => map(new FakeDataRecord(row)))
                .ToList();
            return Task.FromResult(mappedRows);
        }

        public void Dispose() {
        }
    }

    private sealed record FakeCrtShPostgreSqlQuery(
        string ConnectionString,
        string Sql,
        IReadOnlyDictionary<string, object?> Parameters);

    private sealed class FakeDataRecord : IDataRecord {
        private readonly object?[] _values;

        public FakeDataRecord(object?[] values) {
            _values = values;
        }

        public object this[int i] => _values[i]!;
        public object this[string name] => throw new NotSupportedException();
        public int FieldCount => _values.Length;
        public bool GetBoolean(int i) => (bool)_values[i]!;
        public byte GetByte(int i) => (byte)_values[i]!;
        public long GetBytes(int i, long fieldOffset, byte[]? buffer, int bufferoffset, int length) => throw new NotSupportedException();
        public char GetChar(int i) => (char)_values[i]!;
        public long GetChars(int i, long fieldoffset, char[]? buffer, int bufferoffset, int length) => throw new NotSupportedException();
        public IDataReader GetData(int i) => throw new NotSupportedException();
        public string GetDataTypeName(int i) => GetFieldType(i).Name;
        public DateTime GetDateTime(int i) => (DateTime)_values[i]!;
        public decimal GetDecimal(int i) => (decimal)_values[i]!;
        public double GetDouble(int i) => (double)_values[i]!;
        public Type GetFieldType(int i) => _values[i]?.GetType() ?? typeof(DBNull);
        public float GetFloat(int i) => (float)_values[i]!;
        public Guid GetGuid(int i) => (Guid)_values[i]!;
        public short GetInt16(int i) => (short)_values[i]!;
        public int GetInt32(int i) => (int)_values[i]!;
        public long GetInt64(int i) => (long)_values[i]!;
        public string GetName(int i) => i.ToString(System.Globalization.CultureInfo.InvariantCulture);
        public int GetOrdinal(string name) => int.Parse(name, System.Globalization.CultureInfo.InvariantCulture);
        public string GetString(int i) => (string)_values[i]!;
        public object GetValue(int i) => _values[i] ?? DBNull.Value;
        public int GetValues(object[] values) {
            int count = Math.Min(values.Length, _values.Length);
            for (int i = 0; i < count; i++) {
                values[i] = _values[i] ?? DBNull.Value;
            }

            return count;
        }

        public bool IsDBNull(int i) => _values[i] == null || _values[i] == DBNull.Value;
    }
}
