using Xunit;

namespace DomainDetective.Tests;

// Serializes tests that modify global port-scan profile state
[CollectionDefinition("PortScan")]
public class PortScanCollection : ICollectionFixture<object> { }

// Serializes DNSSEC trust-anchor cache tests to avoid shared cache collisions
[CollectionDefinition("DnssecCache")]
public class DnssecCacheCollection : ICollectionFixture<object> { }

