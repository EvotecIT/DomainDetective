using Xunit;

namespace DomainDetective.Tests;

// Serializes tests that modify global port-scan profile state
[CollectionDefinition("PortScan")] 
public class PortScanCollection : ICollectionFixture<object> { }

