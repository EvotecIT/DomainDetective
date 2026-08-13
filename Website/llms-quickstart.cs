using DomainDetective;

var healthCheck = new DomainHealthCheck();
await healthCheck.Verify("example.com");

Console.WriteLine(healthCheck.ToJson());
