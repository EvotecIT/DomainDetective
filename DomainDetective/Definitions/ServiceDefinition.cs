namespace DomainDetective;

/// <summary>
/// Defines a target host and port for service checks.
/// </summary>
/// <remarks>
/// <para>Instances describe endpoints that <see cref="DomainHealthCheck"/> can
/// verify.</para>
/// </remarks>
public readonly struct ServiceDefinition {
    /// <summary>
    /// Initializes a new instance of the <see cref="ServiceDefinition"/> struct.
    /// </summary>
    /// <param name="host">The host name to query.</param>
    /// <param name="port">The port used by the service.</param>
    public ServiceDefinition(string host, int port) {
        Host = host;
        Port = port;
    }

    /// <summary>Gets the host name.</summary>
    public string Host { get; }

    /// <summary>Gets the service port.</summary>
    public int Port { get; }
}