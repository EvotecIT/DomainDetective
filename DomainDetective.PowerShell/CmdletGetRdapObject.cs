using System.Management.Automation;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.PowerShell {

/// <summary>Retrieves RDAP objects from a specified service.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Query domain data.</summary>
///   <code>Get-RdapObject -Domain example.com</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDRdapObject", DefaultParameterSetName = "Domain")]
[Alias("Get-RdapObject")]
[OutputType(typeof(object))]
public sealed class CmdletGetRdapObject : AsyncPSCmdlet
{
    /// <param name="Domain">Domain name to query.</param>
    [Parameter(Mandatory = true, ParameterSetName = "Domain", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Domain { get; set; } = string.Empty;

    /// <param name="Tld">Top-level domain to query.</param>
    [Parameter(Mandatory = true, ParameterSetName = "Tld", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Tld { get; set; } = string.Empty;

    /// <param name="Ip">IP address or CIDR to query.</param>
    [Parameter(Mandatory = true, ParameterSetName = "Ip", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Ip { get; set; } = string.Empty;

    /// <param name="AsNumber">Autonomous system number to query.</param>
    [Parameter(Mandatory = true, ParameterSetName = "As", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string AsNumber { get; set; } = string.Empty;

    /// <param name="Entity">Entity handle to query.</param>
    [Parameter(Mandatory = true, ParameterSetName = "Entity", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Entity { get; set; } = string.Empty;

    /// <param name="Registrar">Registrar handle to query.</param>
    [Parameter(Mandatory = true, ParameterSetName = "Registrar", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Registrar { get; set; } = string.Empty;

    /// <param name="Nameserver">Nameserver host to query.</param>
    [Parameter(Mandatory = true, ParameterSetName = "Nameserver", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Nameserver { get; set; } = string.Empty;

    /// <summary>RDAP service endpoint.</summary>
    [Parameter]
    public string ServiceEndpoint { get; set; } = "https://rdap.org";

    private RdapClient _client = null!;

    /// <summary>Initializes the RDAP client.</summary>
    protected override Task BeginProcessingAsync()
    {
        _client = new RdapClient(ServiceEndpoint);
        return Task.CompletedTask;
    }

    /// <summary>Executes the request and writes the object.</summary>
    protected override async Task ProcessRecordAsync()
    {
        object? result = ParameterSetName switch
        {
            "Domain" => await _client.GetDomain(Domain, CancelToken).ConfigureAwait(false),
            "Tld" => await _client.GetTld(Tld, CancelToken).ConfigureAwait(false),
            "Ip" => await _client.GetIp(Ip, CancelToken).ConfigureAwait(false),
            "As" => await _client.GetAutnum(AsNumber, CancelToken).ConfigureAwait(false),
            "Entity" => await _client.GetEntity(Entity, CancelToken).ConfigureAwait(false),
            "Registrar" => await _client.GetRegistrar(Registrar, CancelToken).ConfigureAwait(false),
            "Nameserver" => await _client.GetNameserver(Nameserver, CancelToken).ConfigureAwait(false),
            _ => null,
        };

        WriteObject(result);
    }
}
}
