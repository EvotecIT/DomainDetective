using System.Management.Automation;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.PowerShell {

/// <summary>Retrieves RDAP objects from a specified service.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Query domain data.</summary>
///   <code>Get-DDRdapObject -Domain example.com</code>
/// </example>
[Cmdlet(VerbsCommon.Get, "DDRdapObject", DefaultParameterSetName = "Domain")]
[Alias("Get-RdapObject")]
[OutputType(typeof(object))]
public sealed class CmdletGetRdapObject : AsyncPSCmdlet
{
    /// <para>Domain name to query.</para>
    [Parameter(Mandatory = true, ParameterSetName = "Domain", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Domain { get; set; } = string.Empty;

    /// <para>Top-level domain to query.</para>
    [Parameter(Mandatory = true, ParameterSetName = "Tld", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Tld { get; set; } = string.Empty;

    /// <para>IP address or CIDR to query.</para>
    [Parameter(Mandatory = true, ParameterSetName = "Ip", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Ip { get; set; } = string.Empty;

    /// <para>Autonomous system number to query.</para>
    [Parameter(Mandatory = true, ParameterSetName = "As", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string AsNumber { get; set; } = string.Empty;

    /// <para>Entity handle to query.</para>
    [Parameter(Mandatory = true, ParameterSetName = "Entity", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Entity { get; set; } = string.Empty;

    /// <para>Registrar handle to query.</para>
    [Parameter(Mandatory = true, ParameterSetName = "Registrar", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Registrar { get; set; } = string.Empty;

    /// <para>Nameserver host to query.</para>
    [Parameter(Mandatory = true, ParameterSetName = "Nameserver", Position = 0)]
    [ValidateNotNullOrEmpty]
    public string Nameserver { get; set; } = string.Empty;

    /// <summary>RDAP service endpoint.</summary>
    [Parameter]
    public string ServiceEndpoint { get; set; } = "https://rdap.org";

    /// <para>Return a flattened view for domain queries instead of the raw JSON model.</para>
    [Parameter]
    public SwitchParameter Flatten { get; set; }

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
        object? result = null;
        switch (ParameterSetName)
        {
            case "Domain":
                var dom = await _client.QueryDomainAsync(Domain, CancelToken).ConfigureAwait(false);
                if (!Flatten || dom == null)
                {
                    result = dom;
                }
                else
                {
                    // Build a flattened view similar to Get-DDRdap
                    string? registrar = null;
                    string? registrarId = null;
                    if (dom.Entities != null)
                    {
                        foreach (var ent in dom.Entities)
                        {
                            if (ent.Roles != null && ent.Roles.Exists(r => string.Equals(r, "registrar", System.StringComparison.OrdinalIgnoreCase)))
                            {
                                registrarId ??= ent.Handle;
                                if (ent.VcardArray.HasValue && ent.VcardArray.Value.ValueKind == System.Text.Json.JsonValueKind.Array && ent.VcardArray.Value.GetArrayLength() > 1)
                                {
                                    foreach (var card in ent.VcardArray.Value[1].EnumerateArray())
                                    {
                                        if (card.GetArrayLength() > 3 && card[0].GetString() == "fn")
                                        {
                                            registrar = card[3].GetString();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    var nameservers = dom.Nameservers != null
                        ? System.Linq.Enumerable.ToArray(System.Linq.Enumerable.Where(System.Linq.Enumerable.Select(dom.Nameservers, n => n.LdhName), s => !string.IsNullOrEmpty(s))!)
                        : System.Array.Empty<string>();
                    var statuses = dom.Status != null ? System.Linq.Enumerable.ToArray(dom.Status) : System.Array.Empty<DomainDetective.RdapDomainStatus>();
                    var events = dom.Events != null
                        ? System.Linq.Enumerable.ToArray(System.Linq.Enumerable.Select(dom.Events, e => new { Action = e.Action, Date = e.Date }))
                        : System.Array.Empty<object>();

                    var view = new PSObject();
                    view.Properties.Add(new PSNoteProperty("LdhName", dom.LdhName));
                    view.Properties.Add(new PSNoteProperty("UnicodeName", dom.UnicodeName));
                    view.Properties.Add(new PSNoteProperty("Handle", dom.Handle));
                    view.Properties.Add(new PSNoteProperty("Registrar", registrar));
                    view.Properties.Add(new PSNoteProperty("RegistrarId", registrarId));
                    view.Properties.Add(new PSNoteProperty("Status", statuses));
                    view.Properties.Add(new PSNoteProperty("Events", events));
                    view.Properties.Add(new PSNoteProperty("Nameservers", nameservers));
                    result = view;
                }
                break;

            case "Tld":
                result = await _client.QueryTldAsync(Tld, CancelToken).ConfigureAwait(false);
                break;
            case "Ip":
                result = await _client.QueryIpAsync(Ip, CancelToken).ConfigureAwait(false);
                break;
            case "As":
                result = await _client.QueryAutnumAsync(AsNumber, CancelToken).ConfigureAwait(false);
                break;
            case "Entity":
                result = await _client.QueryEntityAsync(Entity, CancelToken).ConfigureAwait(false);
                break;
            case "Registrar":
                result = await _client.QueryRegistrarAsync(Registrar, CancelToken).ConfigureAwait(false);
                break;
            case "Nameserver":
                result = await _client.QueryNameserverAsync(Nameserver, CancelToken).ConfigureAwait(false);
                break;
        }

        WriteObject(result);
    }
}
}
