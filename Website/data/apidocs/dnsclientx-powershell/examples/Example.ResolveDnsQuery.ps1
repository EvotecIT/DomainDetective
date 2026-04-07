Clear-Host

Import-Module $PSScriptRoot\..\DnsClientX.psd1 -Force -Verbose

$Domains = 'sip2sip.info' #, 'sip5060.net'

foreach ($Domain in $Domains) {
    Resolve-Dns -Type NAPTR -Name $Domain -DnsProvider Cloudflare | Format-Table
    Resolve-Dns -Type NAPTR -Name $Domain -DnsProvider Google | Format-Table
    Resolve-Dns -Type NAPTR -Name $Domain -DnsProvider GoogleWireFormat | Format-Table
    Resolve-Dns -Type NAPTR -Name $Domain -DnsProvider OpenDNS | Format-Table
    Resolve-Dns -Type NAPTR -Name $Domain -DnsProvider CloudflareWireFormat | Format-Table
    Resolve-Dns -Type NAPTR -Name $Domain -DnsProvider CloudflareWireFormatPost | Format-Table
}

Resolve-Dns -Name 'www.bücher.de' -Type A | Format-Table
Resolve-Dns -Name 'evotec.pl' -Type A | Format-Table
Resolve-Dns -Name 'evotec.pl' -Type A -DnsProvider Cloudflare -Verbose | Format-Table
Resolve-Dns -Name 'evotec.pl' -Type TXT -DnsProvider System -Verbose | Format-Table
Resolve-Dns -Name 'github.com', 'evotec.pl', 'google.com' -Type TXT -DnsProvider System -Verbose -TimeOut 5000 | Format-Table

# Request and validate DNSSEC over explicit resolver endpoints
Resolve-Dns -Name 'example.com' -Type A -ResolverEndpoint 'https://dns.google/dns-query' -RequestDnsSec -ValidateDnsSec -FullResponse | Format-List

# Send EDNS Client Subnet and request NSID metadata
Resolve-Dns -Name 'example.com' -Type A -DnsProvider Quad9ECS -EnableEdns -ClientSubnet '192.0.2.0/24' -RequestNsid -FullResponse | Format-List

# Use an explicit transport on the -Server path
Resolve-Dns -Name 'example.com' -Type A -Server 'dns.google' -RequestFormat DnsOverHttps -Port 443 -UserAgent 'DnsClientX/PowerShell Example' | Format-Table
