# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Raw RDAP domain object
$domainRaw = Get-RdapObject -Domain 'example.com'
$domainRaw | Format-List

# Flattened RDAP domain view (registrar, nameservers, status, events)
$domainFlat = Get-RdapObject -Domain 'example.com' -Flatten
$domainFlat | Format-List

# RDAP IP network (cidr derived from cidr0_cidrs when needed)
$ip = Get-RdapObject -Ip '185.242.254.62'
$ip | Select-Object StartAddress, EndAddress, Cidr | Format-Table -AutoSize
