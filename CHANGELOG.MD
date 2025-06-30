## 1.0.0

### What's Changed
- Initial release of Domain Detective
- Includes CLI and PowerShell module
- Supports checks for SPF, DMARC, DKIM, CAA, NS, SOA, DNSSEC and DANE/TLSA records

## 1.0.1

### What's Changed
- Enabled trimming on CLI and example projects with partial mode to align with .NET 8 NativeAOT guidance

## 1.0.2

### What's Changed
- Added TTL analysis for common DNS record types
- New `Test-DnsTtl` PowerShell cmdlet

## 1.0.3

### What's Changed
- warn when CAA records use unknown critical tags
