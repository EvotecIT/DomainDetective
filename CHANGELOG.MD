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
- DNSSEC validation now walks the delegation chain and checks DS records
- DNSSEC analysis summarizes any mismatches for each chain element

## 1.0.4

### What's Changed
- SOA analysis now validates serial number format and suggests using `YYYYMMDDnn`
  when an invalid pattern is detected

## 1.0.5

### What's Changed
- Evaluate Strict-Transport-Security header for preload readiness
- Added property to report if the `preload` token is present
- Added tests for headers from hstspreload.org

