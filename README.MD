[![codecov](https://codecov.io/gh/your-user/DomainDetective/branch/master/graph/badge.svg)](https://codecov.io/gh/your-user/DomainDetective)
Domain Detective is a C# library, Tool and PowerShell module in one project. It is designed to help you find interesting information about a domain name.
While there are plenty of tools on the internet that can do this, most of them are web based and require you to enter the domain name into a web form.
This is not ideal if you want to automate the process or if you are working with sensitive information.

Current capabilities include:
- [x] Verify SPF
- [x] Verify DMARC
- [x] Verify DKIM
- [x] Verify CAA
- [ ] Verify NS Records
- [ ] Verify SOA Records
- [ ] Verify MX Records
- [ ] Verify DNSSEC
- [x] Verify DANE/TLSA
- [ ] Verify STARTTLS
- [ ] Verify MTA-STS
- [ ] Verify SMTP TLS
- [ ] Verify Website Connectivity
  - [ ] Verify HTTP/2
  - [ ] Verify HTTP/3
  - [ ] Verify Certificate
  - [ ] Verify Response Time
  - [ ] Verify Headers
  - [ ] Verify HSTS
  - [ ] Verify HPKP
- [ ] Verify SecurityTXT
- [ ] Verify Open Relay (SMTP)
- [ ] Verify Blacklist (DNSBL)
- [ ] Check propagation of DNS records across the world/country/company
- [ ] Other things that I haven't thought of yet

### DNSBL Configuration
DNSBL lists used for blacklist checks can be customized. `DNSBLAnalysis` comes with a built-in list, but you can modify it at runtime. Each list entry exposes `Domain`, `Enabled`, and `Comment` fields. Use the following methods on `DNSBLAnalysis` to manage the list:

- `AddDNSBL`/`AddDNSBL(IEnumerable<string>)`
- `RemoveDNSBL`
- `ClearDNSBL`
- `LoadDNSBL`

You can load a custom list from a file using `LoadDNSBL`.

## Alternatives
If you don't need to automate the process, or if you just want to quickly query for your domain name, you can use the following web based tools:

- [MXToolbox](https://mxtoolbox.com/)
- [DNSChecker](https://dnschecker.org/)
- [DNSStuff](https://www.dnsstuff.com/)
- [Dmarcian](https://dmarcian.com/)
- [DMARC Analyzer](https://www.dmarcanalyzer.com/)
- [DKIM Validator](https://dkimvalidator.com/)
- [DKIM Core](https://www.dkimcore.org/tools/)

## Continuous Integration

This project uses GitHub Actions to run .NET and PowerShell tests on Windows, Linux and macOS.
Code coverage results are published to [Codecov](https://codecov.io/gh/your-user/DomainDetective).
