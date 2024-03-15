






Domain Detective is a C# library, Tool and PowerShell module in one. It is designed to help you find interesting information about a domain name.
While there are plenty of tools on the internet that can do this, most of them are web based and require you to enter the domain name into a web form. This is not ideal if you want to automate the process or if you are working with sensitive information.

Domain Detective is designed to be used in a PowerShell script, but it can also be used as a standalone tool or as a library in your own C# project.

Current capatbilities include:
- [x] Verify SPF
- [x] Verify DMARC
- [x] Verify DKIM
- [x] Verify CAA
- [ ] Verify NS Records
- [ ] Verify SOA Records
- [ ] Verify MX Records
- [ ] Verify DNSSEC
- [ ] Verify TLSA
- [ ] Verify DANE
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

## Alternatives
If you don't need to automate the process, or if you just want to quickly query for your domain name, you can use the following web based tools:

- [MXToolbox](https://mxtoolbox.com/)
- [DNSChecker](https://dnschecker.org/)
- [DNSStuff](https://www.dnsstuff.com/)
- [Dmarcian](https://dmarcian.com/)
- [DMARC Analyzer](https://www.dmarcanalyzer.com/)
- [DKIM Validator](https://dkimvalidator.com/)
- [DKIM Core](https://www.dkimcore.org/tools/)
