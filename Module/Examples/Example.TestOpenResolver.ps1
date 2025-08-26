# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Typed details include RA bit, RCODE, section counts and timing
$Google = Test-OpenResolver -Server '8.8.8.8' -Port 53 -Verbose
$Google | Format-List Host,Port,IsOpenResolver,QueryTimeMs,Rcode,RaBitSet,QdCount,AnCount,NsCount,ArCount

$Cloudflare = Test-OpenResolver -Server '1.1.1.1'
$Cloudflare | Format-List Host,Port,IsOpenResolver,QueryTimeMs,Rcode,RaBitSet,QdCount,AnCount,NsCount,ArCount
