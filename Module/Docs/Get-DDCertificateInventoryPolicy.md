---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDCertificateInventoryPolicy
## SYNOPSIS
Evaluates certificate inventory snapshots against baseline policy profiles.

## SYNTAX
### __AllParameterSets
```powershell
Get-DDCertificateInventoryPolicy [-CacheDirectory <string>] [-SinceUtc <DateTime>] [-BaselineProfile <string>] [-IncludeCompliant] [-MaxEndpoints <int>] [-PolicyOverridesPath <string>] [-DesiredStatePath <string>] [-DesiredStateDomain <string>] [-MailClassification <MailDomainClassificationCategory>] [<CommonParameters>]
```

## DESCRIPTION
Builds endpoint policy posture with explicit violation codes using Strict, Balanced, or Legacy profiles.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDCertificateInventoryPolicy -SinceUtc (Get-Date).ToUniversalTime().AddDays(-30)
```


### EXAMPLE 2
```powershell
Get-DDCertificateInventoryPolicy -BaselineProfile Strict -IncludeCompliant -MaxEndpoints 500
```


### EXAMPLE 3
```powershell
Get-DDCertificateInventoryPolicy -BaselineProfile Balanced -PolicyOverridesPath .\policy-overrides.json
```


### EXAMPLE 4
```powershell
Get-DDCertificateInventoryPolicy -DesiredStatePath .\desired-state.json -DesiredStateDomain example.com
```


## PARAMETERS

### -BaselineProfile
Policy baseline profile to evaluate (Strict, Balanced, Legacy).

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: Strict, Balanced, Legacy

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CacheDirectory
Certificate monitor cache directory containing the inventory folder.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DesiredStateDomain
Domain/subject used to resolve desired state overrides when -DesiredStatePath is provided.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DesiredStatePath
Optional desired state configuration path used to resolve certificate inventory policy settings.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IncludeCompliant
Include endpoints with no policy violations.

```yaml
Type: SwitchParameter
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MailClassification
Optional mail classification used when resolving desired state overrides.

```yaml
Type: MailDomainClassificationCategory
Parameter Sets: __AllParameterSets
Aliases: None
Possible values: SendingAndReceiving, ReceivingOnly, SendingOnly, Parked, Unknown

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxEndpoints
Maximum endpoint rows returned.

```yaml
Type: Int32
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PolicyOverridesPath
Optional JSON file path with policy override rules.

```yaml
Type: String
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SinceUtc
Only include snapshots captured since this UTC date/time.

```yaml
Type: DateTime
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `DomainDetective.CertificateInventoryPolicySummary`

## RELATED LINKS

- None
