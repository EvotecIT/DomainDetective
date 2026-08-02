---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Start-DDUptimeMonitor
## SYNOPSIS
Starts background HTTP(S) uptime monitoring for one or more URLs.

## SYNTAX
### __AllParameterSets
```powershell
Start-DDUptimeMonitor [-Url] <string[]> [-IntervalSeconds <int>] [-SnapshotDirectory <string>] [-WebhookUrl <string>] [-SlowTtfbMs <int>] [-OnDown <scriptblock>] [-OnSlow <scriptblock>] [-OnUp <scriptblock>] [-OnAny <scriptblock>] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Start-DDUptimeMonitor -Url 'https://evotec.pl','https://evotec.xyz' -IntervalSeconds 60 -WebhookUrl 'https://example.com/webhook' -SnapshotDirectory .\Uptime
```


## PARAMETERS

### -IntervalSeconds
Polling interval in seconds (default 60).

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

### -OnAny
Script to execute for any result (Severity: Down|Slow|Up) with probe PSCustomObject.

```yaml
Type: ScriptBlock
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OnDown
Script to execute when a URL is detected DOWN (receives one argument: probe PSCustomObject).

```yaml
Type: ScriptBlock
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OnSlow
Script to execute when a URL is SLOW (receives one argument: probe PSCustomObject).

```yaml
Type: ScriptBlock
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OnUp
Script to execute when a URL is UP within thresholds (receives one argument: probe PSCustomObject).

```yaml
Type: ScriptBlock
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SlowTtfbMs
Slow TTFB threshold in milliseconds (default 2000ms).

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

### -SnapshotDirectory
Optional directory to write JSON snapshots per probe.

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

### -Url
One or more absolute HTTP(S) URLs to probe.

```yaml
Type: String[]
Parameter Sets: __AllParameterSets
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WebhookUrl
Optional webhook URL for alerts (DOWN/SLOW).

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `None`

## RELATED LINKS

- None
