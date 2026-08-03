---
external help file: DomainDetective-help.xml
Module Name: DomainDetective
online version: https://github.com/EvotecIT/DomainDetective
schema: 2.0.0
---
# Get-DDRdapObject
## SYNOPSIS
Retrieves RDAP objects from a specified service.

## SYNTAX
### Domain (Default)
```powershell
Get-DDRdapObject [-Domain] <string> [-ServiceEndpoint <string>] [-Flatten] [<CommonParameters>]
```

### Tld
```powershell
Get-DDRdapObject [-Tld] <string> [-ServiceEndpoint <string>] [-Flatten] [<CommonParameters>]
```

### Ip
```powershell
Get-DDRdapObject [-Ip] <string> [-ServiceEndpoint <string>] [-Flatten] [<CommonParameters>]
```

### As
```powershell
Get-DDRdapObject [-AsNumber] <string> [-ServiceEndpoint <string>] [-Flatten] [<CommonParameters>]
```

### Entity
```powershell
Get-DDRdapObject [-Entity] <string> [-ServiceEndpoint <string>] [-Flatten] [<CommonParameters>]
```

### Registrar
```powershell
Get-DDRdapObject [-Registrar] <string> [-ServiceEndpoint <string>] [-Flatten] [<CommonParameters>]
```

### Nameserver
```powershell
Get-DDRdapObject [-Nameserver] <string> [-ServiceEndpoint <string>] [-Flatten] [<CommonParameters>]
```

## DESCRIPTION
Part of the DomainDetective project.

## EXAMPLES

### EXAMPLE 1
```powershell
Get-DDRdapObject -Domain example.com
```


## PARAMETERS

### -AsNumber
Autonomous system number to query.

```yaml
Type: String
Parameter Sets: As
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Domain
Domain name to query.

```yaml
Type: String
Parameter Sets: Domain
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Entity
Entity handle to query.

```yaml
Type: String
Parameter Sets: Entity
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Flatten
Return a flattened view for domain queries instead of the raw JSON model.

```yaml
Type: SwitchParameter
Parameter Sets: Domain, Tld, Ip, As, Entity, Registrar, Nameserver
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Ip
IP address or CIDR to query.

```yaml
Type: String
Parameter Sets: Ip
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Nameserver
Nameserver host to query.

```yaml
Type: String
Parameter Sets: Nameserver
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Registrar
Registrar handle to query.

```yaml
Type: String
Parameter Sets: Registrar
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServiceEndpoint
RDAP service endpoint.

```yaml
Type: String
Parameter Sets: Domain, Tld, Ip, As, Entity, Registrar, Nameserver
Aliases: None
Possible values:

Required: False
Position: named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Tld
Top-level domain to query.

```yaml
Type: String
Parameter Sets: Tld
Aliases: None
Possible values:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

- `None`

## OUTPUTS

- `System.Object`

## RELATED LINKS

- None
