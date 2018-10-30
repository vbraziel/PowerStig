# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Main Functions
<#
    .SYNOPSIS
        Looks in the Check-Content element to see if it matches registry string.

    .PARAMETER CheckStrings
        Check-Content element
#>
function Test-SingleLineRegistryRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($CheckContent -match "(HKCU|HKLM|HKEY_LOCAL_MACHINE)\\")
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $true"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $false"
    }
}
#endregion
#region Registry Path
<#
    .SYNOPSIS
        Extract the registry path from an office STIG string.

    .Parameter CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-SingLineRegistryPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable

    )
    
    $fullRegistryPath = $CheckContent
    
    foreach($i in $Hashtable.Value.GetEnumerator()) 
    {  

    if ($i.Value.GetType().Name -eq 'OrderedDictionary') 
    {
        Get-SingleLineRegistryPath -CheckContent $CheckContent -Hashtable $i
    } 
    else
    {
        switch ($i.Key)
        {
            Contains
            { 
                if ($CheckContent.Contains($i.Value)) 
                {
                    continue
                }
                else 
                { 
                    return 
                }
            }

            Match 
            { 
                if($CheckContent -match $i.Value )
                {
                  continue
                }
                else
                {
                    return
                }
            }
            
            Select 
            { 
                
                $regEx =  '{0}' -f $i.Value
                $result = [regex]::Matches($CheckContent.ToString(), $regEx)
                $fullRegistryPath = $result.Value
            }
        }
    }

   } 
    if ( -not [String]::IsNullOrEmpty( $fullRegistryPath ) )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found path : $true"

        switch -Wildcard ($fullRegistryPath)
        {
            "*HKLM*" {$fullRegistryPath = $fullRegistryPath -replace "^HKLM", "HKEY_LOCAL_MACHINE"}

            "*HKCU*" {$fullRegistryPath = $fullRegistryPath -replace "^HKCU", "HKEY_CURRENT_USER"}

            "*Software Publishing Criteria" {$fullRegistryPath = $fullRegistryPath -replace 'Software Publishing Criteria$','Software Publishing'}
        }

        $fullRegistryPath = $fullRegistryPath.ToString().trim(' ', '.')

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed path : $fullRegistryPath"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found path : $false"
        throw "Registry path was not found in check content."
    }

    #$Script:fullRegistryPath += $fullRegistryPath
    return $fullRegistryPath
    #return $Script:rawString += $CheckContent
    #return $Script:fullRegistryPath
    #return $result.Value
}
<#
    .SYNOPSIS
        Extract the registry path from an office STIG string.

    .Parameter CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-FinalRegistryPath
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $fullRegistryPath
    )

    if ( -not [String]::IsNullOrEmpty( $fullRegistryPath ) )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found path : $true"

        switch -Wildcard ($fullRegistryPath)
        {
            "*HKLM*" {$fullRegistryPath = $fullRegistryPath -replace "^HKLM", "HKEY_LOCAL_MACHINE"}

            "*HKCU*" {$fullRegistryPath = $fullRegistryPath -replace "^HKCU", "HKEY_CURRENT_USER"}

            "*Software Publishing Criteria" {$fullRegistryPath = $fullRegistryPath -replace 'Software Publishing Criteria$','Software Publishing'}
        }

        $fullRegistryPath = $fullRegistryPath.ToString().trim(' ', '.')

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed path : $fullRegistryPath"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found path : $false"
        throw "Registry path was not found in check content."
    }

    return $fullRegistryPath

}
#endregion
#region Registry Name
<#
    .SYNOPSIS
        Extract the registry value type from a string.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueNameFromSingleLineStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )

    $valueName = $CheckContent
    
    foreach($i in $Hashtable.Value.GetEnumerator()) 
    {  

        switch ($i.Key)
        {
            Contains
            { 
                if ($CheckContent.Contains($i.Value)) 
                {
                    continue
                }
                else 
                { 
                    return 
                }
            }

            Match 
            { 
                if($CheckContent -match $i.Value )
                {
                  continue
                }
                else
                {
                    return
                }
            }
            
            Select 
            { 
                
                $regEx =  '{0}' -f $i.Value
                $result = [regex]::Matches($CheckContent.ToString(), $regEx)
                $valueName = $result.Value
            }
    } #Switch
}#Foreach

     if($valueName)
     {
        $valueName = $valueName.Replace('"', '')

        if ($valueName.Count -gt 1)
        {
            $valueName = $valueName[0]
        }

        if ( -not [String]::IsNullOrEmpty( $valueName ) )
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Name : $valueName"

            $return = $valueName.trim()

            Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed Name : $valueName"
        }
        else
        {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Name : $false"
            return
        }
            $return
        }
    else
    {
        return $valueName
    }
}
#endregion

#region Registry Type
<#
    .SYNOPSIS
        Extract the registry value type from an Office STIG string.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueTypeFromSingleLineStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )

    try
    {
        #$valueName = Get-RegistryValueNameFromSingleLineStig -CheckContent $CheckContent -Hashtable $Script:SingleLineRegistryValueName
        $valueName = Get-RegistryValueNameFromSingleLineStig -CheckContent $Script:rawString 
    }
    catch
    {
        return
    }

    $valueName = [Regex]::Escape($valueName)

    $valueType = $CheckContent

    foreach($i in $Hashtable.Value.GetEnumerator()) 
    {  

        switch ($i.Key)
        {
            Contains
            { 
                if ($CheckContent.Contains($i.Value)) 
                {
                    continue
                }
                else 
                { 
                    return 
                }
            }

            Match 
            { 
                if($CheckContent -match $i.Value )
                {
                  continue
                }
                else
                {
                    return
                }
            }
            
            Select 
            { 
                $regEx =  '{0}' -f $i.Value
                $result = [regex]::Matches($CheckContent.ToString(), $regEx)
                $valueType = $result.Value
            }
    } #Switch
}#Foreach
     if($valueType)
     {
    if ($valueType -is [Microsoft.PowerShell.Commands.MatchInfo])
    {
        $valueType = $valueType.Matches.Value.Replace('=', '').Replace('"', '')
    }

    if ( -not [String]::IsNullOrWhiteSpace( $valueType.Trim() ) )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]    Found Type : $valueTypetype"

        $valueType = Test-RegistryValueType -TestValueType $valueType
        $return = $valueType.trim()
        #$return = $valueType[0].ValueType.Trim()

        Write-Verbose "[$($MyInvocation.MyCommand.Name)]  Trimmed Type : $valueType"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Type : $false"
        # If we get here, there is nothing to verify so return.
        return
    }

    $return
        }
    else
    {
        return $valueType
    }
}
#endregion

#region Registry Data
<#
    .SYNOPSIS
        Looks for multiple patterns in the value string to extract out the value to return or determine
        if additional processing is required. For example if an allowable range detected, additional
        functions need to be called to convert the text into powershell operators.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueDataFromSingleStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent,

        [Parameter(Mandatory = $true)]
        [psobject]
        $Hashtable
    )

    try
    {
        #$valueType = Get-RegistryValueTypeFromSingleLineStig -CheckContent $CheckContent
        $valueType = $Script:SingleLineRegistryValueType.GetEnumerator() | ForEach-Object { Get-RegistryValueTypeFromSingleLineStig -CheckContent $Script:rawString -Hashtable $_ }

    }
    catch
    {
        return
    }

    $valueData = $CheckContent

    foreach($i in $Hashtable.Value.GetEnumerator()) 
    {  

        switch ($i.Key)
        {
            Contains
            { 
                if ($CheckContent.Contains($i.Value)) 
                {
                    continue
                }
                else 
                { 
                    return 
                }
            }

            Match 
            { 
                if($CheckContent -match $i.Value )
                {
                  continue
                }
                else
                {
                    return
                }
            }
            
            Select 
            { 
                $regEx =  '{0}' -f $i.Value
                $result = [regex]::Matches($CheckContent.ToString(), $regEx)
                $valueData = $result.Value
            }
    } #Switch
}#Foreach

    if($valueData)
    {
    $valueData = $valueData.Replace(',', '').Replace('"', '')

    if ( -not [String]::IsNullOrEmpty( $valueData ) )
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Name : $valueData"

        $return = $valueData.trim(" ", "'")

        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Trimmed Name : $return"
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)]   Found Name : $false"
        return
    }

    $return
    }
    else
    {
        return $valueData
    }
}

<#
    .SYNOPSIS
        Checks the registry string format to determine if it is in the Office STIG format.

    .Parameter CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Test-SingleLineStigFormat
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    if ($CheckContent -match "HKLM|HKCU|HKEY_LOCAL_MACHINE\\")
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $true"
        $true
    }
    else
    {
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] $false"
        $false
    }
}
#endregion
