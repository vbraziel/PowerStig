# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
    Instructions:  Use this file to add/update/delete regsitry expressions that are used accross 
    multiple technologies files that are considered commonly used.  Ensure expressions are listed
    from MOST Restrive to LEAST Restrictive, similar to exception handling.  Also, ensure only
    UNIQUE Keys are used in each hashtable to prevent errors and conflicts.
#>

$global:SingleLineRegistryPath += [ordered]@{
    Office1 = [ordered]@{
        Match  = 'outlook\\security'
        Select = '((HKLM|HKCU).*\\security)'
    }
    # Added for Outlook 2013 Stig V-17761.b
    Office2 = [ordered]@{
        Match  = 'value for hkcu.*Message\sPlain\sFormat\sMime'
        Select = '(HKCU).*(?<=me)'
    }
}

$global:SingleLineRegistryValueName += [ordered]@{
    Office1 = @{
        Match  = 'If the REG_DWORD'
        Select = '((?<=for\s")(.*)(?<="))'
    }
    # Added for Outlook 2013 Stig V-17761.b
    Office2 = @{
        Match  = 'Message Plain Format Mime'
        Select = '((?<=il\\)(.*)(?<=e\s))'
    }
    # Added for Outlook 2013 Stig V-17575
    Office3 = @{
        Match  = 'Configure trusted add-ins'
        Select = '(?<=ty\\).*(?=\sIn)'
    }
    # Added for Office 2016 STIGs Excel, PPT, Word
    Office10 = @{
        Select = '(?<=If the value\s)(.*)(?<=PV)'
    }
    # Added for Outlook 2016 Stig V-71193 and Excel 2016 Stig V-71015
    Office4 = @{
        Select = '((?<=If the value\s)(.*)(?=does\snot))'
    }
<#    # Added for Excel 2016 Stig V-71015 - Can I wrap this one into the Office4 RegEx?
    Office5 = @{
      #  Match  = 'ExcelBypassEncrypted'
        Select = '((?<=If the value\s)(.*)(?=does\snot))'
    }#>
    # Added for Outlook 2013 Stig V-17761.a
    Office6 = @{
        Match  = 'a value of between'
        Select = '((?<=gs\\)(.*)(?<=Len))'
    }
    # Added for Outlook 2013 Stig V-17774 and V-17775
    Office7 = @{
        Match  = 'FileExtensionsRemoveLevel'
        Select = '(?<=the registry value\s.)(.*)(?=.\We)'
    }
    # Added for Outlook 2013 Stig V-17733
    Office8 = [ordered]@{
        Match  = 'If the.+(registry key exist)'
        Select = '(?<=ty\\).*(?=\sC)'
    }
    # Added for Outlook 2016 Stig V-71123
    Office9 = @{
        Select = '(?<=If the value of\s)(.*)(?=is\sR)'
    }
}

$global:SingleLineRegistryValueType += [ordered]@{
    Office1 = @{
        Select = '((?<=If the\s)(.*)(?<=DWORD))'
    }
    # Added for Outlook 2013 Stig V-17575
    Office2 = @{
        Select = '(?<=\sto\s).*"'
    }
}

$global:SingleLineRegistryValueData += [ordered]@{
    # Added for Outlook Stig 2016 V-71273
    Office1 = @{
        Match = 'MinEncKey'
        Select= '((?<=or\s)(.*)(?=,))'
    }
    # Added for Outlook 2013 Stig V-17776 and Outlok 2016 Stig V-71133
    Office2 = @{
        Match = 'PublishCalendarDetailsPolicy'
        Select = '((?<=is\s)(.*)(?=\sor))'
    }
    # Added for Outlook 2013 Stig V-17761.a
    Office3 = @{
        Match  = 'a value of between'
        Select = '(?<=between\s)(.*)(?<=\s)'
    }
}
