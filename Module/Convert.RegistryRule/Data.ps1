# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# These are the registry types that are accepted by the registry DSC resource
data dscRegistryValueType
{
    ConvertFrom-StringData -stringdata @'
        REG_SZ         = String
        REG_BINARY     = Binary
        REG_DWORD      = Dword
        REG_QWORD      = Qword
        REG_MULTI_SZ   = MultiString
        REG_EXPAND_SZ  = ExpandableString
        Does Not Exist = Does Not Exist
        DWORD          = Dword
        Disabled       = Dword
        Enabled        = Dword
'@
}

data registryRegularExpression
{
    ConvertFrom-StringData -stringdata @'
        # the registry hive is not provided in a consistant format, so the search pattern needs
        # to account for optional character ranges

        registryRoot = ((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER).*)

        testItem = @{
            Red = Apple
            Yellow = Banana
        }
        
        registryHive = (Registry)?\\s?Hive\\s?:\\s*?(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)

        #registryPath      = ((Registry)?\\s*(Path|SubKey)\\s*:\\s*|^\\\\SOFTWARE)(\\\\)?\\w+(\\\\)\\w+(\\\\)?

        registryPath      = ((Registry)?\\s*(Path|SubKey)\\s*:\\s*|^\\\\SOFTWARE)(\\\\)?\\w+(\\\\)(\\w+(\\\\)?|\\sP)

        registryEntryType = Type\\s?:\\s*?REG_(SZ|BINARY|DWORD|QWORD|MULTI_SZ|EXPAND_SZ)(\\s{1,}|$)

        registryValueName = ^\\s*?Value\\s*?Name\\s*?:

        registryValueData = ^\\s*?Value\\s*?:
        # extracts multi string values
        MultiStringNamedPipe = (?m)(^)(System|Software)(.+)$

        # or is in a word boundary since it is a common pattern
        registryValueRange = (?<![\\w\\d])but|\\bor\\b|and|Possible values(?![\\w\\d])

        # this is need validate that a value is still a string even if it contains a number
        hardenUncPathValues = (RequireMutualAuthentication|RequireIntegrity)
'@
}

data testExpression
{
    ConvertFrom-StringData -stringdata @'
    Red = Apple
    Yellow = Banana
'@
}

$SingleLineRegistryPath = 
     [ordered]@{
        Root     = [ordered]@{ 
                        Match    = '(HKCU|HKLM|HKEY_LOCAL_MACHINE)\\'; 
                        Select   = '((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER).*)' 
                    };

        Criteria = [ordered]@{ 
                        Contains = 'Criteria:'; 
                        After    = [ordered]@{ 
                                        Match  = '((HKLM|HKCU).*(?=Criteria:))';
                                        Select = '((HKLM|HKCU).*(?=Criteria:))'; 
                                        
                                    };
                        Before   = [ordered]@{
                                        Match = 'Criteria:.*(HKLM|HKCU)'
                                        Select = '((HKLM|HKCU).*(?=\sis))'
                                    } 
                    };

        Verify = [ordered]@{ 
                        Contains = 'Verify'; 
                        Select   = $Values.Testing
                  };
    }

$SingleLineRegistryValueName = 
     [ordered]@{
     One = @{ Select = '(?<=If the value(\s*)?((for( )?)?)").*(")?((?=is.*R)|(?=does not exist))' };
     Two = [ordered]@{ Match = 'If the.+(registry key does not exist)'; Select = '"[\s\S]*?"' };
     Three = @{ Select = '(?<=If the value of\s")(.*)(?="\s.*R)|(?=does not exist)' };
     Four = @{ Select = '((?<=If the value\s)(.*)(?=is\sR))' };
     Five = [ordered]@{ Match = 'the policy value'; Select = '(?<=")(.*)(?="\sis)' };
     Six = @{ Select = '((?<=for\s).*)' };
     Seven = @{ Select = '(?<=filevalidation\\).*(?=\sis\sset\sto)' }
     }

$SingleLineRegistryValueType = 
     [ordered]@{
     One = @{ Select = '(?<=$([regex]::escape($valueName))(\"")? is not ).*=' }; #$([regex]::escape($myString))
     Two = @{ Select = '(?<=$([regex]::escape($valueName))(\"")?\s+is ).*=' };
     Three = @{ Select = '(?<=Verify\sa).*(?=value\sof)'};
     #Four = @{ Select = 'registry key exists and the([\s\S]*?)value'; Group = 1 };
     Five = @{ Select = '(?<=$([regex]::escape($valueName))`" is set to ).*`"'};
     #Six = @{ Select = '((hkcu|hklm).*\sis\s(.*)=)'; Group = 3 };
     #Seven = @{ Select = 'does not exist, this is not a finding'; Return = 'Does Not Exist'}
     }

$SingleLineRegistryValueData = 
     [ordered]@{
     One = @{ Select = '(?<=$($valueType)(\s*)?=).*(?=(,|\())' };
     Two = @{ Select = '((?<=value\sof).*(?=for))' };
     Three = @{ Select = '((?<=set\sto).*(?=\(true\)))' };
     Four = @{ Select = "((?<=is\sset\sto\s)(`'|`")).*(?=(`'|`"))" };
     Five = @{ Select = "(?<=$($valueType)\s=).*"}
     }
