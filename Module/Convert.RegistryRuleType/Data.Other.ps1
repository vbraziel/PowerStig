$SingleLineRegistryPath += 
     [ordered]@{
        Other = [ordered]@{ 
                        Match    = 'the value for hkcu.*Message\sPlain\sFormat\sMime';
                        Select   = '((HKLM|HKCU).*(?=\sis))' 
                  }
    }
