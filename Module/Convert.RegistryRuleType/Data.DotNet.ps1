$SingleLineRegistryPath += 
     [ordered]@{
        DotNet = [ordered]@{
                        Contains = 'NETFramework'; 
                        Select   = '((HKLM|HKCU|HKEY_LOCAL_MACHINE).*(?=key))' 
                  };
    }
