# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS Get-DbExistGetScript
        Returns the query that checks to see if a DB exists.

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-DbExistGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = Get-Query -CheckContent $checkContent

    return $return
}

<#
    .SYNOPSIS Get-DbExistTestScript
        Returns the query that checks to see if a DB exists.

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-DbExistTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = Get-Query -CheckContent $checkContent

    return $return
}

<#
    .SYNOPSIS Get-DbExistSetScript
        Returns a SQL Statement that removes a DB

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the event Ids that will be returned
#>
function Get-DbExistSetScript {
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = $FixText[1].Trim()

    if ($return -notmatch ";$")
    {
        $return = $return + ";"
    }

    return $return
}


<#
    .SYNOPSIS Get-TraceGetScript
        Returns a query that gets Trace ID's

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-TraceGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $eventId = Get-EventIdData -CheckContent $checkContent

    $return = Get-TraceIdQuery -EventId $eventID

    return $return
}

<#
    .SYNOPSIS Get-TraceTestScript
        Returns a query and sub query that gets Trace ID's and Event ID's that should be tracked

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-TraceTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $eventId = Get-EventIdData -CheckContent $checkContent

    $return = Get-TraceIdQuery -EventId $eventId

    return $return
}

<#
    .SYNOPSIS Get-TraceSetScript
        Returns a SQL Statement that removes a DB

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-TraceSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $eventId = Get-EventIdData -CheckContent $checkContent

    return "BEGIN IF OBJECT_ID('TempDB.dbo.#StigEvent') IS NOT NULL BEGIN DROP TABLE #StigEvent END IF OBJECT_ID('TempDB.dbo.#Trace') IS NOT NULL BEGIN DROP TABLE #Trace END IF OBJECT_ID('TempDB.dbo.#TraceEvent') IS NOT NULL BEGIN DROP TABLE #TraceEvent END CREATE TABLE #StigEvent (EventId INT) INSERT INTO #StigEvent (EventId) VALUES $($eventId) CREATE TABLE #Trace (TraceId INT) INSERT INTO #Trace (TraceId) SELECT DISTINCT TraceId FROM sys.fn_trace_getinfo(0)ORDER BY TraceId DESC CREATE TABLE #TraceEvent (TraceId INT, EventId INT) DECLARE cursorTrace CURSOR FOR SELECT TraceId FROM #Trace OPEN cursorTrace DECLARE @currentTraceId INT FETCH NEXT FROM cursorTrace INTO @currentTraceId WHILE @@FETCH_STATUS = 0 BEGIN INSERT INTO #TraceEvent (TraceId, EventId) SELECT DISTINCT @currentTraceId, EventId FROM sys.fn_trace_geteventinfo(@currentTraceId) FETCH NEXT FROM cursorTrace INTO @currentTraceId END CLOSE cursorTrace DEALLOCATE cursorTrace DECLARE @missingStigEventCount INT SET @missingStigEventCount = (SELECT COUNT(*) FROM #StigEvent SE LEFT JOIN #TraceEvent TE ON SE.EventId = TE.EventId WHERE TE.EventId IS NULL) IF @missingStigEventCount > 0 BEGIN DECLARE @returnCode INT DECLARE @newTraceId INT DECLARE @maxFileSize BIGINT = 5 EXEC @returnCode = sp_trace_create @traceid = @newTraceId OUTPUT, @options = 2, @tracefile = N'C:\Program Files\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\Log\PowerStig', @maxfilesize = @maxFileSize, @stoptime = NULL, @filecount = 2; IF @returnCode = 0 BEGIN EXEC sp_trace_setstatus @traceid = @newTraceId, @status = 0 DECLARE cursorMissingStigEvent CURSOR FOR SELECT DISTINCT SE.EventId FROM #StigEvent SE LEFT JOIN #TraceEvent TE ON SE.EventId = TE.EventId WHERE TE.EventId IS NULL OPEN cursorMissingStigEvent DECLARE @currentStigEventId INT FETCH NEXT FROM cursorMissingStigEvent INTO @currentStigEventId WHILE @@FETCH_STATUS = 0 BEGIN EXEC sp_trace_setevent @traceid = @newTraceId, @eventid = @currentStigEventId, @columnid = NULL, @on = 1 FETCH NEXT FROM cursorMissingStigEvent INTO @currentStigEventId END CLOSE cursorMissingStigEvent DEALLOCATE cursorMissingStigEvent EXEC sp_trace_setstatus @traceid = @newTraceId, @status = 1 END END END"
}

<#
    .SYNOPSIS Get-PermissionGetScript
        Returns a query that will get a list of users who have access to a certain SQL Permission

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-PermissionGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $queries = Get-Query -CheckContent $checkContent

    $return = $queries[0]

    if ($return -notmatch ";$")
    {
        $return = $return + ";"
    }

    return $return
}

<#
    .SYNOPSIS Get-PermissionTestScript
        Returns a query that will get a list of users who have access to a certain SQL Permission

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-PermissionTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $queries = Get-Query -CheckContent $checkContent

    $return = $queries[0]

    if ($return -notmatch ";$")
    {
        $return = $return + ";"
    }

    return $return
}

<#
    .SYNOPSIS Get-PermissionSetScript
        Returns an SQL Statemnt that will remove a user with unauthorized access

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-PermissionSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $permission = ((Get-Query -CheckContent $checkContent)[0] -split "'")[1] #Get the permission that will be set

    $return = "DECLARE @name as varchar(512) DECLARE @permission as varchar(512) DECLARE @sqlstring1 as varchar(max) SET @sqlstring1 = 'use master;' SET @permission = '{0}' DECLARE  c1 cursor  for  SELECT who.name AS [Principal Name], what.permission_name AS [Permission Name] FROM sys.server_permissions what INNER JOIN sys.server_principals who ON who.principal_id = what.grantee_principal_id WHERE who.name NOT LIKE '##MS%##' AND who.type_desc <> 'SERVER_ROLE' AND who.name <> 'sa'  AND what.permission_name = @permission OPEN c1 FETCH next FROM c1 INTO @name,@permission WHILE (@@FETCH_STATUS = 0) BEGIN SET @sqlstring1 = @sqlstring1 + 'REVOKE ' + @permission + ' FROM [' + @name + '];' FETCH next FROM c1 INTO @name,@permission END CLOSE c1 DEALLOCATE c1 EXEC ( @sqlstring1 );" -f $permission

    return $return
}

<#
    .SYNOPSIS Get-AuditGetScript
        Returns a query that will get a list of audit events

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-AuditGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $queries = Get-Query -CheckContent $checkContent

    $return = $queries[0]

    if ($return -notmatch ";$")
    {
        $return = $return + ";"
    }

    return $return
}


<#
    .SYNOPSIS Get-AuditTestScript
        Returns a query that will get a list of audit events

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-AuditTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $queries = Get-Query -CheckContent $checkContent

    $return = $queries[0]

    if ($return -notmatch ";$")
    {
        $return = $return + ";"
    }

    return $return
}

<#
    .SYNOPSIS Get-AuditSetScript
        Returns an SQL Statemnt that will create an audit

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-AuditSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    #$permission = ((Get-Query -CheckContent $checkContent)[0] -split "'")[1] #Get the permission that will be set

    #$return = "DECLARE @name as varchar(512) DECLARE @permission as varchar(512) DECLARE @sqlstring1 as varchar(max) SET @sqlstring1 = 'use master;' SET @permission = '{0}' DECLARE  c1 cursor  for  SELECT who.name AS [Principal Name], what.permission_name AS [Permission Name] FROM sys.server_permissions what INNER JOIN sys.server_principals who ON who.principal_id = what.grantee_principal_id WHERE who.name NOT LIKE '##MS%##' AND who.type_desc <> 'SERVER_ROLE' AND who.name <> 'sa'  AND what.permission_name = @permission OPEN c1 FETCH next FROM c1 INTO @name,@permission WHILE (@@FETCH_STATUS = 0) BEGIN SET @sqlstring1 = @sqlstring1 + 'REVOKE ' + @permission + ' FROM [' + @name + '];' FETCH next FROM c1 INTO @name,@permission END CLOSE c1 DEALLOCATE c1 EXEC ( @sqlstring1 );" -f $permission

    $return = "CREATE AUDIT"
    
    return $return
}

<#
    .SYNOPSIS Get-PlainSQLGetScript
        Returns a plain SQL query from $checkContent

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the GetScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-PlainSQLGetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = Get-SQLQuery -CheckContent $checkContent

    return $return
}


<#
    .SYNOPSIS Get-PlainSQLTestScript
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the TestScript block

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-PlainSQLTestScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = Get-SQLQuery -CheckContent $checkContent

    return $return
}

<#
    .SYNOPSIS Get-PlainSQLSetScript
        Returns a plain SQL query

    .DESCRIPTION
        The SqlScriptResource uses a script resource format with GetScript, TestScript and SetScript.
        The SQL STIG contains queries that will be placed in each of those blocks.
        This functions returns the query that will be used in the SetScript block

    .PARAMETER FixText
        String that was obtained from the 'Fix' element of the base STIG Rule

    .PARAMETER CheckContent
        Arbitrary in this function but is needed in Get-TraceSetScript
#>
function Get-PlainSQLSetScript
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $FixText,

        [Parameter()]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $return = Get-SQLQuery -CheckContent $FixText

    return $return
}


<#
    .SYNOPSIS Get-Query
        Returns all Queries found withing the 'CheckContent'

    .DESCRIPTION
        This function parses the 'CheckContent' to find all queies and extract them
        Not all queries may be used by later functions and will be separated then.
        Some functions require variations of the queries returned thus the reason for
        returning all queries found

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the query that will be returned
#>
function Get-Query
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $collection = @()
    $queries = @()

    if ($checkContent.Count -gt 1)
    {
        $checkContent = $checkContent -join ' '
    }

    $lines = $checkContent -split "(?=USE|SELECT)"

    foreach ($line in $lines)
    {
        if ($line -match "^(Select|SELECT)")
        {
            $collection += $line
        }
        if ($line -match "^(Use|USE)")
        {
            $collection += $line
        }
    }

    foreach ($line in $collection)
    {
        if ($line -notmatch ";")
        {
            $query = ($line -split "(\s+GO)")[0]
        }
        else
        {
            $query = ($line -split "(?<=;)")[0]
        }

        $queries += $query
    }

    return $queries
}

function Get-SQLQuery
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $collection = @()
    $queries = @()
    $bInitiated = $false
    $bTerminated = $false

    foreach ($line in $CheckContent){
        # Clean the line first
        $line = $line.Trim()

        # Search for a SQL initiator if we haven't found one
        if ($line -match "^(select\s|use\s|alter\s)"){
            $bInitiated = $true
            $collection += $line
        } elseif ($bInitiated){
            # Look for SQL fragments
            if ($line -match "(from\s|\sas\s|join\s|where\s)"){
                $collection += $line
            }
            # Look for non-SQL line - indicating termination
            if ($line -notmatch "(select\s|use\s|alter\s|from\s|\sas\s|join\s|wheres\|go|;)"){
                $bTerminated = $true
            }
        }
        # If we found one (or more) criteria for terminating the SQL script, then close out the query
        if ($bTerminated){
            $query = $collection -join " "
            $queries += $query
            $collection = @()
            $bInitiated = $false
            $bTerminated = $false
        }
    }

    return $queries
}

<#
    .SYNOPSIS Get-TraceIdQuery
        Returns a query that is used to obtain Trace ID's

    .PARAMETER Query
        An array of queries.
#>
function Get-TraceIdQuery
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $EventId
    )

    $return = "BEGIN IF OBJECT_ID('TempDB.dbo.#StigEvent') IS NOT NULL BEGIN DROP TABLE #StigEvent END IF OBJECT_ID('TempDB.dbo.#Trace') IS NOT NULL BEGIN DROP TABLE #Trace END IF OBJECT_ID('TempDB.dbo.#TraceEvent') IS NOT NULL BEGIN DROP TABLE #TraceEvent END CREATE TABLE #StigEvent (EventId INT) CREATE TABLE #Trace (TraceId INT) CREATE TABLE #TraceEvent (TraceId INT, EventId INT) INSERT INTO #StigEvent (EventId) VALUES $($EventId) INSERT INTO #Trace (TraceId) SELECT DISTINCT TraceId FROM sys.fn_trace_getinfo(0) DECLARE cursorTrace CURSOR FOR SELECT TraceId FROM #Trace OPEN cursorTrace DECLARE @traceId INT FETCH NEXT FROM cursorTrace INTO @traceId WHILE @@FETCH_STATUS = 0 BEGIN INSERT INTO #TraceEvent (TraceId, EventId) SELECT DISTINCT @traceId, EventId FROM sys.fn_trace_geteventinfo(@traceId) FETCH NEXT FROM cursorTrace INTO @TraceId END CLOSE cursorTrace DEALLOCATE cursorTrace SELECT * FROM #StigEvent SELECT SE.EventId AS NotFound FROM #StigEvent SE LEFT JOIN #TraceEvent TE ON SE.EventId = TE.EventId WHERE TE.EventId IS NULL END"

    return $return
}

<#
    .SYNOPSIS Get-EventIdQuery
        Returns a query that is used to obtain Event ID's

    .PARAMETER Query
        An array of queries.
#>
function Get-EventIdQuery
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $Query
    )

    foreach ($line in $query)
    {
        if ($line -match "eventid")
        {
            return $line
        }
    }
}

<#
    .SYNOPSIS Get-EventIdData
        Returns the Event ID's that are checked against

    .PARAMETER CheckContent
        This is the 'CheckContent' derived from the STIG raw string and holds the Data that will be returned
#>
function Get-EventIdData
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $array = @()

    $eventData = $checkContent -join " "
    $eventData = ($eventData -split "listed:")[1]
    $eventData = ($eventData -split "\.")[0]

    $eventId = $eventData.Trim()

    $split = $eventId -split ', '

    foreach ($line in $split)
    {
        $add = '(' + $line + ')'

        $array += $add
    }

    $return = $array -join ','

    return $return
}

function Get-SqlRuleType
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $CheckContent
    )

    $content = $checkContent -join " "

    switch ( $content )
    {
        # Standard database existence parsers
        {
            $PSItem -Match 'SELECT' -and
            $PSItem -Match 'existence.*publicly available.*(").*(")\s*(D|d)atabase'
        }
        {
            $ruleType = 'DbExist'
        }
        # Standard trace and event ID parsers
        {
            $PSItem -Match 'SELECT' -and
            $PSItem -Match 'traceid' -and
            $PSItem -Match 'eventid' -and
            $PSItem -NotMatch 'SHUTDOWN_ON_ERROR'
        }
        {
            $ruleType = 'Trace'
        }
        # Standard permissions parsers
        {
            $PSItem -Match 'SELECT' -and
            $PSItem -Match 'direct access.*server-level'
        }
        {
            $ruleType = 'Permission'
        }
        # Audit rules for SQL Server 2012 and beyond
        {
            $PSItem -Match 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
        }
        {
            $ruleType = 'Audit'
        }
        # Default parser if not caught before now - if we end up here we haven't trapped for the rule sub-type.
        # These should be able to get, test, set via Get-Query cleanly
        default
        {
            $ruleType = 'PlainSQL'
        }
    }

    return $ruleType
}
#endregion
