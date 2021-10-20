<#

.SYNOPSIS

Created by: ingo.gegenwarth[at]sap.com
Version:    42 ("What do you get if you multiply six by nine?")
Changed:    05.06.2015

Retrieves statistics from CAS server for specific user from RPC logs. 

.DESCRIPTION

The Get-RCAStats.ps1 script is enumerating all CAS servers in the current AD site and parse all RPC log files within the given time range for the given mailbox or logonaccount.

The output will be CSV file.

.LINK

https://ingogegenwarth.wordpress.com/2015/05/30/troubleshooting-exchange-with-logparserrca-logs/

.PARAMETER Mailbox

a given mailbox, which is used. The last part from the LegacyExchangeDN is extracted for this e.g.:"/o=contoso/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=Administrator37d" will be "Administrator37d"

.PARAMETER Logonaccount

a given logonaccount, which is used to access mailboxes

.PARAMETER StartDate

this is used for filtering the logfiles to be parsed. The format must be yyMMdd.

.PARAMETER EndDate

this is used for filtering the logfiles to be parsed. The format must be yyMMdd.

.PARAMETER ErrorReport

this is used to collect all errors. Could be combined with mailbox.

.PARAMETER Hourly

only logon operations will be count per hour. Could be combined with mailbox or logonaccount.

.PARAMETER ClientReport

this is used to collect all clients

.PARAMETER Logparser

this is used for the path to LogParser.exe

.PARAMETER ADSite

here you can define in which ADSite is searched for Exchange server

.PARAMETER Outpath

where the output will be found.

.PARAMETER LogFolders

which folders to parse. It must be an UNC path without the server name and could have multiple path comma deliminated.

.PARAMETER LogFolders2013

which folders to parse on an Exchange 2013 server. It must be an UNC path without the server name and could have multiple path comma deliminated.

.PARAMETER Exchange2013

looks only for Exchange 2013 mailbox server.

.PARAMETER Localpath

if you have log files in a local folder. There is no filtering by date! All files will be analyzed. Logs across server versions cannot be mixed.

.EXAMPLE 

# collect all "connect" and "DelegateLogon" operations for a specific mailbox
.\Get-RCAStats.ps1 -Mailbox Administrator -startdate 130213 -enddate 130214

# collect all "connect" and "DelegateLogon" operations for a specific mailbox on
.\Get-RCAStats.ps1 -Mailbox Administrator -startdate 130213 -enddate 130214 -Echange2013

# collect all failures for a specific mailbox
.\Get-RCAStats.ps1 -Mailbox Administrator -startdate 130213 -enddate 130214 -errorreport

# count all "connect" per hour and could be combined with mailbox or logonaccount
.\Get-RCAStats.ps1 -hourly

# count all "connect" per hour for a specific mailbox
.\Get-RCAStats.ps1 -hourly -Mailbox Administrator

# count all "connect" per hour for a specific mailbox
.\Get-RCAStats.ps1 -hourly -Mailbox Administrator -LogFolders "D$\Exchange\Logging\RPC","C$\Program Files\Microsoft\Exchange Server\V14\Logging\RPC Client Access"

.NOTES

You need to run this script in the same AD site where the servers are.

#>

[CmdletBinding(DefaultParameterSetName = "ALL")]

param(
    [parameter( Mandatory=$false, ParameterSetName="MBX")]
    [parameter( Position=0)]
    [string]$Mailbox,
    
    [parameter( Mandatory=$false, ParameterSetName="LOGON")]
    [parameter( Position=1)]
    [string]$Logonaccount,
    
    [parameter( Mandatory=$false, Position=2)]
    [int]$StartDate="$((get-date).ToString("yyMMdd"))",
    
    [parameter( Mandatory=$false, Position=3)]
    [int]$EndDate="$((get-date).ToString("yyMMdd"))",
    
    [parameter( Mandatory=$false, Position=4)]
    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="MBX")]
    [switch]$ErrorReport,
    
    [parameter( Mandatory=$false, Position=5)]
    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="MBX")]
    [parameter( Mandatory=$false, ParameterSetName="LOGON")]
    [switch]$Hourly,
    
    [parameter( Mandatory=$false, Position=6)]
    [parameter( Mandatory=$false, ParameterSetName="ALL")]
    [parameter( Mandatory=$false, ParameterSetName="MBX")]
    [parameter( Mandatory=$false, ParameterSetName="LOGON")]
    [parameter( Mandatory=$false, ParameterSetName="CLIENT")]
    [switch]$ClientReport,
        
    [parameter( Mandatory=$false, Position=7)]
    [ValidateScript({If (Test-Path $_ -PathType leaf) {$True} Else {Throw "Logparser could not be found!"}})]
    [string]$Logparser="C:\Program Files (x86)\Log Parser 2.2\LogParser.exe",
    
    [parameter( Mandatory=$false, Position=8)]
    [string]$ADSite="$(([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name)",
    
    [parameter( Mandatory=$false, Position=9)]
    [ValidateScript({If (Test-Path $_ -PathType container) {$True} Else {Throw "$_ is not a valid path!"}})]
    $Outpath = $env:temp,
    
    [parameter( Mandatory=$false, Position=10)]
    [array]$LogFolders="C$\Program Files\Microsoft\Exchange Server\V14\Logging\RPC Client Access",
    
    [parameter( Mandatory=$false, Position=11)]
    [array]$LogFolders2013="C$\Program Files\Microsoft\Exchange Server\V15\Logging\RPC Client Access",
    
    [parameter( Mandatory=$false, Position=12)]
    [switch]$Exchange2013,

    [parameter( Mandatory=$false, Position=13)]
    [ValidateScript({If (Test-Path $_ -PathType container) {$True} Else {Throw "$_ is not a valid path!"}})]
    [string]$Localpath
)

# check for elevated PS
If (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

# function to get the Exchangeserver from AD site
Function GetExchServer {
    #http://technet.microsoft.com/en-us/library/bb123496(v=exchg.80).aspx on the bottom there is a list of values
    param([array]$Roles,[string]$ADSite)
    Process {
        $valid = @("2","4","16","20","32","36","38","54","64","16385","16439")
        ForEach ($Role in $Roles){
            If (!($valid -contains $Role)) {
                Write-Output -fore red "Please use the following numbers: MBX=2,CAS=4,UM=16,HT=32,Edge=64 multirole servers:CAS/HT=36,CAS/MBX/HT=38,CAS/UM=20,E2k13 MBX=54,E2K13 CAS=16385,E2k13 CAS/MBX=16439"
                Break
            }
        }
        Function GetADSite {
            param([string]$Name)
            If (!($Name)) {
                [string]$Name = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).GetDirectoryEntry().Name
            }
            $FilterADSite = "(&(objectclass=site)(Name=$Name))"
            $RootADSite= ([ADSI]'LDAP://RootDse').configurationNamingContext
            $SearcherADSite = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$RootADSite")
            $SearcherADSite.Filter = "$FilterADSite"
            $SearcherADSite.pagesize = 1000
            $ResultsADSite = $SearcherADSite.FindOne()
            $ResultsADSite
        }
        $Filter = "(&(objectclass=msExchExchangeServer)(msExchServerSite=$((GetADSite -Name $ADSite).properties.distinguishedname))(|"
        ForEach ($Role in $Roles){
            $Filter += "(msexchcurrentserverroles=$Role)"
        }
        $Filter += "))"
        $Root= ([ADSI]'LDAP://RootDse').configurationNamingContext
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Root")
        $Searcher.Filter = "$Filter"
        $Searcher.pagesize = 1000
        $Results = $Searcher.FindAll()
        $Results
    }
}

If (!($Localpath)) {
# get CAS servers
    If ($Exchange2013) {
        [array]$servers = GetExchServer -Role 54,16439 -ADSite $ADSite
        $LogFolders=$LogFolders2013
    }
    Else {
        [array]$servers = GetExchServer -Role 4,20,36,38 -ADSite $ADSite
    }
    $RCAServer = "EXTRACT_PREFIX(EXTRACT_TOKEN(EXTRACT_PATH(filename),1,'\\\\'),0,'\\')"
    # Note: Properties of LDAP result is case sensitive!
    If ($Servers) {
        Write-Output "Found the following servers:" $($Servers | %{$_.Properties.name})
    }
    Else {
        Write-Output "No server found!"
        Break
    }

    # build folderpath for all servers
    ForEach ($Server in $Servers) {
        ForEach ($Folder in $LogFolders) {
        [array]$TempPath += "\\" + $Server.Properties.name + "\" + $Folder
        }
    }
}
Else {
    [array]$TempPath = $Localpath
    $RCAServer = "server-ip"
}

$Path = $null
[array]$LogFiles = $null
[string]$LogsFrom = $null

# validate all path
Foreach ($Path in $TempPath) { 
    If (Test-Path -LiteralPath $Path) {
    [array]$ValidPath += $Path
    }
}
# get all items in final path
If ($ValidPath) {
    ForEach ($Item in $ValidPath) {
        If (Test-Path -LiteralPath $Item){
        $LogFiles += Get-ChildItem -LiteralPath $Item -Filter "*.log"
        }
    }
}
Else {
    Write-Output "No logs found!"
    Break
}
# filter and sort files
If (!($Localpath)) {
    $LogFiles = $LogFiles | ?{$_.name.substring(6,6) -ge $StartDate -and $_.name.substring(6,6) -le $EndDate}
}

If ($LogFiles) {
    $LogFiles | %{$Logsfrom += "'" + $_.fullname +"',"}
    $Logsfrom = $Logsfrom.TrimEnd(",")
    Write-Output "Logs to be parsed:"
    $LogFiles |select fullname|sort fullname
}
Else {
    Write-Output "No logs found!"
    Break
}
# build query for RPC
If ($errorreport) {
If ($mailbox) {     
$stamp = "ErrorReport" + "_" + $mailbox + "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}
Else {
$stamp = "ErrorReport" + "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}
$query_RPC = @"
SELECT Day,Time AS TimeUTC,Mailbox,Client,Version,Mode,Server,ClientIP,RPCStatus,Failures
Using
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: date-time],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: date-time],0,'T')),0,'.'), 'hh:mm:ss') AS Time,
SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3) AS Mailbox,
$RCAServer AS Server,
REVERSEDNS(client-ip) AS ClientIP,
TO_STRING(rpc-status) AS RPCStatus,
TO_LOWERCASE(client-software) AS Client,
client-software-version AS Version,
client-mode AS Mode

INTO    $outpath\*_RCA_Result_$stamp.csv
From 
"@
$query_RPC += $Logsfrom 
$query_RPC += @"

Where (Failures IS NOT NULL AND Time IS NOT NULL)
"@
If ($mailbox) {     
$query_RPC += @"
AND Mailbox LIKE '%$mailbox%'
"@
}
$query_RPC += @"

GROUP BY Day,TimeUTC,Mailbox,Client,Version,Mode,Server,ClientIP,RPCStatus,Failures
ORDER BY Time
"@
}

Else {

If ($clientreport) {
If ($mailbox) {
$stamp = "Clientreport" + "_" + $mailbox +  "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}
Else{
$stamp = "Clientreport" + "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}
$query_RPC = @"
SELECT DISTINCT Day,Client,Version,Count(*) AS TotalHits
Using
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: date-time],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
TO_LOWERCASE(client-software) AS Client,
client-software-version AS Version,
SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3) AS Mailbox,
CASE Operation
    WHEN 'Connect' Then RESOLVE_SID(EXTRACT_SUFFIX(EXTRACT_PREFIX(operation-specific,0,','),0,'='))
END AS LogonAccount

INTO    $outpath\*_RCA_Result_$stamp.csv
From 
"@
$query_RPC += $logsfrom 
$query_RPC += @"

Where Operation LIKE 'connect' 
"@
If ($mailbox) {     
$query_RPC += @"
AND Mailbox LIKE '%$mailbox%'
"@
}
ElseIf ($logonaccount) {        
$query_RPC += @"
AND LogonAccount LIKE '%$logonaccount%'
"@
}
$query_RPC += @"

GROUP BY Day,Client,Version
ORDER BY TotalHits DESC
"@
}

Else {
#if hourly build query for report based on hours
If ($hourly){

#define the outputfilename
If ($mailbox) {     
$stamp = "Hourly" + "_" + $mailbox + "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}
ElseIf ($logonaccount) {
$stamp = "Hourly" + "_" + $logonaccount + "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}
Else {
$stamp = "Hourly" + "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}

$query_RPC = @"
SELECT Day,Hour,Server,Mailbox,Count(Connects) AS Connect, Count(DelegateConnects) AS DelegateConnect --Count(*) AS Hits, Server
Using
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: date-time],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3) AS Mailbox,
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: date-time],0,'T')),0,'.'), 'hh:mm:ss'),'hh') AS Hour,
$RCAServer AS Server,
CASE Operation
    WHEN 'Connect' Then 1
END AS Connects,
CASE Operation
    WHEN 'DelegateLogon' Then 1
END AS DelegateConnects,
CASE Operation
    WHEN 'Connect' Then RESOLVE_SID(EXTRACT_SUFFIX(EXTRACT_PREFIX(operation-specific,0,','),0,'='))
END AS LogonAccount

INTO    $outpath\*_RCA_Result_$stamp.csv
From 
"@
$query_RPC += $logsfrom 
If ($mailbox) {     
$query_RPC += @"

Where (Operation LIKE 'connect' OR Operation LIKE 'DelegateLogon') AND Mailbox LIKE '%$mailbox%'
"@
}
ElseIf ($logonaccount) {        
$query_RPC += @"

Where (Operation LIKE 'connect' OR Operation LIKE 'DelegateLogon') AND LogonAccount LIKE '%$logonaccount%'
"@
}
Else {
$query_RPC += @"

Where Operation LIKE 'connect' OR Operation LIKE 'DelegateLogon'
"@

}
$query_RPC += @"
GROUP BY Day,Hour,Server,Mailbox
ORDER BY Hour
"@

}

Else {

#define the outputfilename
If ($mailbox) {     
$stamp = $mailbox + "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}
ElseIf ($logonaccount) {        
$stamp = "LogonAccount_" + $logonaccount + "_" + $(Get-Date -Format yyMMdd_HH-mm-ss)
}
Else {
$stamp = $(Get-Date -Format yyMMdd_HH-mm-ss)
}

$query_RPC = @"
SELECT Day,Time AS TimeUTC,Mailbox,Server,ClientIP,LogonAccount,DelegateLogonAccount,OwnerLogonAccount,Operation,Client,Version,Mode,Protocol,[Time taken in MS],Flags
Using
TO_STRING(TO_TIMESTAMP(EXTRACT_PREFIX(REPLACE_STR([#Fields: date-time],'T',' '),0,'.'), 'yyyy-MM-dd hh:mm:ss'),'yyMMdd') AS Day,
TO_TIMESTAMP(EXTRACT_PREFIX(RTRIM(REPLACE_STR([#Fields: date-time],'T',' ')),0,'.'), 'yyyy-mm-dd hh:mm:ss') AS Date,
TO_TIMESTAMP(EXTRACT_PREFIX(TO_STRING(EXTRACT_SUFFIX([#Fields: date-time],0,'T')),0,'.'), 'hh:mm:ss') AS TIME,
SUBSTR(EXTRACT_SUFFIX(client-name,0,'/'),3) AS Mailbox,
$RCAServer AS Server,
TO_INT(ADD(ADD(MUL(TO_REAL(SUBSTR(processing-time, 0, 2)), 3600000), MUL(TO_REAL(SUBSTR(processing-time, 3, 2)), 60000)),ADD(MUL(TO_REAL(SUBSTR(processing-time, 6, 2)), 1000), MUL(TO_REAL(SUBSTR(processing-time, 9, 3)), 1)))) as [Time taken in MS],
CASE Operation
    WHEN 'Connect' Then RESOLVE_SID(EXTRACT_SUFFIX(EXTRACT_PREFIX(operation-specific,0,','),0,'='))
END AS LogonAccount,
CASE Operation
    WHEN 'Connect' Then EXTRACT_SUFFIX(EXTRACT_SUFFIX(operation-specific,0,','),0,'=')
END AS Flags,
CASE Operation
    WHEN 'DelegateLogon' Then EXTRACT_PREFIX(EXTRACT_SUFFIX(EXTRACT_SUFFIX(operation-specific,1,','),0,'='),0,' ')
END AS  DelegateLogonAccount,
CASE Operation
    WHEN 'OwnerLogon' Then EXTRACT_PREFIX(EXTRACT_SUFFIX(EXTRACT_SUFFIX(operation-specific,1,','),0,'='),0,' ')
END AS  OwnerLogonAccount,
TO_LOWERCASE(client-software) AS Client,
client-software-version AS Version,
client-mode AS Mode,
REVERSEDNS(client-ip) AS ClientIP

INTO    $outpath\*_RCA_Result_$stamp.csv
From 
"@
$query_RPC += $logsfrom 
$query_RPC += @"

Where (Operation LIKE 'connect' OR Operation LIKE 'DelegateLogon' OR Operation LIKE 'OwnerLogon')
"@

If ($mailbox) {     
$query_RPC += @"
AND Mailbox LIKE '%$mailbox%'
"@
}
ElseIf ($logonaccount) {        
$query_RPC += @"
AND LogonAccount LIKE '%$logonaccount%'
"@
}
$query_RPC += @"

GROUP BY Day,Date,TimeUTC,Mailbox,Server,ClientIP,LogonAccount,DelegateLogonAccount,OwnerLogonAccount,operation,Client,Version,Mode,Protocol,[Time taken in MS],Flags
ORDER BY Time
"@
}
}
}
# workaround for limitation of path length, therefor we put the query into a file
sc -value $query_RPC $outpath\query.txt -force

Write-Output "Start query!"
& $Logparser file:$outpath\query.txt -i:csv -nSkipLines:4 -e:100 -dtLines:0
Write-Output "Query done!"
# clean query file
Get-ChildItem -LiteralPath $outpath -Filter query.txt | Remove-Item -Confirm:$false | Out-Null