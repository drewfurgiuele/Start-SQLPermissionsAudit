<#
.SYNOPSIS
    Takes a given SQL server (or database on a SQL server) and audits people who have write access. If there are AD groups, it finds all users in those groups (and groups within groups).
.DESCRIPTION
    This script will attempt to scan all domain users and groups in the Windows Active Directory domain and report out on who has write access to your database(s). It will also recursively scan AD groups if a group contains other groups.
	NOTE: This script requires the SQLPS module. You can get it by installing SQL Server Management Tools, then by importing the module:

	Import-Module SQLPS

	ALSO NOTE: This script also requires the Windows Remote Management tools installed on your machine, or, if you're running from a server, the AD Domain Services Windows feature. You can get either by:

		A) Installing Windows Remote Server Administration Tools, or
		B) Running the "Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools" command in PowerShell

	This will install the AD module that this script makes use of.

	You can also customize the script to look for other server/database roles or permissions by modifying the $LookingForGroups or $LookingForObjectPermissions arrays.

.PARAMETER servername
    The hostname or FQDN of the server you want the script to scan.
.PARAMETER instancename
    The instance name of the SQL server you want the script to run on, defaults to "DEFAULT" for non-named instances. This is optional parameter.
.PARAMETER databasename
    The name of the database you want to collect write permissions on. If not provided, the script will scan all databases. This is an optional parameter.
.EXAMPLE
    ./Start-SQLPermissionsAudit -Servername localhost

	This will execute a permissions audit on the server 'localhost' in ALL databases
.EXAMPLE
    ./Start-SQLPermissionsAudit -Servername localhost -databasename AdventureWorks2014

	This will execute a permissions audit on the server 'localhost' in ONLY the AdventureWorks 2014 database
.OUTPUTS
    The script will output a table full of permissions.
.NOTES
    .
.CHANGELOG
    .
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory=$true)] [string] $servername,
    [Parameter(Mandatory=$false)] [string] $instanceName = "DEFAULT",
    [Parameter(Mandatory=$false)] [string] $databaseName
)

$LookingForGroups = @("db_datawriter","db_owner")
$LookingForObjectPermissions = @("INSERT","UPDATE","DELETE","EXECUTE","ALTER")

$dbs = Get-ChildItem -Path ("SQLSERVER:\SQL\" + $servername + "\" + $instanceName + "\DATABASES") -Force
$serverLogins = Get-ChildItem -Path ("SQLSERVER:\SQL\" + $servername + "\" + $instanceName + "\LOGINS") | Where-Object {($_.LoginType -eq "WindowsUser") -or ($_.LoginType -eq "WindowsGroup")}

if ($databaseName) {$dbs = $dbs | Where-Object {$_.Name -eq $databaseName}}
$permissionsList = @()

ForEach ($d in $dbs)
{
    $CurrentDatabase = $d.Name
    Write-Verbose "Looking in database $currentDatabase"
    $permissionsForDatabase = @()
    $ObjectPermissions = $d.EnumObjectPermissions()
    ForEach ($s in $serverLogins) 
    {
        $permissions = New-Object -TypeName PSObject
        $permissions | Add-Member -MemberType NoteProperty -Name Name -Value $s.Name
        $permissions | Add-Member -MemberType NoteProperty -Name Orphaned -Value "No"
        $permissions | Add-Member -MemberType NoteProperty -Name LoginType -Value $s.LoginType

        $permissionsForDatabase += $permissions
    }
    $usersNotInServerLogins = $d.Users | Where-Object {$_.Name -notin @("dbo","distributor_admin","guest","INFORMATION_SCHEMA","sys") -and $_.Name -notin $serverLogins.Name}
    ForEach ($u in $usersNotInServerLogins) 
    {
        $permissions = New-Object -TypeName PSObject
        $permissions | Add-Member -MemberType NoteProperty -Name Name -Value $u.Name
        $permissions | Add-Member -MemberType NoteProperty -Name Orphaned -Value "Yes"
        $permissions | Add-Member -MemberType NoteProperty -Name LoginType -Value $u.LoginType
        $permissionsForDatabase += $permissions
    }
    ForEach ($p in $permissionsForDatabase)
    {
        if ($d.Users | Where-Object {$_.Login -eq $p.Name})
        {
            Foreach ($l in $LookingForGroups)
            {
                if (($d.Users | Where-Object {$_.Login -eq $p.Name}).EnumRoles() -contains $l)
                {
                    if ($p.LoginType -eq "WindowsGroup")
                    {
                        $members = Get-ADGroupMember -Identity (($p.Name -split "\\")[1]) -Recursive | Where {$_.ObjectClass -eq "user"}
                        ForEach ($m in $members)
                        {
                            $ADUser = Get-ADUser $m
                            $permissionsObject = New-Object -TypeName PSObject
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name UserName -Value $ADUser.UserPrincipalName
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name Name -Value $ADUser.Name
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name DatabaseName -Value $d.Name
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name MemberOfRole -Value $l
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name FromGroupName -Value $p.Name
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name ObjectType -Value $null
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name ObjectName -Value $null
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name Permissions -Value $null
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name Orphaned -Value $p.Orphaned
                            $permissionsList += $permissionsObject
                        }
                    }
                    if ($p.LoginType -eq "WindowsUser")
                    {
                        
                            $ADUser = Get-ADUser ($p.Name -split "\\")[1]
                            $permissionsObject = New-Object -TypeName PSObject
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name UserName -Value $ADUser.UserPrincipalName
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name Name -Value $ADUser.Name
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name DatabaseName -Value $d.Name
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name MemberOfRole -Value $l
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name FromGroupName -Value $p.Name
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name ObjectType -Value $null
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name Permissions -Value $null                            
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name ObjectName -Value $null
                            $permissionsObject | Add-Member -MemberType NoteProperty -Name Orphaned -Value $p.Orphaned
                            $permissionsList += $permissionsObject
                    }
                }
            }
            $userObjectPermissions = $ObjectPermissions | Where-Object {($_.PermissionType.ToString()) -in $LookingForObjectPermissions -and $_.Grantee -eq $p.Name}
            Foreach ($uop in $userObjectPermissions)
            {
                if ($p.LoginType -eq "WindowsGroup")
                {
                    $members = Get-ADGroupMember -Identity (($p.Name -split "\\")[1]) -Recursive
                    ForEach ($m in $members)
                    {
                        $ADUser = Get-ADUser $m
                        $permissionsObject = New-Object -TypeName PSObject
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name UserName -Value $ADUser.UserPrincipalName
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name Name -Value $ADUser.Name
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name DatabaseName -Value $d.Name
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name MemberOfRole -Value $null
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name FromGroupName -Value $p.Name
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name ObjectType -Value $uop.ObjectClass
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name Permissions -Value ($uop.PermissionType.ToString())
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name ObjectName -Value (&{if($uop.ObjectClass -ne "Schema") {$uop.ObjectSchema + "." + $uop.Objectname} else {$uop.Objectname}})
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name Orphaned -Value $p.Orphaned
                        $permissionsList += $permissionsObject
                    }
                }
                if ($p.LoginType -eq "WindowsUser")
                {
                        $ADUser = Get-ADUser ($p.Name -split "\\")[1]
                        $permissionsObject = New-Object -TypeName PSObject
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name UserName -Value $ADUser.UserPrincipalName
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name Name -Value $ADUser.Name
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name DatabaseName -Value $d.Name
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name MemberOfRole -Value $null
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name FromGroupName -Value $p.Name
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name ObjectType -Value $uop.ObjectClass
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name Permissions -Value ($uop.PermissionType.ToString())
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name ObjectName -Value (&{if($uop.ObjectClass -ne "Schema") {$uop.ObjectSchema + "." + $uop.Objectname} else {$uop.Objectname}})
                        $permissionsObject | Add-Member -MemberType NoteProperty -Name Orphaned -Value $p.Orphaned
                        $permissionsList += $permissionsObject
                }
            }
        }
    }
    

}

$permissionsList | Sort-Object -Property DatabaseName,FromGroupName,Name,ObjectType,ObjectName,Permissions



