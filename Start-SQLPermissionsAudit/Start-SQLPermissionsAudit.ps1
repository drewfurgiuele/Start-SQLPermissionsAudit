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
param(
    [Parameter(Mandatory=$true)] [string] $servername,
    [Parameter(Mandatory=$false)] [string] $instanceName = "DEFAULT",
    [Parameter(Mandatory=$false)] [string] $databaseName
)

$LookingForGroups = @("db_datawriter","db_owner")
$LookingForObjectPermissions = @("INSERT","UPDATE","DELETE","EXECUTE","ALTER")

$users = Get-ChildItem -Path ("SQLSERVER:\SQL\" + $servername + "\" + $instanceName + "\LOGINS") | Where-Object {($_.LoginType -eq "WindowsUser") -or ($_.LoginType -eq "WindowsGroup")}
$dbs = Get-ChildItem -Path ("SQLSERVER:\SQL\" + $servername + "\" + $instanceName + "\DATABASES") -Force

if ($databaseName) {$dbs = $dbs | Where-Object {$_.Name -eq $databaseName}}

$objectsTable = New-Object System.Data.DataTable
$objectsTable.Columns.Add("UserName") | Out-Null
$objectsTable.Columns.Add("Name") | Out-Null
$objectsTable.Columns.Add("DatabaseName") | Out-Null
$objectsTable.Columns.Add("MemberOfRole") | Out-Null
$objectsTable.Columns.Add("FromGroupName") | Out-Null
$objectsTable.Columns.Add("ObjectType") | Out-Null
$objectsTable.Columns.Add("ObjectName") | Out-Null
$objectsTable.Columns.Add("Permissions") | Out-Null

ForEach ($u in $users)
{
    $CurrentUser = $u.Name
    Write-Verbose "Checking user: $CurrentUser"
    ForEach ($d in $dbs)
    {
        $d.Refresh()
        $CurrentDatabase = $d.Name
        if ($d.Users | Where-Object {$_.Login -eq $u.Name})
        {
            Foreach ($l in $LookingForGroups)
            {
                if (($d.users | Where-Object {$_.Login -eq $u.Name}).EnumRoles() -contains $l)
                {
                    Write-Verbose "Looking for $l"
                    if ($u.LoginType -eq "WindowsGroup")
                    {
                        $members = Get-ADGroupMember -Identity (($u.Name -split "\\")[1]) -Recursive | Where {$_.ObjectClass -eq "user"}
                        ForEach ($m in $members)
                        {
                            $ADUser = Get-ADUser $m
                            $row = $objectsTable.NewRow()
                            $row["UserName"] = $ADUser.UserPrincipalName
                            $row["Name"] = $ADUser.Name
                            $row["DatabaseName"] = $d.Name
                            $row["MemberOfRole"] = $l
                            $objectsTable.Rows.Add($row)
                        }
                    }
                    if ($u.LoginType -eq "WindowsUser")
                    {
                        
                            $ADUser = Get-ADUser ($u.Name -split "\\")[1]
                            $row = $objectsTable.NewRow()
                            $row["UserName"] = $ADUser.UserPrincipalName
                            $row["Name"] = $ADUser.Name
                            $row["DatabaseName"] = $d.Name
                            $row["MemberOfRole"] = $l
                            $row["FromGroupName"] = $u.Name
                            $objectsTable.Rows.Add($row)
                    }
                }
            }
        }

        $perms = $d.EnumObjectPermissions()
        $userObjectPermissions = $perms | Where-Object {($_.PermissionType.ToString()) -in $LookingForObjectPermissions -and $_.Grantee -eq $u.Name}
        Foreach ($uop in $userObjectPermissions)
        {
            if ($u.LoginType -eq "WindowsGroup")
            {
                $members = Get-ADGroupMember -Identity (($u.Name -split "\\")[1]) -Recursive
                ForEach ($m in $members)
                {
                    $ADUser = Get-ADUser $m
                    $row = $objectsTable.NewRow()
                    $row["UserName"] = $ADUser.UserPrincipalName
                    $row["Name"] = $ADUser.Name
                    $row["DatabaseName"] = $d.Name
                    $row["ObjectType"] = $uop.ObjectClass
                    $row["ObjectName"] = (&{if($uop.ObjectClass -ne "Schema") {$uop.ObjectSchema + "." + $uop.Objectname} else {$uop.Objectname}})
                    $row["FromGroupName"] = $u.Name
                    $row["Permissions"] = ($uop.PermissionType.ToString())
                    $objectsTable.Rows.Add($row)
                }
            }
            if ($u.LoingType -eq "WindowsUser")
            {
                    $ADUser = Get-ADUser ($u.Name -split "\\")[1]
                    $row = $objectsTable.NewRow()
                    $row["UserName"] = $ADUser.UserPrincipalName
                    $row["Name"] = $ADUser.Name
                    $row["DatabaseName"] = $d.Name
                    $row["ObjectType"] = $uop.ObjectClass
                    $row["ObjectName"] = (&{if($uop.ObjectClass -ne "Schema") {$uop.ObjectSchema + "." + $uop.Objectname} else {$uop.Objectname}})
                    $row["Permissions"] = ($uop.PermissionType.ToString())
                    $objectsTable.Rows.Add($row)
            }
        }
    }
}

$objectsTable | Sort-Object -Property Name,ObjectType,ObjectName,Permissions



