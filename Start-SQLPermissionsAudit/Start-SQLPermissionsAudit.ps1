<#
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



