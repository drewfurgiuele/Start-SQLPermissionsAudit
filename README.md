# Start-SQLPermissionsAudit

Have you ever wanted an easy way to look at a SQL Server and know who's got write access to your database(s)? No? Well guess what, your IT auditors do. And digging through all those databases, users, and Active Directory groups sure can be a chore.

This PowerShell script will let you get all USERS (not just groups) that have write access to a database. It will (recursively) scan any groups that have access and report back in a table format the list of users. If the users are members of roles (like db_owner or db_datawriter), or if they have some sort of write access (such as INSERT, UPDATE, DELETE, or ALTER) to individual objects.

Please note that this script requires both the SQLPS module and the ActiveDirectory module. The former can be obtained by installing SQL Server Management Tools, and the ActiveDirectory module can either be obtained by installing Windows Remote Server Administration Tools or by installing the AD Domain Services feature (Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools)

As always, don't run something in production without testing it first.

This script was written in Visual Studio, so if you don't want the entire solution, just dig into the directories to get the .PS1 file.

Did you like this script? Me too! You should send me a shout-out on twitter @pittfurg.
