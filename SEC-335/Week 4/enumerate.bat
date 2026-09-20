:: Create the temp directory first
mkdir C:\temp

:: 1. Current user, groups, and privileges
whoami /all > C:\temp\01_user_privs.txt

:: 2. Running processes
tasklist /v > C:\temp\02_processes.txt

:: 3. Open network sockets and connections
netstat -ano > C:\temp\03_network_connections.txt

:: 4. Running services
sc query type= all > C:\temp\04_services.txt

:: 5. All local user accounts
net user > C:\temp\05_local_users.txt

:: 6. All local groups
net localgroup > C:\temp\06_local_groups.txt

:: 7. Users in the Administrators group
net localgroup Administrators > C:\temp\07_admins.txt

:: 8. Network configuration (IP, gateway, DNS)
ipconfig /all > C:\temp\08_network_config.txt

:: 9. Firewall policies
netsh advfirewall show allprofiles > C:\temp\09_firewall.txt

:: 10. ARP table
arp -a > C:\temp\10_arp_table.txt

:: 11. SMB sessions
net session > C:\temp\11_smb_sessions.txt

:: 12. System information
systeminfo > C:\temp\12_sysinfo.txt
