# Windows Server Grunnleggende Oppsett med Active Directory

Dette repositoryet inneholder et PowerShell-skript/kommandoer for å utføre et grunnleggende oppsett av en Windows Server, inkludert nettverkskonfigurasjon, installasjon av nødvendige roller, opprettelse av et nytt Active Directory-skog, konfigurering av DHCP (valgfritt), og opprettelse av grunnleggende Organisatoriske Enheter (OUer) og en testbruker.

**Advarsel:** Dette skriptet gjør betydelige endringer på serveren. Kjør det kun i et testmiljø eller på en server du har til hensikt å konfigurere som domenekontroller. 

## Hva du trenger

* En maskin med Windows Server (Windows Server  2022).
* Administratorrettigheter på serveren.


$newname = "eksamen"
Rename-Computer -NewName $newname -Force -PassThru

$statiskIP = @(
    $interfaceAlias = "Ethernet"
    $ip = "192.168.1.8"
    $prefixLength = 24
    $gateway = "192.168.1.1"
    $dnsServers = @("127.0.0.1")  
    
    New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $ip -PrefixLength $prefixLength -DefaultGateway $gateway

    Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses $dnsServers   
)

 
$innstallerADDS = @(
    $domainName = "poland.dm"
    $netbiosName = "POLAND"
    
    $windowsFeatures = @(
        "AD-Domain-Services"
        "DNS"
        "DHCP"
        "FS-FileServer"
    )
    
    $installResult = Install-WindowsFeature -Name $windowsFeatures -IncludeAllSubFeature -IncludeManagementTools
    
    Write-Output "Restart needed: $($installResult.RestartNeeded)"
    
    if ($installResult.RestartNeeded) {
        Write-Host "A system reboot is required to complete the installation of Windows features."
        Restart-Computer -Force
    } else {
        Write-Host "No reboot is necessary after installing Windows features."
    }   
)


$installerForest = @(
    $domainName = "poland.dm"
    $netbiosName = "POLAND"

    $installADDSForestParams = @{
        DomainName            = $domainName
        DomainNetbiosName     = $netbiosName
        InstallDns            = $true
        CreateDnsDelegation   = $false
        DatabasePath          = "C:\Windows\NTDS"
        LogPath               = "C:\Windows\NTDS"
        SysvolPath            = "C:\Windows\SYSVOL"
        Force                 = $true
    }
    
    $env:HostIP = (
        Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4DefaultGateway -ne $null -and
            $_.NetAdapter.Status -ne "Disconnected"
        }
    ).IPv4Address.IPAddress
    
    Install-ADDSForest @installADDSForestParams
)

# --- DHCP Setup ---
$DHCPSetup = @(
    $ip = "192.168.1.8"
    $dhcpScopeName = "DefaultScope"
    $dhcpStartRange = "192.168.1.100"
    $dhcpEndRange = "192.168.1.200"
    $dhcpSubnetMask = "255.255.255.0"
    
    if ((Get-WindowsFeature -Name DHCP).Installed) {
        $serverFQDN = (Get-ADDomainController -Discover -Service PrimaryDC).HostName
        $serverIPAddress = $ip
    
        Write-Host "Authorizing DHCP server '$serverFQDN' in Active Directory..."
        Add-DhcpServerInDC -DnsName $serverFQDN -IPAddress $serverIPAddress
    
        Write-Host "Creating DHCP scope '$dhcpScopeName' ($dhcpStartRange - $dhcpEndRange)..."
        Add-DhcpServerv4Scope -Name $dhcpScopeName `
            -StartRange $dhcpStartRange `
            -EndRange $dhcpEndRange `
            -SubnetMask $dhcpSubnetMask `
            -State Active
    
        Write-Host "Setting DHCP options (Router, DNS)..."
        $dhcpOptions = @{}
    
        if ($PSBoundParameters.ContainsKey('dhcpRouterOption')) { $dhcpOptions.Add("003", $dhcpRouterOption) }
        if ($PSBoundParameters.ContainsKey('dhcpDnsServerOption')) { $dhcpOptions.Add("006", $dhcpDnsServerOption) }
    
        if ($dhcpOptions.Count -gt 0) {
            Set-DhcpServerv4OptionValue -ScopeId $ip -OptionId $dhcpOptions.Keys -Value $dhcpOptions.Values
        }
    
        Restart-Service DhcpServer
    }
    else {
        Write-Host "DHCP role is not installed. Skipping DHCP configuration." -ForegroundColor Yellow
    }
    
)

$setupOU = @(
    $domainPath = "DC=poland,DC=dm"  
    $ouComputersBase = "Maskiner"
    $ouUsersBase = "Brukere"
    $ouITComputers = "IT-Maskiner"
    $ouGroups = "Grupper"
    $ouServers = "Servere"
    
    New-ADOrganizationalUnit -Name $ouComputersBase -Path $domainPath -Description "Organizational unit for computers"
    New-ADOrganizationalUnit -Name $ouUsersBase -Path $domainPath -Description "Organizational unit for users"
    New-ADOrganizationalUnit -Name $ouGroups -Path $domainPath -Description "Organizational unit for groups"
    New-ADOrganizationalUnit -Name $ouServers -Path $domainPath -Description "Organizational unit for servers"
    
    $computerBasePath = "OU=$ouComputersBase,$domainPath"
    New-ADOrganizationalUnit -Name $ouITComputers -Path $computerBasePath -Description "OU for IT department computers"
    
    Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
    
    $computerRedirectPath = "OU=$ouITComputers,OU=$ouComputersBase,$domainPath"
    Write-Host "Redirecting new computers to: $computerRedirectPath"
    
    redircmp $computerRedirectPath
    
    $userRedirectPath = "OU=$ouUsersBase,$domainPath"
    Write-Host "Redirecting new users to: $userRedirectPath"
    redirusr $userRedirectPath  
)

 
$lagtestbruker = @(
    $testUserName = "Test Bruker"
    $testUserSamAccount = "test.bruker"
    $testUserPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    $testUserChangePasswordAtLogon = $false
    $testUserUPN = "$testUserSamAccount@$domainName"
    $userOUFullPath = "OU=$ouUsersBase,$domainPath"
    
    New-ADUser -Name $testUserName `
        -SamAccountName $testUserSamAccount `
        -UserPrincipalName $testUserUPN `
        -Path $userOUFullPath `
        -AccountPassword $testUserPassword `
        -Enabled $true `
        -ChangePasswordAtLogon:$testUserChangePasswordAtLogon
    
    $createdUser = Get-ADUser -Filter "SamAccountName -eq '$testUserSamAccount'"
    if ($createdUser) {
        Write-Host "Test user '$testUserName' created in OU '$($createdUser.DistinguishedName)'." -ForegroundColor Green
    }
    else {
        Write-Host "Could not verify creation of test user '$testUserName'." -ForegroundColor Red
    }
)


