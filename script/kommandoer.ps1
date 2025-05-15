Get-NetAdapter -Name $interfaceAlias | New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $gateway

Get-NetAdapter -Name $interfaceAlias | Set-DnsClientServerAddress -ServerAddresses $dnsServers

Install-WindowsFeature -Name $windowsFeatures -IncludeAllSubFeature -IncludeManagementTools

Get-WindowsFeature -Name $windowsFeatures

Restart-Computer -Force

$installADDSForestParams = @{
    DomainName = $domainName
    DomainNetbiosName = $netbiosName
    InstallDns = $true
    CreateDnsDelegation = $false
    DatabasePath = "C:\Windows\NTDS"
    LogPath = "C:\Windows\NTDS"
    SysvolPath = "C:\Windows\SYSVOL"
    Force = $true # Bruk Force med forsiktighet, bekrefter automatiske omstarter etc.
}
if ($PSBoundParameters.ContainsKey('safeModePassword')) {
    $installADDSForestParams.Add("SafeModeAdministratorPassword", $safeModePassword)
}

Install-ADDSForest @installADDSForestParams


if (Get-WindowsFeature -Name DHCP | Where-Object { $_.Installed }) {

    # Hent serverens FQDN (viktig for autorisasjon)
    $serverFQDN = (Get-ADDomainController -Discover -Service PrimaryDC).HostName
    $serverIPAddress = $env:HostIP # Bruker IP-adressen satt tidligere

    # Autoriser DHCP-serveren i Active Directory
    Add-DhcpServerInDC -DnsName $serverFQDN -IPAddress $serverIPAddress

    # Opprett et nytt DHCP-scope
    Add-DhcpServerv4Scope -Name $dhcpScopeName `
        -StartRange $dhcpStartRange `
        -EndRange $dhcpEndRange `
        -SubnetMask $dhcpSubnetMask `
        -State Active

    # Sett DHCP-opsjoner (f.eks. Ruter/Gateway og DNS-servere)
    $dhcpOptions = @{}
    if ($PSBoundParameters.ContainsKey('dhcpRouterOption')) { $dhcpOptions.Add("003", $dhcpRouterOption) }
    if ($PSBoundParameters.ContainsKey('dhcpDnsServerOption')) { $dhcpOptions.Add("006", $dhcpDnsServerOption) }
    if ($dhcpOptions.Count -gt 0) {
        Set-DhcpServerv4OptionValue -ScopeId $ipAddress -OptionId $dhcpOptions.Keys -Value $dhcpOptions.Values
    }


    # Start DHCP-tjenesten på nytt for å aktivere endringer
    Restart-Service DhcpServer

    
} else {
    Install-WindowsFeature -NAME DHCP -IncludeManagementTools
    Write-Host "DHCP-rollen er ikke installert. installerer dns." -ForegroundColor Yellow
}

$domainPath = "DC=ove-server, DC=dm"

New-ADOrganizationalUnit -Name $ouComputersBase -Path $domainPath -Description "Organisatorisk enhet for datamaskiner"
New-ADOrganizationalUnit -Name $ouUsersBase -Path $domainPath -Description "Organisatorisk enhet for brukere"
New-ADOrganizationalUnit -Name $ouGroups -Path $domainPath -Description "Organisatorisk enhet for grupper"
New-ADOrganizationalUnit -Name $ouServers -Path $domainPath -Description "Organisatorisk enhet for servere"

#setter standard gruppe for brukere og maskiner
$computerRedirectPath = "OU=$ouITComputers,OU=$ouComputersBase,$domainPath"
Write-Host "Omdirigerer nye datamaskiner til: $computerRedirectPath"
redircmp $computerRedirectPath

# Omdiriger 'Users'-containeren til OU for Brukere
$userRedirectPath = "OU=$ouUsersBase,$domainPath"
redirusr $userRedirectPath

$testUserUPN = "$testUserSamAccount@$domainName"
# Definer stien til bruker-OUen
$userOUFullPath = "OU=$ouUsersBase,$domainPath"

# Opprett brukeren
New-ADUser -Name $testUserName `
    -SamAccountName $testUserSamAccount `
    -UserPrincipalName $testUserUPN `
    -Path $userOUFullPath `
    -AccountPassword $testUserPassword `
    -Enabled $true `
    -ChangePasswordAtLogon:$testUserChangePasswordAtLogon


$createdUser = Get-ADUser -Filter "SamAccountName -eq '$testUserSamAccount'"
if ($createdUser) {
    Write-Host "Testbruker '$testUserName' opprettet i OU '$($createdUser.DistinguishedName)'." -ForegroundColor Green
} else {
    Write-Host "Kunne ikke verifisere opprettelsen av testbruker '$testUserName'." -ForegroundColor Red
}
