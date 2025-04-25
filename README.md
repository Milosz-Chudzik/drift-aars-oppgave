# Windows Server Grunnleggende Oppsett med Active Directory

Dette repositoryet inneholder et PowerShell-skript/kommandoer for å utføre et grunnleggende oppsett av en Windows Server, inkludert nettverkskonfigurasjon, installasjon av nødvendige roller, opprettelse av et nytt Active Directory-skog, konfigurering av DHCP (valgfritt), og opprettelse av grunnleggende Organisatoriske Enheter (OUer) og en testbruker.

**Advarsel:** Dette skriptet gjør betydelige endringer på serveren. Kjør det kun i et testmiljø eller på en server du har til hensikt å konfigurere som domenekontroller. Sørg for å forstå hver kommando før du kjører den.

## Forutsetninger

* En maskin med Windows Server installert (Windows Server  2022).
* Administratorrettigheter på serveren.
* Kjennskap til nettverksadressene som skal brukes (IP, nettverksmaske, gateway, DNS).

## Konfigurasjonsvariabler

Før du kjører kommandoene, bør du tilpasse følgende variabler i skriptet eller manuelt erstatte verdiene i kommandoene:

```powershell
# --- Nettverksinnstillinger ---
$interfaceAlias = "Ethernet" # Endre til navnet på ditt nettverkskort (bruk Get-NetAdapter for å finne navnet)
$ipAddress = "192.168.1.8"
$prefixLength = 24 # Tilsvarer nettverksmaske 255.255.255.0
$gateway = "192.168.1.1"
# DNS-server(e). Etter AD/DNS-installasjon bør serveren peke til seg selv (127.0.0.1) og evt. en annen DNS.
$dnsServers = "127.0.0.1" # Kan også være en liste, f.eks. @("127.0.0.1", "192.168.1.1")

# --- Active Directory-innstillinger ---
$domainName = "poland.local" # Fult kvalifisert domenenavn (FQDN). Bruk .local for interne testmiljøer eller et subdomene du eier.
$netbiosName = "POLAND"      # NetBIOS-navn (vanligvis første del av $domainName, maks 15 tegn).
# Du vil bli bedt om et SafeModeAdministratorPassword under AD-installasjonen.
# Alternativt, definer det her (FJERN KOMMENTAREN og sett et STERKT passord):
# $safeModePassword = ConvertTo-SecureString "DittTryggePassordHer!" -AsPlainText -Force

# --- Roller som skal installeres ---
# Legg til eller fjern roller etter behov
$windowsFeatures = @(
    "AD-Domain-Services",
    "DNS",
    "DHCP",
    "Hyper-V",
    "FS-FileServer"
)

# --- DHCP-innstillinger (hvis DHCP-rollen installeres) ---
$dhcpScopeName = "DefaultScope"
$dhcpStartRange = "192.168.1.100"
$dhcpEndRange = "192.168.1.200"
$dhcpSubnetMask = "255.255.255.0"
# $dhcpRouterOption = $gateway # Angi gateway for klienter
# $dhcpDnsServerOption = $ipAddress # Angi DNS-server(e) for klienter (denne serveren)

# --- OU-navn ---
$ouComputersBase = "Maskiner" # Hoved-OU for datamaskiner
$ouUsersBase = "Brukere"     # Hoved-OU for brukere
$ouITComputers = "IT-Maskiner" # Spesifikk OU for IT-datamaskiner (brukes for redircmp)
$ouGroups = "Grupper"        # OU for grupper
$ouServers = "Servere"       # OU for servere

# --- Testbruker ---
$testUserName = "Test Bruker"
$testUserSamAccount = "test.bruker"
# Passord for testbrukeren (BYTT TIL ET STERKT PASSORD!)
$testUserPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
$testUserChangePasswordAtLogon = $false # Sett til $true for å tvinge passordbytte ved første pålogging


Fremgangsmåte
Kjør følgende kommandoer i en PowerShell-konsoll som administrator. Det anbefales å kjøre dem trinnvis for å verifisere hvert steg.
1. Konfigurer Statisk IP-adresse og DNS
# Sett statisk IP-adresse, nettverksmaske og gateway
Write-Host "Konfigurerer statisk IP-adresse for '$interfaceAlias'..."
Get-NetAdapter -Name $interfaceAlias | New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $gateway

# Sett DNS-server(e) for nettverkskortet
Write-Host "Setter DNS-server(e) til '$($dnsServers -join ', ')'..."
Get-NetAdapter -Name $interfaceAlias | Set-DnsClientServerAddress -ServerAddresses $dnsServers

Write-Host "Nettverkskonfigurasjon er satt. Verifiser med:" -ForegroundColor Yellow
Write-Host "Get-NetIPConfiguration -InterfaceAlias '$interfaceAlias'" -ForegroundColor Cyan


2. Installer Nødvendige Roller og Funksjoner
Write-Host "Installerer Windows-funksjoner: $($windowsFeatures -join ', ')..."
Install-WindowsFeature -Name $windowsFeatures -IncludeAllSubFeature -IncludeManagementTools

# Noen roller kan kreve omstart før konfigurasjon
Write-Host "Rolleinstallasjon fullført. En omstart kan være nødvendig før AD DS konfigureres." -ForegroundColor Yellow
# Uncomment og kjør hvis en omstart er nødvendig:
# Restart-Computer -Force


3. Promoter til Domenekontroller (Nytt Skog)
Denne kommandoen oppretter et nytt Active Directory-skog og konfigurerer serveren som den første domenekontrolleren. Den installerer og konfigurerer også DNS-rollen for det nye domenet.
Write-Host "Starter promotering til domenekontroller for domenet '$domainName'..."
# Sjekk om $safeModePassword er definert
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

# Kjør installasjonen
Install-ADDSForest @installADDSForestParams

# Serveren vil automatisk starte på nytt etter at promoteringen er fullført.
Write-Host "Active Directory Domain Services installasjon startet. Serveren vil starte på nytt automatisk." -ForegroundColor Green


VIKTIG: Vent til serveren har startet på nytt. Logg deretter inn med domeneadministrator-kontoen ($netbiosName\Administrator eller Administrator@$domainName) med det passordet du bruker for den lokale administratorkontoen.
4. (Valgfritt) Konfigurer DHCP-server
Hvis du installerte DHCP-rollen ("DHCP" i $windowsFeatures), må du konfigurere den og autorisere den i Active Directory. Kjør disse kommandoene etter at serveren er promotert og har startet på nytt.
# Sjekk om DHCP-rollen er installert før du fortsetter
if (Get-WindowsFeature -Name DHCP | Where-Object { $_.Installed }) {
    Write-Host "Konfigurerer DHCP-server..."

    # Hent serverens FQDN (viktig for autorisasjon)
    $serverFQDN = (Get-ADDomainController -Discover -Service PrimaryDC).HostName
    $serverIPAddress = $ipAddress # Bruker IP-adressen satt tidligere

    # Autoriser DHCP-serveren i Active Directory
    Write-Host "Autoriserer DHCP-server '$serverFQDN' i Active Directory..."
    Add-DhcpServerInDC -DnsName $serverFQDN -IPAddress $serverIPAddress

    # Opprett et nytt DHCP-scope
    Write-Host "Oppretter DHCP-scope '$dhcpScopeName' ($dhcpStartRange - $dhcpEndRange)..."
    Add-DhcpServerv4Scope -Name $dhcpScopeName `
        -StartRange $dhcpStartRange `
        -EndRange $dhcpEndRange `
        -SubnetMask $dhcpSubnetMask `
        -State Active

    # Sett DHCP-opsjoner (f.eks. Ruter/Gateway og DNS-servere)
    Write-Host "Setter DHCP-opsjoner (Ruter, DNS)..."
    $dhcpOptions = @{}
    if ($PSBoundParameters.ContainsKey('dhcpRouterOption')) { $dhcpOptions.Add("003", $dhcpRouterOption) }
    if ($PSBoundParameters.ContainsKey('dhcpDnsServerOption')) { $dhcpOptions.Add("006", $dhcpDnsServerOption) }
    if ($dhcpOptions.Count -gt 0) {
        Set-DhcpServerv4OptionValue -ScopeId $ipAddress -OptionId $dhcpOptions.Keys -Value $dhcpOptions.Values
    }

    # Start DHCP-tjenesten på nytt for å aktivere endringer
    Write-Host "Restarter DHCP-tjenesten..."
    Restart-Service DhcpServer

    # Verifiser konfigurasjonen
    Write-Host "DHCP-konfigurasjon fullført. Verifiser med:" -ForegroundColor Yellow
    Write-Host "Get-DhcpServerv4Scope" -ForegroundColor Cyan
    Write-Host "Get-DhcpServerInDC" -ForegroundColor Cyan
} else {
    Write-Host "DHCP-rollen er ikke installert. Hopper over DHCP-konfigurasjon." -ForegroundColor Yellow
}



5. Opprett Grunnleggende Organisatoriske Enheter (OUer)
Opprett en struktur med OUer for å organisere objekter i Active Directory.
Write-Host "Oppretter grunnleggende OU-struktur..."
# Definer rot-stien for domenet
$domainPath = "DC=$($domainName.Replace('.',',DC='))"

# Opprett hoved-OUer
New-ADOrganizationalUnit -Name $ouComputersBase -Path $domainPath -Description "Organisatorisk enhet for datamaskiner"
New-ADOrganizationalUnit -Name $ouUsersBase -Path $domainPath -Description "Organisatorisk enhet for brukere"
New-ADOrganizationalUnit -Name $ouGroups -Path $domainPath -Description "Organisatorisk enhet for grupper"
New-ADOrganizationalUnit -Name $ouServers -Path $domainPath -Description "Organisatorisk enhet for servere"

# Opprett under-OUer (eksempel)
$computerBasePath = "OU=$ouComputersBase,$domainPath"
New-ADOrganizationalUnit -Name $ouITComputers -Path $computerBasePath -Description "OU for IT-avdelingens datamaskiner"
# Legg til flere OUer etter behov...

# Verifiser at OUene er opprettet
Write-Host "OU-struktur opprettet. Verifiser med:" -ForegroundColor Yellow
Write-Host "Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName" -ForegroundColor Cyan


6. Omdiriger Standardcontainere
Omdiriger standardplasseringen for nye datamaskin- og brukerobjekter til mer passende OUer. Dette forenkler administrasjon.
Write-Host "Omdirigerer standardcontainere for nye datamaskiner og brukere..."

# Omdiriger 'Computers'-containeren til en spesifikk OU (f.eks. IT-Maskiner)
$computerRedirectPath = "OU=$ouITComputers,OU=$ouComputersBase,$domainPath"
Write-Host "Omdirigerer nye datamaskiner til: $computerRedirectPath"
redircmp $computerRedirectPath

# Omdiriger 'Users'-containeren til OU for Brukere
$userRedirectPath = "OU=$ouUsersBase,$domainPath"
Write-Host "Omdirigerer nye brukere til: $userRedirectPath"
redirusr $userRedirectPath

Write-Host "Standardcontainere er omdirigert." -ForegroundColor Green


7. Opprett en Testbruker
Opprett en eksempelbruker i den definerte bruker-OUen.
Write-Host "Oppretter testbruker '$testUserName'..."
# Definer brukerens UPN (User Principal Name)
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

# Verifiser at brukeren er opprettet
$createdUser = Get-ADUser -Filter "SamAccountName -eq '$testUserSamAccount'"
if ($createdUser) {
    Write-Host "Testbruker '$testUserName' opprettet i OU '$($createdUser.DistinguishedName)'." -ForegroundColor Green
} else {
    Write-Host "Kunne ikke verifisere opprettelsen av testbruker '$testUserName'." -ForegroundColor Red
}


Videre Steg
Dette er kun et grunnleggende oppsett. Vurder følgende videre steg:
Konfigurer DNS Forwarders og Reverse Lookup Zones.
Sett opp Group Policies (GPOer) for sikkerhet og konfigurasjon.
Legg til flere domenekontrollere for redundans og lastbalansering.
Konfigurer sikkerhetskopiering av Active Directory og serveren generelt.
Implementer ytterligere sikkerhetstiltak (f.eks. LAPS, herding av serveren).
Opprett nødvendige brukergrupper og tilordne rettigheter.
Finjuster DHCP-opsjoner og reservasjoner.
Konfigurer fil

