# --- Nettverksinnstillinger ---
$env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
    }
).IPv4Address.IPAddress
$prefixLength = 24 # Tilsvarer nettverksmaske 255.255.255.0
$gateway = "192.168.1.1"
# DNS-server(e). Etter AD/DNS-installasjon bør serveren peke til seg selv (127.0.0.1) og evt. en annen DNS.
$dnsServers = "127.0.0.1" # Kan også være en liste, f.eks. @("127.0.0.1", "192.168.1.1")

# --- Active Directory-innstillinger ---
$domainName = "ove-server.dm" # Du kan bare bruke karakterer fra a-z, tall og bindestrek. til slutt må du ha .dm/com/no eller organisasjons domenet ditt.
$netbiosName = "OVE-SERVER"      # NetBIOS-navn (vanligvis første del av $domainName, maks 15 tegn).
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
