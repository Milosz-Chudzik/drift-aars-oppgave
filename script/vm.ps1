$mem = 4096MB #Hvor mye minne skal du gi til maskinen?
$switch = 'wifi'
$vhdpath = 'C:\virtuellmaskin' #Lokasjonen for den virtuelle harddisken
$vhdsize = 256GB
$dvd = "C:\Users\MiIosz\Downloads\en-us_windows_server_2022_updated_july_2023_x64_dvd_541692c3.iso" #Bane til ISO filen som har operativsystemet
$vmname = (Read-Host -Prompt 'Skiv inn navnet på din virtuelle  maskin') #Hva skal den virtuelle maskinen hete?

#Så lager vi den virtuelle maskinen med variablene vi har satt opp.
New-VM -Name $vmname -MemoryStartupBytes $mem -SwitchName $switch -NewVHDSizeBytes $vhdsize -NewVHDPath $vhdpath\$vmname.vhdx -Generation 2


Set-VMMemory -VMName $vmname -DynamicMemory $true

Set-VM -Name $vmname -ProcessorCount 4 -DynamicMemory -Notes 'Dette er en Virtuell maskin for generelt bruk'
Add-VMScsiController -VMName $vmname
Add-VMDvdDrive -VMName $vmname -ControllerNumber 1 -Path $dvd


$network = Get-VMNetworkAdapter -VMName $vmname
$diskphy = Get-VMHardDiskDrive -VMName $vmname
$dvdboot = Get-VMDvdDrive -VMName $vmname
Set-VMFirmware -VMName $vmname -BootOrder $dvdboot, $diskphy, $network