$if_idx = $gw = $ip = $dns = $null
# Get the IPv4 default gateway.
# only get active interfaces
# If multiple gw, take the one with the least RouteMetric + InterfaceMetric
$default_routes = Get-NetRoute 0.0.0.0/0 |
        Where-Object {$_.AddressFamily -eq 'IPv4' -AND $_.NextHop -ne '0.0.0.0'} |
        Select-Object ifIndex, NextHop, @{l='Metric';e={$_.RouteMetric + $_.InterfaceMetric}}
$up_intf = Get-NetAdapter |
        Where-Object {$_.Status -eq 'Up'}
$rt = $default_routes |
        Where-Object {$up_intf.ifIndex -contains $_.ifIndex} |
        Sort-Object -Property Metric |
        Select-Object -First 1

if ({$rt | Measure-Object}.Count -eq 1) {
    # Get the IPv4 Address on the egress interface towards default gateway
    $intf = Get-NetIpaddress -InterfaceIndex $rt.ifIndex |
        Where-Object {$_.AddressFamily -eq 'IPv4'} |
        Select-Object -First 1
    $if_idx = $rt.ifIndex
    $gw = $rt.NextHop
    if( {$intf | Measure-Object}.Count -eq 1) {
        $ip = $intf.IPAddress
        $intf_name = $intf.InterfaceAlias
    }
}
# Get Local DNS Server
if ($if_idx) {
    $dns_info = Get-DnsClientServerAddress -AddressFamily 'IPv4' |
            Where-Object {$_.ServerAddresses -ne '' -AND $_.InterfaceIndex -eq $if_idx} |
            Select-Object -First 1
} else {
    $dns_info = Get-DnsClientServerAddress -AddressFamily 'IPv4' |
            Where-Object {$_.ServerAddresses -ne ''} |
            Select-Object -First 1
}
if ({$dns_info | Measure-Object}.Count -ne 0) {
    $dns = $dns_info.ServerAddresses | Select-Object -first 1
}
# Add empty string to end of null object, to keep EOL output
Write-Host ($gw + '')
Write-Host ($ip + '')
Write-Host ($dns + '')
Write-Host ($intf_name + '')