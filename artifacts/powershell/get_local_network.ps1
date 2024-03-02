$if_idx = $gw = $ip = $null
# Get the IPv4 default gateway.
# If multiple gw, take the one with the least RouteMetric + InterfaceMetric
$rt = Get-NetRoute 0.0.0.0/0 |
        Where-Object {$_.AddressFamily -eq 'IPv4' -AND $_.NextHop -ne '0.0.0.0'} |
        Select-Object ifIndex, NextHop, @{l='Metric';e={$_.RouteMetric + $_.InterfaceMetric}} |
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
    }
}
# Add empty string to end of null object, to keep EOL output
Write-Host ($if_idx + '')
Write-Host ($gw + '')
Write-Host ($ip + '')
