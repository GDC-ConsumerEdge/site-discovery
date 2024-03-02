param (
    # get the dns servers on given interface index
    [string]$if_idx = ''
)
$dns = $null
if ($if_idx -ne '') {
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

Write-Host ($dns + '')