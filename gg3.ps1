# Number of threads to use (based on available CPU cores)
$threads = [Environment]::ProcessorCount
$chunkSize = 1GB      # Size of each chunk (adjust based on available RAM)
$targetSize = 64GB    # Total target memory size (increased for higher stress)

# Disable automatic pagefile management and other memory optimizations
# Disable automatic pagefile management
Invoke-Expression "wmic computersystem where name='%computername%' set AutomaticManagedPagefile=False"
# Disable pagefile on C:
Invoke-Expression "wmic pagefileset where name='C:\\pagefile.sys' delete"
# Disable memory compression (it helps in reducing memory load)
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"

# Disable Superfetch (SysMain) to stop memory optimization
Stop-Service -Name 'SysMain' -Force
Set-Service -Name 'SysMain' -StartupType Disabled

# Calculate number of chunks needed to reach the target size
$chunksNeeded = [math]::Ceiling($targetSize / $chunkSize)
$jobs = @()

# Start parallel jobs based on the number of threads (cores)
for ($i = 1; $i -le $threads; $i++) {
    $jobs += Start-Job -ScriptBlock {
        # Define the Stress-Test function inside the job block
        function Stress-Test {
            param($jobId, $chunksNeeded, $chunkSize)
            $chunks = New-Object System.Collections.Generic.List[string]
            $bytes = New-Object byte[] $chunkSize
            $null = [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)

            # Simulate memory usage and CPU load with intensive operations
            for ($i = 0; $i -lt $chunksNeeded; $i++) {
                $randString = [System.Text.Encoding]::UTF8.GetString($bytes)
                for($x=0;$x -lt 100;++$i){
                    $chunks.Add($randString)
                }
                # Perform more intensive CPU operations (added more iterations)
                for ($j = 0; $j -lt 50000; $j++) {
                    # Deep SHA256 hashing with multiple iterations
                    $data = [System.Text.Encoding]::UTF8.GetBytes($randString)
                    $hash1 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($data)
                    $hash2 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($hash1)
                    $hash3 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($hash2)
                    $hash4 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($hash3)
                    $hash5 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($hash4)
                }

                # Add more complex math-intensive loops (increase iterations)
                $num = 0
                for ($k = 1; $k -lt 5000; $k++) {
                    $num += [math]::Sqrt($k * 12345) * [math]::Log($k + 1)
                }

                # Generate larger matrices to multiply (increase matrix size)
                $size = 50000  # Increase the matrix size to a larger value
                $A = @()
                $B = @()
                $C = @()

                for ($i = 0; $i -lt $size; $i++) {
                    $rowA = @()
                    $rowB = @()
                    $rowC = @()
                    for ($j = 0; $j -lt $size; $j++) {
                        $rowA += (Get-Random -Minimum 1532360321 -Maximum 1231235436536999)
                        $rowB += (Get-Random -Minimum 5677464869 -Maximum 1245235235466795)
                        $rowC += 0
                    }
                    $A += ,$rowA
                    $B += ,$rowB
                    $C += ,$rowC
                }

                # Multiply A * B into C
                for ($i = 0; $i -lt $size; $i++) {
                    for ($j = 0; $j -lt $size; $j++) {
                        $sum = 0
                        for ($k = 0; $k -lt $size; $k++) {
                            $sum += $A[$i][$k] * $B[$k][$j]
                        }
                        $C[$i][$j] = $sum
                    }
                }

                # Introduce intensive number factorization
                function Get-Primes($n) {
                    $factors = @()
                    for ($i = 2; $i -le $n; $i++) {
                        while ($n % $i -eq 0) {
                            $factors += $i
                            $n = [math]::Floor($n / $i)
                        }
                    }
                    return $factors
                }
                $null = Get-Primes 9889396939693

                # Small RSA key generation for further CPU load
                $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(16384)
                $publicKey = $rsa.ToXmlString($false)
                $privateKey = $rsa.ToXmlString($true)
            }

            # Periodically show progress for each job
            if ($i % 10 -eq 0) {
                Write-Progress -Activity "Job ${jobId}: Stressing Memory + CPU" -Status "Chunk $i of $chunksNeeded" -PercentComplete (($i / $chunksNeeded) * 100)
            }
            Write-Progress -Activity "Job ${jobId}: Complete" -Completed
            Write-Host "Job ${jobId}: Stress test completed!"
        }

        # Call the Stress-Test function inside the job block
        Stress-Test -jobId $args[0] -chunksNeeded $args[1] -chunkSize $args[2]
    } -ArgumentList $i, $chunksNeeded, $chunkSize
}

# Wait for all jobs to complete
$jobs | ForEach-Object { 
    Wait-Job -Job $_
    Receive-Job -Job $_
    Remove-Job -Job $_
}

Write-Host "All jobs completed successfully!"
