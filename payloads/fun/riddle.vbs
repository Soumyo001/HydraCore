Option Explicit ' Force var declaration, whatever
Dim x9q2v, w7k3p, z4m8r, y6n1t, p3j5w, i
Set x9q2v = CreateObject("SAPI.SpVoice") ' Voice to fuck with their head
Set w7k3p = CreateObject("WScript.Shell") ' Shell for chaos
Set z4m8r = CreateObject("Scripting.FileSystemObject") ' File system for temp files

' Set creepy voice tone
x9q2v.Rate = -1 ' Slow, ominous speech
x9q2v.Volume = 100 ' Loud as fuck

' Start the neural horror show
x9q2v.Speak "Initiating cortical vivisection"
w7k3p.Popup "Subject: " & CreateObject("WScript.Network").UserName & vbCrLf & _
             "Brain tissue scan active. Synapses exposed.", 5, "NEURAL INCISION PROTOCOL", vbCritical
WScript.Sleep 2500 + Rnd * 500 ' Random delay for unease

x9q2v.Speak "Cerebral veins rupturing. Memory decay imminent"
w7k3p.Popup "Your thoughts bleed into the void. Can you feel your skull fissuring?", 5, "HEMORRHAGIC COLLAPSE", vbExclamation
WScript.Sleep 1800 + Rnd * 300 ' Erratic timing

x9q2v.Speak "Dissecting neural pathways. Gray matter liquefying"
w7k3p.Popup "Your neurons unravel like threads from a rotting tapestry. Do you sense the absence?", 5, "CORTICAL DISSOLUTION", vbQuestion
WScript.Sleep 3500 + Rnd * 1000 ' Longer, unpredictable pause

' Harder riddle with brain-horror theme
y6n1t = "prion"
p3j5w = InputBox( _
    "I am no blade, yet I carve through thought." & vbCrLf & _
    "I fold in secret, leaving minds to rot." & vbCrLf & _
    "In protein's guise, I spread decay's art." & vbCrLf & _
    "What am I that tears your brain apart?" & vbCrLf & vbCrLf & _
    "(Answer in one word)", _
    "CEREBRAL OBLITERATION", _
    "Speak the truth or dissolve..." _
)

' Check the answer
Select Case LCase(Trim(p3j5w))
    Case y6n1t
        x9q2v.Speak "Decay paused. The void retreats... for now"
        w7k3p.Popup "The dissection halts. Your mind clings to its last fragments.", 5, "TEMPORARY REPRIEVE", vbInformation
        
    Case ""
        x9q2v.Speak "Silence is consumption. Your cortex collapses"
        w7k3p.Popup "The void swallows your thoughts. Nothing remains.", 5, "NEURAL NECROSIS", vbCritical
        
    Case Else
        x9q2v.Speak "Wrong. Your synapses burn. Sensory annihilation begins"
        w7k3p.Popup "Axons shred..." & vbCrLf & _
                    "Cerebellum melts..." & vbCrLf & _
                    "Your soul frays into nothingness", 5, "TOTAL COGNITIVE ANNIHILATION", vbCritical
        
        ' Simulate GDI-like screen flashing (red/green/blue)
        If Not z4m8r.FolderExists("C:\Temp") Then z4m8r.CreateFolder("C:\Temp")
        For i = 1 To 5
            ' Create temp HTML files for colored backgrounds
            Set z4m8r = z4m8r.CreateTextFile("C:\Temp\flash" & i & ".htm", True)
            z4m8r.WriteLine "<html><body style='background-color:" & Choose(i, "red", "green", "blue", "red", "green") & _
                           ";margin:0'><h1 style='color:white;font-size:50px;text-align:center'>YOUR MIND IS GONE</h1></body></html>"
            z4m8r.Close
            w7k3p.Run "C:\Temp\flash" & i & ".htm", 3 ' Maximize window
            WScript.Sleep 300
            w7k3p.Run "taskkill /IM iexplore.exe", 0, True ' Kill browser to "flash"
            WScript.Sleep 200
        Next
        z4m8r.DeleteFile "C:\Temp\flash*.htm" ' Clean up
End Select

' Final sensory overload
x9q2v.Speak "Sensory matrix destabilizing. Reality fractures"
w7k3p.Run "cmd.exe", 9 ' Open cmd for chaos
WScript.Sleep 1000
w7k3p.AppActivate "C:\Windows\system32\cmd.exe"
WScript.Sleep 500
For i = 1 To 5
    w7k3p.SendKeys "{F11}" ' Spam full-screen toggles
    x9q2v.Speak "Your perception splinters"
    WScript.Sleep 400 + Rnd * 200
Next

' Final nail in the psyche
x9q2v.Speak "The incision festers. You will never wake whole"
w7k3p.Popup "Your mind is an open wound. The dissection never ends.", 5, "ETERNAL NEURAL LACERATION", vbExclamation