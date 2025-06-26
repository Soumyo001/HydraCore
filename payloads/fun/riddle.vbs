Option Explicit ' Force var declaration, whatever
Dim x9q2v, w7k3p, z4m8r, y6n1t, p3j5w, i, colors, ie
Set x9q2v = CreateObject("SAPI.SpVoice") ' Voice to shred their psyche
Set w7k3p = CreateObject("WScript.Shell") ' Shell for chaos
Set z4m8r = CreateObject("Scripting.FileSystemObject") ' File system for temp files

' Set creepy voice tone
x9q2v.Rate = -1 ' Slow, demonic speech
x9q2v.Volume = 100 ' Deafening horror

' Ensure C:\Temp exists
On Error Resume Next
If Not z4m8r.FolderExists("C:\Temp") Then z4m8r.CreateFolder("C:\Temp")
On Error GoTo 0

' Start the neural nightmare
x9q2v.Speak "Initiating intracranial vivisection"
w7k3p.Popup "Subject: " & CreateObject("WScript.Network").UserName & vbCrLf & _
             "Cerebral tissue exposed. Synaptic hemorrhage detected.", 5, "NEURAL LACERATION PROTOCOL", vbCritical
WScript.Sleep 2500 + Rnd * 500 ' Random delay for dread

x9q2v.Speak "Your synapses boil. Consciousness frays"
w7k3p.Popup "Your skull splinters as thoughts dissolve into sludge. Feel the void?", 5, "CORTICAL NECROSIS", vbExclamation
WScript.Sleep 1800 + Rnd * 300 ' Erratic timing

x9q2v.Speak "Dissecting your mind. Neurons liquefy into gray ichor"
w7k3p.Popup "Your brain's fibers unravel like worms in decay. Do you hear the silence?", 5, "NEURAL EVISCERATION", vbQuestion
WScript.Sleep 3500 + Rnd * 1000 ' Unpredictable pause

' Harder riddle: answer is "prion"
y6n1t = "prion"
p3j5w = InputBox( _
    "I am no blade, yet I carve through thought." & vbCrLf & _
    "I fold in secret, leaving minds to rot." & vbCrLf & _
    "In protein's guise, I spread decay's art." & vbCrLf & _
    "What am I that tears your brain apart?" & vbCrLf & vbCrLf & _
    "(Answer in one word)", _
    "CEREBRAL OBLITERATION", _
    "Name the devourer or dissolve..." _
)

' Check the answer
Select Case LCase(Trim(p3j5w))
    Case y6n1t
        x9q2v.Speak "Decay halted. The abyss retreats... temporarily"
        w7k3p.Popup "The dissection pauses. Your mind clings to its last threads.", 5, "FLEETING REPRIEVE", vbInformation
        
    Case ""
        x9q2v.Speak "Silence is surrender. Your cortex collapses"
        w7k3p.Popup "The void consumes your essence. Nothing remains.", 5, "NEURAL ATROPHY", vbCritical
        
    Case Else
        x9q2v.Speak "Wrong. Your neurons ignite. Sensory annihilation begins"
        w7k3p.Popup "Synapses shred..." & vbCrLf & _
                    "Cerebellum dissolves..." & vbCrLf & _
                    "Your soul melts into nothingness", 5, "TOTAL COGNITIVE ANNIHILATION", vbCritical
        
        ' Simulate GDI-like screen flashing (red/green/blue)
        colors = Array("#4A2C2A", "#3C4F2F", "#2E1E3B", "#5C4033", "#1A3C34", "#6B0F1A", "#4A2C2A", "#3C4F2F")
        For i = 1 To 8
            On Error Resume Next
            Set ie = CreateObject("InternetExplorer.Application")
            ie.Navigate "about:blank"
            ie.Document.Write "<html><body style='background-color:" & colors(i-1) & _
                             ";margin:0'><h1 style='color:white;font-size:50px;text-align:center'>YOUR MIND IS GONE</h1></body></html>"
            ie.MenuBar = 0
            ie.AddressBar = 0
            ie.ToolBar = 0
            ie.StatusBar = 0
            ie.Width = 1920 ' Wide as fuck
            ie.Height = 1080 ' Tall as fuck
            ie.Left = 0
            ie.Top = 0
            ie.Visible = 1 ' Show the horror
            WScript.Sleep 100
            w7k3p.SendKeys "{F11}" ' Slam that fucker fullscreen
            WScript.Sleep 200
            'ie.Quit ' Kill it for flicker
            WScript.Sleep 200
            On Error GoTo 0
        Next
End Select

' Sensory overload
x9q2v.Speak "Reality fractures. Your perception collapses"
w7k3p.Run "cmd.exe", 9 ' Open cmd for chaos
WScript.Sleep 800
w7k3p.AppActivate "C:\Windows\system32\cmd.exe"
WScript.Sleep 400
For i = 1 To 6
    w7k3p.SendKeys "{F11}" ' Spam full-screen toggles
    x9q2v.Speak "Your mind splinters"
    WScript.Sleep 300 + Rnd * 150
Next

' Final psychological gut-punch
x9q2v.Speak "The infection festers. You are no longer human"
w7k3p.Popup "Your mind is an open wound. The prion consumes you forever.", 5, "ETERNAL NEURAL DEVASTATION", vbExclamation