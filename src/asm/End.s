[BITS 64]

global GetShellcodeEnd

[SECTION .text$Y]
    GetShellcodeEnd:
        call coucou

        coucou:
        pop rax
        add rax, 6
        ret       


[SECTION .text$Z]
    Leave:
        db 'R', 't', 'l', 'D', 'a', 'l', 'l', 'a' ,'s'