; Opaque013 slots: no guessed prototype, stack adjustment or captured target.
; Proxy layout is statically asserted by steam_observer_dispatch.h.
option casemap:none
.code
RS2_TAIL MACRO slot
PUBLIC Rs2ObserverThunk&slot
Rs2ObserverThunk&slot PROC
    mov rcx, qword ptr [rcx + 8]
    mov rax, qword ptr [rcx]
    jmp qword ptr [rax + slot * 8]
Rs2ObserverThunk&slot ENDP
ENDM
RS2_TAIL 0
RS2_TAIL 1
RS2_TAIL 2
RS2_TAIL 3
RS2_TAIL 4
RS2_TAIL 5
RS2_TAIL 7
RS2_TAIL 9
RS2_TAIL 10
RS2_TAIL 11
RS2_TAIL 13
RS2_TAIL 14
RS2_TAIL 15
RS2_TAIL 16
RS2_TAIL 17
RS2_TAIL 18
RS2_TAIL 19
RS2_TAIL 21
RS2_TAIL 22
RS2_TAIL 23
RS2_TAIL 24
RS2_TAIL 25
RS2_TAIL 26
RS2_TAIL 28
RS2_TAIL 31
RS2_TAIL 32
RS2_TAIL 33
RS2_TAIL 34
RS2_TAIL 35
RS2_TAIL 36
RS2_TAIL 37
RS2_TAIL 38
RS2_TAIL 41
RS2_TAIL 42
RS2_TAIL 43
END
