; Inert machine-ABI driver. No Steam library is linked or executed.
option casemap:none
EXTERN Rs2AbiRecord:BYTE
.code
RS2_FAKE MACRO slot
PUBLIC Rs2AbiFake&slot
Rs2AbiFake&slot PROC
    inc qword ptr [Rs2AbiRecord]
    mov qword ptr [Rs2AbiRecord + 8], slot
    mov qword ptr [Rs2AbiRecord + 16], rcx
    mov qword ptr [Rs2AbiRecord + 24], rdx
    mov qword ptr [Rs2AbiRecord + 32], r8
    mov qword ptr [Rs2AbiRecord + 40], r9
    mov rax, qword ptr [rsp + 28h]
    mov qword ptr [Rs2AbiRecord + 48], rax
    mov rax, qword ptr [rsp + 30h]
    mov qword ptr [Rs2AbiRecord + 56], rax
    movq qword ptr [Rs2AbiRecord + 64], xmm1
    movq qword ptr [Rs2AbiRecord + 72], xmm2
    movq qword ptr [Rs2AbiRecord + 80], xmm3
    mov eax, slot
    add rax, 1000h
    ret
Rs2AbiFake&slot ENDP
ENDM
RS2_FAKE 0
RS2_FAKE 1
RS2_FAKE 2
RS2_FAKE 3
RS2_FAKE 4
RS2_FAKE 5
RS2_FAKE 6
RS2_FAKE 7
RS2_FAKE 8
RS2_FAKE 9
RS2_FAKE 10
RS2_FAKE 11
RS2_FAKE 12
RS2_FAKE 13
RS2_FAKE 14
RS2_FAKE 15
RS2_FAKE 16
RS2_FAKE 17
RS2_FAKE 18
RS2_FAKE 19
RS2_FAKE 20
RS2_FAKE 21
RS2_FAKE 22
RS2_FAKE 23
RS2_FAKE 24
RS2_FAKE 25
RS2_FAKE 26
RS2_FAKE 27
RS2_FAKE 28
RS2_FAKE 29
RS2_FAKE 30
RS2_FAKE 31
RS2_FAKE 32
RS2_FAKE 33
RS2_FAKE 34
RS2_FAKE 35
RS2_FAKE 36
RS2_FAKE 37
RS2_FAKE 38
RS2_FAKE 39
RS2_FAKE 40
RS2_FAKE 41
RS2_FAKE 42
RS2_FAKE 43

PUBLIC Rs2AbiInvoke
; (proxy, slot): machine-level opaque call, with register/stack/XMM sentinels.
Rs2AbiInvoke PROC FRAME
    sub rsp, 38h
    .allocstack 38h
    .endprolog
    mov rax, qword ptr [rcx]
    mov rax, qword ptr [rax + rdx * 8]
    mov rdx, 1122334455667788h
    mov r8, 2233445566778899h
    mov r9, 33445566778899aah
    mov qword ptr [rsp + 20h], 12345678h
    mov qword ptr [rsp + 28h], 23456789h
    movq xmm1, rdx
    movq xmm2, r8
    movq xmm3, r9
    call rax
    add rsp, 38h
    ret
Rs2AbiInvoke ENDP

PUBLIC Rs2AbiFactoryCall, Rs2AbiFactoryReturn
; (target,user,version), with a stable exported original return address.
Rs2AbiFactoryCall PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, rcx
    mov ecx, edx
    mov rdx, r8
    call rax
Rs2AbiFactoryReturn LABEL BYTE
    add rsp, 28h
    ret
Rs2AbiFactoryCall ENDP

PUBLIC Rs2AbiLoggedPublisher, Rs2AbiPublisherReturn, Rs2AbiLoggedAdvertise, Rs2AbiAdvertiseReturn
Rs2AbiLoggedPublisher PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 8 * 8]
Rs2AbiPublisherReturn LABEL BYTE
    add rsp, 28h
    ret
Rs2AbiLoggedPublisher ENDP
Rs2AbiLoggedAdvertise PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, qword ptr [rcx]
    call qword ptr [rax + 8 * 8]
Rs2AbiAdvertiseReturn LABEL BYTE
    add rsp, 28h
    ret
Rs2AbiLoggedAdvertise ENDP

PUBLIC Rs2AbiHidden, Rs2AbiHiddenCall
Rs2AbiHidden PROC
    inc qword ptr [Rs2AbiRecord]
    mov qword ptr [Rs2AbiRecord + 16], rcx
    mov qword ptr [rdx], 13579bdfh
    mov qword ptr [rdx + 8], 2468ace0h
    mov rax, rdx
    ret
Rs2AbiHidden ENDP
; (proxy,resultStorage,slot), preserves member hidden-result storage in RDX.
Rs2AbiHiddenCall PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    mov rax, qword ptr [rcx]
    call qword ptr [rax + r8 * 8]
    add rsp, 28h
    ret
Rs2AbiHiddenCall ENDP

.const
PUBLIC Rs2AbiFakeTable
Rs2AbiFakeTable QWORD Rs2AbiFake0,Rs2AbiFake1,Rs2AbiFake2,Rs2AbiFake3
QWORD Rs2AbiFake4,Rs2AbiFake5,Rs2AbiFake6,Rs2AbiFake7
QWORD Rs2AbiFake8,Rs2AbiFake9,Rs2AbiFake10,Rs2AbiFake11
QWORD Rs2AbiFake12,Rs2AbiFake13,Rs2AbiFake14,Rs2AbiFake15
QWORD Rs2AbiFake16,Rs2AbiFake17,Rs2AbiFake18,Rs2AbiFake19
QWORD Rs2AbiFake20,Rs2AbiFake21,Rs2AbiFake22,Rs2AbiFake23
QWORD Rs2AbiFake24,Rs2AbiFake25,Rs2AbiFake26,Rs2AbiFake27
QWORD Rs2AbiFake28,Rs2AbiFake29,Rs2AbiFake30,Rs2AbiFake31
QWORD Rs2AbiFake32,Rs2AbiFake33,Rs2AbiFake34,Rs2AbiFake35
QWORD Rs2AbiFake36,Rs2AbiFake37,Rs2AbiFake38,Rs2AbiFake39
QWORD Rs2AbiFake40,Rs2AbiFake41,Rs2AbiFake42,Rs2AbiFake43
END
