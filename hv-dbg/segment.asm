; https://revers.engineering/day-4-vmcs-segmentation-ops/

PUBLIC __read_ldtr
PUBLIC __read_tr
PUBLIC __read_cs
PUBLIC __read_ss
PUBLIC __read_ds
PUBLIC __read_es
PUBLIC __read_fs
PUBLIC __read_gs
PUBLIC __vmx_save_state
PUBLIC __vmx_exit_and_restore_state
PUBLIC __get_gdt_base
PUBLIC GetGdtBase
PUBLIC GetIdtBase
PUBLIC GetRflags

EXTERN stack_pointer_to_return:QWORD
EXTERN base_pointer_to_return:QWORD

EXTERN MainVmexitHandler:PROC
EXTERN VmResumeInstruction:PROC

.code _text

__read_ldtr proc
        sldt    ax
        ret
__read_ldtr endp

__read_tr proc
        str     ax
        ret
__read_tr endp

__read_cs proc
        mov     ax, cs
        ret
__read_cs endp

__read_ss proc
        mov     ax, ss
        ret
__read_ss endp

__read_ds proc
        mov     ax, ds
        ret
__read_ds endp

__read_es proc
        mov     ax, es
        ret
__read_es endp

__read_fs proc
        mov     ax, fs
        ret
__read_fs endp

__read_gs proc
        mov     ax, gs
        ret
__read_gs endp

__get_gdt_base PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

__get_gdt_base ENDP

__vmx_save_state proc
        mov stack_pointer_to_return, rsp
        mov base_pointer_to_return, rbp
        ret
__vmx_save_state endp

__vmx_exit_and_restore_state proc
        VMXOFF  ; turn it off before existing
	
	MOV RSP, stack_pointer_to_return
	MOV RBP, base_pointer_to_return
	
	; make rsp point to a correct return point
	ADD RSP, 8
	
	; return True

	XOR RAX, RAX
	MOV RAX, 1
	
	; return section
	
	MOV     RBX, [RSP+28h+8h]
	MOV     RSI, [RSP+28h+10h]
	ADD     RSP, 020h
	POP     RDI
	
	RET
__vmx_exit_and_restore_state endp

AsmVmexitHandler PROC

    PUSH R15
    PUSH R14
    PUSH R13
    PUSH R12
    PUSH R11
    PUSH R10
    PUSH R9
    PUSH R8        
    PUSH RDI
    PUSH RSI
    PUSH RBP
    PUSH RBP	; RSP
    PUSH RBX
    PUSH RDX
    PUSH RCX
    PUSH RAX	

	MOV RCX, RSP		; GuestRegs
	SUB	RSP, 28h

	CALL	MainVmexitHandler
	ADD	RSP, 28h	

	POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP		; RSP
    POP RBP
    POP RSI
    POP RDI 
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

	SUB RSP, 0100h ; to avoid error in future functions
	
    JMP VmResumeInstruction
	
AsmVmexitHandler ENDP

;------------------------------------------------------------------------

GetGdtLimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		AX, WORD PTR GDTR[0]

	RET

GetGdtLimit ENDP

;------------------------------------------------------------------------

GetIdtLimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

GetIdtLimit ENDP

;------------------------------------------------------------------------

GetRflags PROC

	PUSHFQ
	POP		RAX
	RET

GetRflags ENDP

;------------------------------------------------------------------------

GetGdtBase PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

GetGdtBase ENDP

GetIdtBase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

GetIdtBase ENDP

END