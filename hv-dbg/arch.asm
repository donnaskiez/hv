
; custom intrinsic functions

PUBLIC __readcs
PUBLIC __readds
PUBLIC __reades
PUBLIC __readss
PUBLIC __readfs
PUBLIC __readgs
PUBLIC __readldtr
PUBLIC __readtr
PUBLIC __readgdtbase
PUBLIC __readidtbase
PUBLIC __getgdtlimit
PUBLIC __getidtlimit
PUBLIC __readrflags
PUBLIC __readmsr
PUBLIC __writemsr

PUBLIC __writecr0 
PUBLIC __writecr4

PUBLIC AsmReloadGdtr
PUBLIC AsmReloadIdtr

; standard vmm handler functions

PUBLIC SaveStateAndVirtualizeCore
PUBLIC VmexitHandler
PUBLIC VmxRestoreState
PUBLIC AsmVmxVmcall

; extern functions

EXTERN VmExitDispatcher:PROC
EXTERN VirtualizeCore:PROC

EXTERN VmmReadGuestRip:PROC
EXTERN VmmReadGuestRsp:PROC

.code _text

SAVE_GP macro

	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8        
	push rdi
	push rsi
	push rbp
	push rbp
	push rbx
	push rdx
	push rcx
	push rax

endm

RESTORE_GP macro

	pop rax
	pop rcx
	pop rdx
	pop rbx
	pop rbp
	pop rbp
	pop rsi
	pop rdi 
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15

endm

SAVE_FP macro

	sub     rsp, 60h

	vmovups  xmmword ptr [rsp +  0h], xmm0
	vmovups  xmmword ptr [rsp + 10h], xmm1
	vmovups  xmmword ptr [rsp + 20h], xmm2
	vmovups  xmmword ptr [rsp + 30h], xmm3
	vmovups  xmmword ptr [rsp + 40h], xmm4
	vmovups  xmmword ptr [rsp + 50h], xmm5

endm

RESTORE_FP macro

        vmovups  xmm0, xmmword ptr [rsp +  0h]
        vmovups  xmm1, xmmword ptr [rsp + 10h]
        vmovups  xmm2, xmmword ptr [rsp + 20h]
        vmovups  xmm3, xmmword ptr [rsp + 30h]
        vmovups  xmm4, xmmword ptr [rsp + 40h]
        vmovups  xmm5, xmmword ptr [rsp + 50h]
	
        add     rsp, 60h

endm

VmexitHandler PROC

	push 0		; ensure the stack is aligned

	pushfq		; push eflags

	SAVE_GP		; save general purpose registers	
	
	; save floating point registers
	; vmovups allows us to store them in an unaligned address
	; which is not ideal and should be fixed.

	SAVE_FP

	; first argument for our exit handler is the guest register state, 
	; so store the base of the stack in rcx

	mov rcx, rsp

	sub	rsp, 20h		; allocate some space for the shadow stack

	CALL	VmExitDispatcher	; call our vm exit dispatcher	

	add	rsp, 20h		; increment stack pointer to free our shadow stack space

	cmp al, 1			; check if the return value from our exit dispatcher is 1 (true)

	je ExitVmx			; jump to ExitVmx routine if we returned true

	RESTORE_FP			; restore fp registers
	
	RESTORE_GP			; restore gp registers

	popfq				; restore eflags 

	vmresume			; resume vmx execution
	
VmexitHandler ENDP

ExitVmx PROC

	sub rsp, 020h       ; shadow space

	call VmmReadGuestRsp

	add rsp, 020h       ; remove for shadow space

	mov [rsp+0e8h], rax  ; now, rax contains rsp

	sub rsp, 020h       ; shadow space

	call VmmReadGuestRip

	add rsp, 020h       ; remove for shadow space

	mov rdx, rsp        ; save current rsp

	mov rbx, [rsp+0e8h] ; read rsp again

	mov rsp, rbx

	push rax            ; push the return address as we changed the stack, we push
			; it to the new stack

	mov rsp, rdx        ; restore previous rsp
                        
	sub rbx,08h         ; we push sth, so we have to add (sub) +8 from previous stack
				; also rbx already contains the rsp
	mov [rsp+0e8h], rbx ; move the new pointer to the current stack

	RESTORE_FP

	RESTORE_GP

	popfq

	pop		rsp     ; restore rsp

	ret             ; jump back to where we called Vmcall

ExitVmx ENDP

; No need to raise the irql as this routine run at IPI_LEVEL 

SaveStateAndVirtualizeCore PROC PUBLIC

	SAVE_GP

	sub rsp, 28h
	mov rdx, rsp
	call VirtualizeCore	
	ret

SaveStateAndVirtualizeCore ENDP 

; Restores the state of the registers pushed before we virtualized the core

VmxRestoreState PROC

	add rsp, 28h

	RESTORE_GP
	
	ret
	
VmxRestoreState ENDP

__readgdtbase PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

__readgdtbase ENDP

__readcs PROC

	MOV		RAX, CS
	RET

__readcs ENDP

__readds PROC

	MOV		RAX, DS
	RET

__readds ENDP

__reades PROC

	MOV		RAX, ES
	RET

__reades ENDP

__readss PROC

	MOV		RAX, SS
	RET

__readss ENDP

__readfs PROC

	MOV		RAX, FS
	RET

__readfs ENDP

__readgs PROC

	MOV		RAX, GS
	RET

__readgs ENDP

__readldtr PROC

	SLDT	RAX
	RET

__readldtr ENDP

__readtr PROC

	STR		RAX
	RET

__readtr ENDP

__readidtbase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

__readidtbase ENDP

__getgdtlimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		AX, WORD PTR GDTR[0]

	RET

__getgdtlimit ENDP

__getidtlimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

__getidtlimit ENDP

__readrflags PROC

	PUSHFQ
	POP		RAX
	RET

__readrflags ENDP

__readmsr PROC

	RDMSR
	SHL		RDX, 32
	OR		RAX, RDX

	RET

__readmsr ENDP

__writemsr PROC

	MOV		RAX, RDX
	SHR		RDX, 32
	WRMSR
	RET

__writemsr ENDP

__writecr0 PROC

	mov cr0, rcx
	ret

__writecr0 ENDP

__writecr4 PROC

	mov cr4, rcx
	ret

__writecr4 ENDP

;------------------------------------------------------------------------

; AsmReloadGdtr (PVOID GdtBase (rcx), ULONG GdtLimit (rdx) );

AsmReloadGdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lgdt	fword ptr [rsp+6]	; do not try to modify stack selector with this ;)
	pop		rax
	pop		rax
	ret
AsmReloadGdtr ENDP

;------------------------------------------------------------------------

; AsmReloadIdtr (PVOID IdtBase (rcx), ULONG IdtLimit (rdx) );

AsmReloadIdtr PROC
	push	rcx
	shl		rdx, 48
	push	rdx
	lidt	fword ptr [rsp+6]
	pop		rax
	pop		rax
	ret
AsmReloadIdtr ENDP

AsmVmxVmcall PROC
    
    ; We change r10 to HVFS Hex ASCII and r11 to VMCALL Hex ASCII and r12 to NOHYPERV Hex ASCII so we can make sure that the calling Vmcall comes
    ; from our hypervisor and we're resposible for managing it, otherwise it has to be managed by Hyper-V
    pushfq
    push    r10
    push    r11
    push    r12
    mov     r10, 48564653H          ; [HVFS]
    mov     r11, 564d43414c4cH      ; [VMCALL]
    mov     r12, 4e4f485950455256H   ; [NOHYPERV]
    vmcall                          ; VmxVmcallHandler(UINT64 VmcallNumber, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3)
    pop     r12
    pop     r11
    pop     r10
    popfq
    ret                             ; Return type is NTSTATUS and it's on RAX from the previous function, no need to change anything

AsmVmxVmcall ENDP

END