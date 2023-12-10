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

PUBLIC __vmx_terminate

PUBLIC SaveStateAndVirtualizeCore
PUBLIC VmexitHandler
PUBLIC VmxRestoreState

EXTERN VmExitDispatcher:PROC
EXTERN VmResumeInstruction:PROC
EXTERN VirtualizeCore:PROC

EXTERN stack_pointer_to_return:QWORD
EXTERN base_pointer_to_return:QWORD

VMX_ERROR_CODE_SUCCESS              = 0
VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
VMX_ERROR_CODE_FAILED               = 2

.code _text

VmexitHandler PROC

	; save general purpose registers

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
	
	; save floating point registers
	; vmovups allows us to store them in an unaligned address
	; which is not ideal and should be fixed.

	sub     rsp, 60h

	vmovups  xmmword ptr [rsp +  0h], xmm0
	vmovups  xmmword ptr [rsp + 10h], xmm1
	vmovups  xmmword ptr [rsp + 20h], xmm2
	vmovups  xmmword ptr [rsp + 30h], xmm3
	vmovups  xmmword ptr [rsp + 40h], xmm4
	vmovups  xmmword ptr [rsp + 50h], xmm5

	; first argument for our exit handler is the guest register state, 
	; so store the base of the stack in rcx

	mov rcx, rsp

	; allocate some space for the shadow stack

	sub	rsp, 20h

	; call our vm exit dispatcher

	CALL	VmExitDispatcher

	; increment stack pointer to free our shadow stack space	

	add	rsp, 20h	

	; restore our saved floating point registers back

        vmovups  xmm0, xmmword ptr [rsp +  0h]
        vmovups  xmm1, xmmword ptr [rsp + 10h]
        vmovups  xmm2, xmmword ptr [rsp + 20h]
        vmovups  xmm3, xmmword ptr [rsp + 30h]
        vmovups  xmm4, xmmword ptr [rsp + 40h]
        vmovups  xmm5, xmmword ptr [rsp + 50h]

	; increment stack pointer since we've restored the floating point registers
	
        add     rsp, 60h

	; pop the general purpose registers back

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
			
	; resume execution 

	jmp VmResumeInstruction
	
VmexitHandler ENDP

; No need to raise the irql as this routine run at IPI_LEVEL 

SaveStateAndVirtualizeCore PROC PUBLIC

	push RAX
	push RCX
	push RDX
	push RBX
	push RBP
	push RSI
	push RDI
	push R8
	push R9
	push R10
	push R11
	push R12
	push R13
	push R14
	push R15
	SUB RSP, 28h
	MOV RDX, RSP
	CALL VirtualizeCore	
	RET

SaveStateAndVirtualizeCore ENDP 

; Restores the state of the registers pushed before we virtualized the core

VmxRestoreState PROC

	ADD RSP, 28h
	pop R15
	pop R14
	pop R13
	pop R12
	pop R11
	pop R10
	pop R9
	pop R8
	pop RDI
	pop RSI
	pop RBP
	pop RBX
	pop RDX
	pop RCX
	pop RAX
	
	RET
	
VmxRestoreState ENDP

__vmx_terminate PROC PUBLIC

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
	
__vmx_terminate ENDP 

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

END