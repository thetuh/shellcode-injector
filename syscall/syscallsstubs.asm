.686 
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 
.CODE

; x64 for x86

EXTERN SW2_GetSyscallNumber: PROC

EXTERN internal_cleancall_wow64_gate: PROC

NtAccessCheck PROC
	push ebp
	mov ebp, esp
	push 0C45B3507h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
	push ebp
	mov ebp, esp
	push 08DAEE74Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
	push ebp
	mov ebp, esp
	push 018AF0340h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
	push ebp
	mov ebp, esp
	push 0A36D8931h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
	push ebp
	mov ebp, esp
	push 064DED283h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
	push ebp
	mov ebp, esp
	push 0FA60878Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCallbackReturn ENDP

NtReadFile PROC
	push ebp
	mov ebp, esp
	push 0B5139A5Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReadFile ENDP

NtDeviceIoControlFile PROC
	push ebp
	mov ebp, esp
	push 0D876A360h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeviceIoControlFile ENDP

NtWriteFile PROC
	push ebp
	mov ebp, esp
	push 002981C2Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWriteFile ENDP

NtRemoveIoCompletion PROC
	push ebp
	mov ebp, esp
	push 0930C939Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
	push ebp
	mov ebp, esp
	push 018084D38h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
	push ebp
	mov ebp, esp
	push 062F27B76h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
	push ebp
	mov ebp, esp
	push 01AB11324h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReplyPort ENDP

NtSetInformationThread PROC
	push ebp
	mov ebp, esp
	push 0554A61D5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationThread ENDP

NtSetEvent PROC
	push ebp
	mov ebp, esp
	push 0298B301Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetEvent ENDP

NtClose PROC
	push ebp
	mov ebp, esp
	push 0049F2513h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtClose ENDP

NtQueryObject PROC
	push ebp
	mov ebp, esp
	push 0F8C80384h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryObject ENDP

NtQueryInformationFile PROC
	push ebp
	mov ebp, esp
	push 078DC7476h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationFile ENDP

NtOpenKey PROC
	push ebp
	mov ebp, esp
	push 064D19FB2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenKey ENDP

NtEnumerateValueKey PROC
	push ebp
	mov ebp, esp
	push 0964FE5B4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtEnumerateValueKey ENDP

NtFindAtom PROC
	push ebp
	mov ebp, esp
	push 0DB5FEA9Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFindAtom ENDP

NtQueryDefaultLocale PROC
	push ebp
	mov ebp, esp
	push 0663754A3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryDefaultLocale ENDP

NtQueryKey PROC
	push ebp
	mov ebp, esp
	push 003C6EE5Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryKey ENDP

NtQueryValueKey PROC
	push ebp
	mov ebp, esp
	push 02EFF5D05h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 00D9F1913h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
	push ebp
	mov ebp, esp
	push 0822EA9B3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
	push ebp
	mov ebp, esp
	push 08F42C8D7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
	push ebp
	mov ebp, esp
	push 0DBC4349Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWriteFileGather ENDP

NtCreateKey PROC
	push ebp
	mov ebp, esp
	push 0099D4C4Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateKey ENDP

NtFreeVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 0039E1B01h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
	push ebp
	mov ebp, esp
	push 010B2392Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
	push ebp
	mov ebp, esp
	push 080BED298h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReleaseMutant ENDP

NtQueryInformationToken PROC
	push ebp
	mov ebp, esp
	push 00B990506h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
	push ebp
	mov ebp, esp
	push 0A0F166BBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 0C985E520h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
	push ebp
	mov ebp, esp
	push 02B9F1114h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
	push ebp
	mov ebp, esp
	push 08EA243F4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationThread ENDP

NtOpenProcess PROC
	push ebp
	mov ebp, esp
	push 04DD34C5Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenProcess ENDP

NtSetInformationFile PROC
	push ebp
	mov ebp, esp
	push 0E5B6CB63h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationFile ENDP

NtMapViewOfSection PROC
	push ebp
	mov ebp, esp
	push 0C348C3DAh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
	push ebp
	mov ebp, esp
	push 0A8A8A93Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
	push ebp
	mov ebp, esp
	push 008C02E49h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
	push ebp
	mov ebp, esp
	push 00785DBD1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
	push ebp
	mov ebp, esp
	push 043DF545Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
	push ebp
	mov ebp, esp
	push 02E8C321Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
	push ebp
	mov ebp, esp
	push 003A00D3Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
	push ebp
	mov ebp, esp
	push 00A8D7876h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
	push ebp
	mov ebp, esp
	push 0900392B8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
	push ebp
	mov ebp, esp
	push 071DA5F7Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
	push ebp
	mov ebp, esp
	push 0AEBEBF24h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtEnumerateKey ENDP

NtOpenFile PROC
	push ebp
	mov ebp, esp
	push 0DD7AFB39h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenFile ENDP

NtDelayExecution PROC
	push ebp
	mov ebp, esp
	push 0D7B017C2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
	push ebp
	mov ebp, esp
	push 032B8BA9Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
	push ebp
	mov ebp, esp
	push 04E9E684Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySystemInformation ENDP

NtOpenSection PROC
	push ebp
	mov ebp, esp
	push 056105A8Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenSection ENDP

NtQueryTimer PROC
	push ebp
	mov ebp, esp
	push 0EBA776ABh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryTimer ENDP

NtFsControlFile PROC
	push ebp
	mov ebp, esp
	push 01CBA4F8Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 0B018A6B4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
	push ebp
	mov ebp, esp
	push 00A942A42h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
	push ebp
	mov ebp, esp
	push 00A379A1Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
	push ebp
	mov ebp, esp
	push 02BB9C0ECh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryAttributesFile ENDP

NtClearEvent PROC
	push ebp
	mov ebp, esp
	push 0D289D502h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtClearEvent ENDP

NtReadVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 047D37B57h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReadVirtualMemory ENDP

NtOpenEvent PROC
	push ebp
	mov ebp, esp
	push 0014B06C0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
	push ebp
	mov ebp, esp
	push 0059B7696h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
	push ebp
	mov ebp, esp
	push 0A580F3A4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDuplicateToken ENDP

NtContinue PROC
	push ebp
	mov ebp, esp
	push 042C6816Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtContinue ENDP

NtQueryDefaultUILanguage PROC
	push ebp
	mov ebp, esp
	push 03B9C0A06h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
	push ebp
	mov ebp, esp
	push 0389B76B1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueueApcThread ENDP

NtYieldExecution PROC
	push ebp
	mov ebp, esp
	push 0CB1FE84Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtYieldExecution ENDP

NtAddAtom PROC
	push ebp
	mov ebp, esp
	push 094C1936Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAddAtom ENDP

NtCreateEvent PROC
	push ebp
	mov ebp, esp
	push 076A44700h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
	push ebp
	mov ebp, esp
	push 06C3CBC8Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
	push ebp
	mov ebp, esp
	push 00EAC1001h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateSection ENDP

NtFlushBuffersFile PROC
	push ebp
	mov ebp, esp
	push 0BF772D41h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
	push ebp
	mov ebp, esp
	push 04F9965DFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
	push ebp
	mov ebp, esp
	push 0838DD751h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateProcessEx ENDP

NtCreateThread PROC
	push ebp
	mov ebp, esp
	push 07D25AD99h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateThread ENDP

NtIsProcessInJob PROC
	push ebp
	mov ebp, esp
	push 0652EB71Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 001911B13h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtProtectVirtualMemory ENDP

NtQuerySection PROC
	push ebp
	mov ebp, esp
	push 006DC0841h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySection ENDP

NtResumeThread PROC
	push ebp
	mov ebp, esp
	push 00D2D038Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtResumeThread ENDP

NtTerminateThread PROC
	push ebp
	mov ebp, esp
	push 04EEE5467h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtTerminateThread ENDP

NtReadRequestData PROC
	push ebp
	mov ebp, esp
	push 062FC724Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReadRequestData ENDP

NtCreateFile PROC
	push ebp
	mov ebp, esp
	push 0AA9825B3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateFile ENDP

NtQueryEvent PROC
	push ebp
	mov ebp, esp
	push 0C88E448Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryEvent ENDP

NtWriteRequestData PROC
	push ebp
	mov ebp, esp
	push 02084CC8Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
	push ebp
	mov ebp, esp
	push 0829C9002h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
	push ebp
	mov ebp, esp
	push 034AB2E06h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 16h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
	push ebp
	mov ebp, esp
	push 031A1FEE3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
	push ebp
	mov ebp, esp
	push 067584C07h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationObject ENDP

NtCancelIoFile PROC
	push ebp
	mov ebp, esp
	push 0349DC0D6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCancelIoFile ENDP

NtTraceEvent PROC
	push ebp
	mov ebp, esp
	push 038BF1F2Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtTraceEvent ENDP

NtPowerInformation PROC
	push ebp
	mov ebp, esp
	push 082099CB9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPowerInformation ENDP

NtSetValueKey PROC
	push ebp
	mov ebp, esp
	push 039E4DC86h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetValueKey ENDP

NtCancelTimer PROC
	push ebp
	mov ebp, esp
	push 005BA93BEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCancelTimer ENDP

NtSetTimer PROC
	push ebp
	mov ebp, esp
	push 02096B195h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetTimer ENDP

NtAccessCheckByType PROC
	push ebp
	mov ebp, esp
	push 05EF96A36h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
	push ebp
	mov ebp, esp
	push 025B92B23h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
	push ebp
	mov ebp, esp
	push 0165116CEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 16h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
	push ebp
	mov ebp, esp
	push 03B942F24h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 17h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
	push ebp
	mov ebp, esp
	push 0D89B3687h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
	push ebp
	mov ebp, esp
	push 089ABB72Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAddAtomEx ENDP

NtAddBootEntry PROC
	push ebp
	mov ebp, esp
	push 0099CE2FEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAddBootEntry ENDP

NtAddDriverEntry PROC
	push ebp
	mov ebp, esp
	push 00995190Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
	push ebp
	mov ebp, esp
	push 01CA80A21h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
	push ebp
	mov ebp, esp
	push 009910D07h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 16h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
	push ebp
	mov ebp, esp
	push 07ADA206Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlertResumeThread ENDP

NtAlertThread PROC
	push ebp
	mov ebp, esp
	push 03C073691h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
	push ebp
	mov ebp, esp
	push 06FB00378h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
	push ebp
	mov ebp, esp
	push 045B13D2Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
	push ebp
	mov ebp, esp
	push 0249E0DC3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
	push ebp
	mov ebp, esp
	push 0059C0400h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
	push ebp
	mov ebp, esp
	push 02A91E2CEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
	push ebp
	mov ebp, esp
	push 0868FC051h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
	push ebp
	mov ebp, esp
	push 065B71C39h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
	push ebp
	mov ebp, esp
	push 0A396860Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
	push ebp
	mov ebp, esp
	push 05E80BFDEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
	push ebp
	mov ebp, esp
	push 0615EDD9Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
	push ebp
	mov ebp, esp
	push 0198C3EDFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
	push ebp
	mov ebp, esp
	push 010CB361Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
	push ebp
	mov ebp, esp
	push 0DD58DDF4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
	push ebp
	mov ebp, esp
	push 00D28F143h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
	push ebp
	mov ebp, esp
	push 036AA2922h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
	push ebp
	mov ebp, esp
	push 03AA910F1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
	push ebp
	mov ebp, esp
	push 0448F2A4Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
	push ebp
	mov ebp, esp
	push 004D07937h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
	push ebp
	mov ebp, esp
	push 07EE2796Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
	push ebp
	mov ebp, esp
	push 065307C9Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
	push ebp
	mov ebp, esp
	push 0D172F2DDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
	push ebp
	mov ebp, esp
	push 024752FEBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
	push ebp
	mov ebp, esp
	push 07DA3440Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
	push ebp
	mov ebp, esp
	push 069496FEBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
	push ebp
	mov ebp, esp
	push 0D54CD5DEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
	push ebp
	mov ebp, esp
	push 03D1E2E8Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
	push ebp
	mov ebp, esp
	push 0922C6144h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
	push ebp
	mov ebp, esp
	push 0FD76E6F9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
	push ebp
	mov ebp, esp
	push 0E076E2DBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
	push ebp
	mov ebp, esp
	push 0F2340C6Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
	push ebp
	mov ebp, esp
	push 0755F4DF3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
	push ebp
	mov ebp, esp
	push 00FA93506h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
	push ebp
	mov ebp, esp
	push 09B3FF9B5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCallEnclave ENDP

NtCancelIoFileEx PROC
	push ebp
	mov ebp, esp
	push 0504BA231h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
	push ebp
	mov ebp, esp
	push 002BB8AACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
	push ebp
	mov ebp, esp
	push 0BBBF56A1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
	push ebp
	mov ebp, esp
	push 099BCBB22h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
	push ebp
	mov ebp, esp
	push 006A3000Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCommitComplete ENDP

NtCommitEnlistment PROC
	push ebp
	mov ebp, esp
	push 05FC97E7Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
	push ebp
	mov ebp, esp
	push 0144FF61Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
	push ebp
	mov ebp, esp
	push 0408A4217h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCommitTransaction ENDP

NtCompactKeys PROC
	push ebp
	mov ebp, esp
	push 0B315A882h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCompactKeys ENDP

NtCompareObjects PROC
	push ebp
	mov ebp, esp
	push 0041B70C3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCompareObjects ENDP

NtCompareSigningLevels PROC
	push ebp
	mov ebp, esp
	push 0248A241Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCompareSigningLevels ENDP

NtCompareTokens PROC
	push ebp
	mov ebp, esp
	push 017BB0CD3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCompareTokens ENDP

NtCompleteConnectPort PROC
	push ebp
	mov ebp, esp
	push 02E71DDFEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCompleteConnectPort ENDP

NtCompressKey PROC
	push ebp
	mov ebp, esp
	push 09700ACBCh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCompressKey ENDP

NtConnectPort PROC
	push ebp
	mov ebp, esp
	push 0EA8DC112h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
	push ebp
	mov ebp, esp
	push 07FF6091Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
	push ebp
	mov ebp, esp
	push 0BCB7DC63h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
	push ebp
	mov ebp, esp
	push 0EC58C48Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
	push ebp
	mov ebp, esp
	push 024D4E78Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
	push ebp
	mov ebp, esp
	push 0CE2EA924h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateEnclave ENDP

NtCreateEnlistment PROC
	push ebp
	mov ebp, esp
	push 00A410BD7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateEnlistment ENDP

NtCreateEventPair PROC
	push ebp
	mov ebp, esp
	push 004B04C65h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateEventPair ENDP

NtCreateIRTimer PROC
	push ebp
	mov ebp, esp
	push 033A00518h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
	push ebp
	mov ebp, esp
	push 03AA41A2Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
	push ebp
	mov ebp, esp
	push 008A7183Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateJobObject ENDP

NtCreateJobSet PROC
	push ebp
	mov ebp, esp
	push 0BD398F86h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
	push ebp
	mov ebp, esp
	push 07CDFA562h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
	push ebp
	mov ebp, esp
	push 09E045956h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
	push ebp
	mov ebp, esp
	push 09E54025Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
	push ebp
	mov ebp, esp
	push 07FC4B571h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateMailslotFile ENDP

NtCreateMutant PROC
	push ebp
	mov ebp, esp
	push 0872186B5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
	push ebp
	mov ebp, esp
	push 0E8482C12h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 14h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
	push ebp
	mov ebp, esp
	push 016B9C982h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreatePagingFile ENDP

NtCreatePartition PROC
	push ebp
	mov ebp, esp
	push 08AD38843h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreatePartition ENDP

NtCreatePort PROC
	push ebp
	mov ebp, esp
	push 0A6F258F1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
	push ebp
	mov ebp, esp
	push 019B5D21Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
	push ebp
	mov ebp, esp
	push 0319E3010h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateProcess ENDP

NtCreateProfile PROC
	push ebp
	mov ebp, esp
	push 036A14072h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateProfile ENDP

NtCreateProfileEx PROC
	push ebp
	mov ebp, esp
	push 07CD28AACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
	push ebp
	mov ebp, esp
	push 0991EC1D0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
	push ebp
	mov ebp, esp
	push 0029EC5D4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
	push ebp
	mov ebp, esp
	push 0CB4BF5C5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
	push ebp
	mov ebp, esp
	push 0163860C5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
	push ebp
	mov ebp, esp
	push 046BC3042h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateThreadEx ENDP

NtCreateTimer PROC
	push ebp
	mov ebp, esp
	push 074575104h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateTimer ENDP

NtCreateTimer2 PROC
	push ebp
	mov ebp, esp
	push 07022D1BDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateTimer2 ENDP

NtCreateToken PROC
	push ebp
	mov ebp, esp
	push 00C312A9Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 13h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateToken ENDP

NtCreateTokenEx PROC
	push ebp
	mov ebp, esp
	push 0B8ABF810h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 17h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateTokenEx ENDP

NtCreateTransaction PROC
	push ebp
	mov ebp, esp
	push 05CC5725Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
	push ebp
	mov ebp, esp
	push 00E2E72C4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
	push ebp
	mov ebp, esp
	push 00BA7063Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 11h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
	push ebp
	mov ebp, esp
	push 0079A21C0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
	push ebp
	mov ebp, esp
	push 025403CC4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
	push ebp
	mov ebp, esp
	push 0853A597Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
	push ebp
	mov ebp, esp
	push 0088C7A74h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
	push ebp
	mov ebp, esp
	push 0B0335121h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDebugActiveProcess ENDP

NtDebugContinue PROC
	push ebp
	mov ebp, esp
	push 01E94F9D8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDebugContinue ENDP

NtDeleteAtom PROC
	push ebp
	mov ebp, esp
	push 036A3AB92h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
	push ebp
	mov ebp, esp
	push 0099D0111h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
	push ebp
	mov ebp, esp
	push 00B960104h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
	push ebp
	mov ebp, esp
	push 047C55079h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteFile ENDP

NtDeleteKey PROC
	push ebp
	mov ebp, esp
	push 0E723055Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
	push ebp
	mov ebp, esp
	push 0C12F3BB9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
	push ebp
	mov ebp, esp
	push 096B95390h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
	push ebp
	mov ebp, esp
	push 07DE46C7Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
	push ebp
	mov ebp, esp
	push 0840E96BEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
	push ebp
	mov ebp, esp
	push 0921C9FBDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
	push ebp
	mov ebp, esp
	push 0F86AEEDBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDisableLastKnownGood ENDP

NtDisplayString PROC
	push ebp
	mov ebp, esp
	push 00EA14480h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDisplayString ENDP

NtDrawText PROC
	push ebp
	mov ebp, esp
	push 0F94CECCDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtDrawText ENDP

NtEnableLastKnownGood PROC
	push ebp
	mov ebp, esp
	push 0A4325A23h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
	push ebp
	mov ebp, esp
	push 02490514Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
	push ebp
	mov ebp, esp
	push 060C4FAEBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
	push ebp
	mov ebp, esp
	push 07E5F08A1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
	push ebp
	mov ebp, esp
	push 0E4B8EC24h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
	push ebp
	mov ebp, esp
	push 034AD1679h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtExtendSection ENDP

NtFilterBootOption PROC
	push ebp
	mov ebp, esp
	push 01A347CE4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFilterBootOption ENDP

NtFilterToken PROC
	push ebp
	mov ebp, esp
	push 0C759CDC2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFilterToken ENDP

NtFilterTokenEx PROC
	push ebp
	mov ebp, esp
	push 08A9B46DEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 14h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
	push ebp
	mov ebp, esp
	push 0043650EBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
	push ebp
	mov ebp, esp
	push 083D47089h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
	push ebp
	mov ebp, esp
	push 01FA1491Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFlushInstructionCache ENDP

NtFlushKey PROC
	push ebp
	mov ebp, esp
	push 040E45579h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
	push ebp
	mov ebp, esp
	push 00929CD7Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 0831C899Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
	push ebp
	mov ebp, esp
	push 097A4B5F4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
	push ebp
	mov ebp, esp
	push 095CFA867h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
	push ebp
	mov ebp, esp
	push 0CC90FC2Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
	push ebp
	mov ebp, esp
	push 05DC95543h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
	push ebp
	mov ebp, esp
	push 0A0AAC638h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
	push ebp
	mov ebp, esp
	push 0FFB4FD27h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
	push ebp
	mov ebp, esp
	push 00228450Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
	push ebp
	mov ebp, esp
	push 082A56FFFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
	push ebp
	mov ebp, esp
	push 0F75B0B2Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
	push ebp
	mov ebp, esp
	push 0CE55AEDEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
	push ebp
	mov ebp, esp
	push 01EBC5467h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
	push ebp
	mov ebp, esp
	push 07DA81C3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetNextProcess ENDP

NtGetNextThread PROC
	push ebp
	mov ebp, esp
	push 0F45039F1h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
	push ebp
	mov ebp, esp
	push 039EC2066h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
	push ebp
	mov ebp, esp
	push 0BA67C8ABh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
	push ebp
	mov ebp, esp
	push 01CC6286Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
	push ebp
	mov ebp, esp
	push 0F15024EBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
	push ebp
	mov ebp, esp
	push 01EAA5B8Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtImpersonateThread ENDP

NtInitializeEnclave PROC
	push ebp
	mov ebp, esp
	push 0A6BE8E3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
	push ebp
	mov ebp, esp
	push 00D47DB04h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
	push ebp
	mov ebp, esp
	push 040DD7651h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
	push ebp
	mov ebp, esp
	push 09C8AF25Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
	push ebp
	mov ebp, esp
	push 0FCFEE649h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
	push ebp
	mov ebp, esp
	push 09BA3D91Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtIsUILanguageComitted ENDP

NtListenPort PROC
	push ebp
	mov ebp, esp
	push 0523E57ACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtListenPort ENDP

NtLoadDriver PROC
	push ebp
	mov ebp, esp
	push 0917ECA53h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLoadDriver ENDP

NtLoadEnclaveData PROC
	push ebp
	mov ebp, esp
	push 0B6CF43A2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
	push ebp
	mov ebp, esp
	push 03EE52A56h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLoadHotPatch ENDP

NtLoadKey PROC
	push ebp
	mov ebp, esp
	push 0069BF5E0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLoadKey ENDP

NtLoadKey2 PROC
	push ebp
	mov ebp, esp
	push 0E69DA08Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLoadKey2 ENDP

NtLoadKeyEx PROC
	push ebp
	mov ebp, esp
	push 0557A8126h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLoadKeyEx ENDP

NtLockFile PROC
	push ebp
	mov ebp, esp
	push 02F78CE3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLockFile ENDP

NtLockProductActivationKeys PROC
	push ebp
	mov ebp, esp
	push 02DB72826h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
	push ebp
	mov ebp, esp
	push 04A6F358Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 01D952B1Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
	push ebp
	mov ebp, esp
	push 0BE925D8Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
	push ebp
	mov ebp, esp
	push 01ABA220Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtMakeTemporaryObject ENDP

NtManagePartition PROC
	push ebp
	mov ebp, esp
	push 04C98084Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtManagePartition ENDP

NtMapCMFModule PROC
	push ebp
	mov ebp, esp
	push 036BC2C38h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
	push ebp
	mov ebp, esp
	push 085BC602Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
	push ebp
	mov ebp, esp
	push 04093742Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
	push ebp
	mov ebp, esp
	push 005AB0B3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
	push ebp
	mov ebp, esp
	push 00F872514h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
	push ebp
	mov ebp, esp
	push 048EA5A42h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
	push ebp
	mov ebp, esp
	push 02AA9DCD7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
	push ebp
	mov ebp, esp
	push 09A8EB9D4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
	push ebp
	mov ebp, esp
	push 00F553C92h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 12h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
	push ebp
	mov ebp, esp
	push 0278C7940h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 8h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
	push ebp
	mov ebp, esp
	push 079E51BF3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenEnlistment ENDP

NtOpenEventPair PROC
	push ebp
	mov ebp, esp
	push 01631DA63h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
	push ebp
	mov ebp, esp
	push 0C88E885Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
	push ebp
	mov ebp, esp
	push 00A26F94Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenJobObject ENDP

NtOpenKeyEx PROC
	push ebp
	mov ebp, esp
	push 06D623BBDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
	push ebp
	mov ebp, esp
	push 056DF5460h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
	push ebp
	mov ebp, esp
	push 062BD3666h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
	push ebp
	mov ebp, esp
	push 0C803D790h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
	push ebp
	mov ebp, esp
	push 05688591Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
	push ebp
	mov ebp, esp
	push 016898EA6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 12h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
	push ebp
	mov ebp, esp
	push 036A01633h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
	push ebp
	mov ebp, esp
	push 0173FD413h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
	push ebp
	mov ebp, esp
	push 093A37BA6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
	push ebp
	mov ebp, esp
	push 0FE57FEC5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
	push ebp
	mov ebp, esp
	push 00AB2DE90h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
	push ebp
	mov ebp, esp
	push 040AFA42Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenSemaphore ENDP

NtOpenSession PROC
	push ebp
	mov ebp, esp
	push 09F317D64h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
	push ebp
	mov ebp, esp
	push 0BC26445Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
	push ebp
	mov ebp, esp
	push 0A4783057h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenThread ENDP

NtOpenTimer PROC
	push ebp
	mov ebp, esp
	push 0DDB02BD4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenTimer ENDP

NtOpenTransaction PROC
	push ebp
	mov ebp, esp
	push 00CA22233h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
	push ebp
	mov ebp, esp
	push 035A70126h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
	push ebp
	mov ebp, esp
	push 0041AE08Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
	push ebp
	mov ebp, esp
	push 00890003Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
	push ebp
	mov ebp, esp
	push 05FC11E13h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
	push ebp
	mov ebp, esp
	push 04929BB70h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
	push ebp
	mov ebp, esp
	push 076A81142h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
	push ebp
	mov ebp, esp
	push 0F855C1F7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
	push ebp
	mov ebp, esp
	push 03C52C61Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
	push ebp
	mov ebp, esp
	push 0B638BCA0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
	push ebp
	mov ebp, esp
	push 01E610EEEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPropagationComplete ENDP

NtPropagationFailed PROC
	push ebp
	mov ebp, esp
	push 04E9E74C0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPropagationFailed ENDP

NtPulseEvent PROC
	push ebp
	mov ebp, esp
	push 040836718h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
	push ebp
	mov ebp, esp
	push 006AB2134h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
	push ebp
	mov ebp, esp
	push 0039F9B95h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
	push ebp
	mov ebp, esp
	push 0C7572ACFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
	push ebp
	mov ebp, esp
	push 0F1480645h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
	push ebp
	mov ebp, esp
	push 014275CF0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 10h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
	push ebp
	mov ebp, esp
	push 02C1F1453h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
	push ebp
	mov ebp, esp
	push 01BB8695Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
	push ebp
	mov ebp, esp
	push 0BC2B8EBCh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
	push ebp
	mov ebp, esp
	push 0DBD9D771h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
	push ebp
	mov ebp, esp
	push 04CD6B17Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
	push ebp
	mov ebp, esp
	push 0ED33FA82h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
	push ebp
	mov ebp, esp
	push 09844E58Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
	push ebp
	mov ebp, esp
	push 0A4BFDDB2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
	push ebp
	mov ebp, esp
	push 064F6795Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
	push ebp
	mov ebp, esp
	push 027B50F2Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
	push ebp
	mov ebp, esp
	push 00C845229h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
	push ebp
	mov ebp, esp
	push 03F29D430h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
	push ebp
	mov ebp, esp
	push 0055D25F4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
	push ebp
	mov ebp, esp
	push 073EF4472h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
	push ebp
	mov ebp, esp
	push 00F5D8C44h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
	push ebp
	mov ebp, esp
	push 0950EB59Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
	push ebp
	mov ebp, esp
	push 021203C98h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
	push ebp
	mov ebp, esp
	push 0E95DC8EAh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
	push ebp
	mov ebp, esp
	push 04F6A0EBEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
	push ebp
	mov ebp, esp
	push 022D830B9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
	push ebp
	mov ebp, esp
	push 09860DE9Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
	push ebp
	mov ebp, esp
	push 0B9A39E38h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
	push ebp
	mov ebp, esp
	push 0229A520Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
	push ebp
	mov ebp, esp
	push 001D01F70h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
	push ebp
	mov ebp, esp
	push 08858D295h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
	push ebp
	mov ebp, esp
	push 08651BBE5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
	push ebp
	mov ebp, esp
	push 08555760Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
	push ebp
	mov ebp, esp
	push 0009E21C3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
	push ebp
	mov ebp, esp
	push 0988B0EBFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
	push ebp
	mov ebp, esp
	push 01035528Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
	push ebp
	mov ebp, esp
	push 036D4F4AEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
	push ebp
	mov ebp, esp
	push 0148A1419h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
	push ebp
	mov ebp, esp
	push 0AEC6509Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
	push ebp
	mov ebp, esp
	push 0228BE4DFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
	push ebp
	mov ebp, esp
	push 0382B0C96h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQueueApcThreadEx ENDP

NtRaiseException PROC
	push ebp
	mov ebp, esp
	push 0990F9595h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRaiseException ENDP

NtRaiseHardError PROC
	push ebp
	mov ebp, esp
	push 0FD6CFDFBh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
	push ebp
	mov ebp, esp
	push 00E26CB74h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
	push ebp
	mov ebp, esp
	push 0BB26A1B0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
	push ebp
	mov ebp, esp
	push 01F06860Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
	push ebp
	mov ebp, esp
	push 00A3606ACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
	push ebp
	mov ebp, esp
	push 015831310h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
	push ebp
	mov ebp, esp
	push 0DAB3C13Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
	push ebp
	mov ebp, esp
	push 00F4AF53Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
	push ebp
	mov ebp, esp
	push 08B77A822h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
	push ebp
	mov ebp, esp
	push 08092D44Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
	push ebp
	mov ebp, esp
	push 08423B668h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRemoveProcessDebug ENDP

NtRenameKey PROC
	push ebp
	mov ebp, esp
	push 003925840h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRenameKey ENDP

NtRenameTransactionManager PROC
	push ebp
	mov ebp, esp
	push 08E329AAFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRenameTransactionManager ENDP

NtReplaceKey PROC
	push ebp
	mov ebp, esp
	push 09EDDB571h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
	push ebp
	mov ebp, esp
	push 03838CA3Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
	push ebp
	mov ebp, esp
	push 020BD272Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
	push ebp
	mov ebp, esp
	push 02ACD0152h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRequestPort ENDP

NtResetEvent PROC
	push ebp
	mov ebp, esp
	push 07EBE4518h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtResetEvent ENDP

NtResetWriteWatch PROC
	push ebp
	mov ebp, esp
	push 074B94E2Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtResetWriteWatch ENDP

NtRestoreKey PROC
	push ebp
	mov ebp, esp
	push 0DF5AFCF0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRestoreKey ENDP

NtResumeProcess PROC
	push ebp
	mov ebp, esp
	push 0DE3CD7A3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
	push ebp
	mov ebp, esp
	push 004AE043Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
	push ebp
	mov ebp, esp
	push 069304180h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
	push ebp
	mov ebp, esp
	push 0F196D64Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
	push ebp
	mov ebp, esp
	push 094D64F9Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
	push ebp
	mov ebp, esp
	push 00E992005h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
	push ebp
	mov ebp, esp
	push 08B375614h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
	push ebp
	mov ebp, esp
	push 009DAF7ACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSaveKey ENDP

NtSaveKeyEx PROC
	push ebp
	mov ebp, esp
	push 07E75B003h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
	push ebp
	mov ebp, esp
	push 021B8DDD2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
	push ebp
	mov ebp, esp
	push 026E94576h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSecureConnectPort ENDP

NtSerializeBoot PROC
	push ebp
	mov ebp, esp
	push 070A0367Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
	push ebp
	mov ebp, esp
	push 01F3269D7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
	push ebp
	mov ebp, esp
	push 0D98B3D1Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
	push ebp
	mov ebp, esp
	push 0209B2424h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
	push ebp
	mov ebp, esp
	push 004BB8D6Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
	push ebp
	mov ebp, esp
	push 0284FAD6Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetContextThread ENDP

NtSetDebugFilterState PROC
	push ebp
	mov ebp, esp
	push 030B16E0Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
	push ebp
	mov ebp, esp
	push 0DD71D8DFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
	push ebp
	mov ebp, esp
	push 0C7A7FD62h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
	push ebp
	mov ebp, esp
	push 0B58B39A3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
	push ebp
	mov ebp, esp
	push 01F8C8C91h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
	push ebp
	mov ebp, esp
	push 0AEEDFED2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetEaFile ENDP

NtSetHighEventPair PROC
	push ebp
	mov ebp, esp
	push 010B43821h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
	push ebp
	mov ebp, esp
	push 03CB3D02Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
	push ebp
	mov ebp, esp
	push 093AAE962h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
	push ebp
	mov ebp, esp
	push 040986A45h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
	push ebp
	mov ebp, esp
	push 07BD27C40h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
	push ebp
	mov ebp, esp
	push 0F8D4C27Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
	push ebp
	mov ebp, esp
	push 0D389FC39h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
	push ebp
	mov ebp, esp
	push 07F1F8F7Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
	push ebp
	mov ebp, esp
	push 0AE38242Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
	push ebp
	mov ebp, esp
	push 03398F932h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
	push ebp
	mov ebp, esp
	push 00EE62E75h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
	push ebp
	mov ebp, esp
	push 0AB14E5C8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 00D963B39h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
	push ebp
	mov ebp, esp
	push 07EEE544Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
	push ebp
	mov ebp, esp
	push 05C847200h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
	push ebp
	mov ebp, esp
	push 03553158Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
	push ebp
	mov ebp, esp
	push 018DE423Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
	push ebp
	mov ebp, esp
	push 02612D21Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
	push ebp
	mov ebp, esp
	push 004B42C01h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
	push ebp
	mov ebp, esp
	push 014B0342Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
	push ebp
	mov ebp, esp
	push 0ED4A266Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
	push ebp
	mov ebp, esp
	push 01CB8241Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
	push ebp
	mov ebp, esp
	push 01483CC3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
	push ebp
	mov ebp, esp
	push 06CBE5E05h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
	push ebp
	mov ebp, esp
	push 03EA23835h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
	push ebp
	mov ebp, esp
	push 07290585Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
	push ebp
	mov ebp, esp
	push 0A4A9B412h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
	push ebp
	mov ebp, esp
	push 05C9257F2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
	push ebp
	mov ebp, esp
	push 0B5B61520h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetTimer2 ENDP

NtSetTimerEx PROC
	push ebp
	mov ebp, esp
	push 0130259FFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetTimerEx ENDP

NtSetTimerResolution PROC
	push ebp
	mov ebp, esp
	push 0C14E205Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
	push ebp
	mov ebp, esp
	push 007ACCF00h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
	push ebp
	mov ebp, esp
	push 0CBDA3ACCh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
	push ebp
	mov ebp, esp
	push 03EAD3B3Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
	push ebp
	mov ebp, esp
	push 0C050C9C4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
	push ebp
	mov ebp, esp
	push 00494706Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
	push ebp
	mov ebp, esp
	push 09AB569CAh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
	push ebp
	mov ebp, esp
	push 0B816D28Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSinglePhaseReject ENDP

NtStartProfile PROC
	push ebp
	mov ebp, esp
	push 004B2DC80h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtStartProfile ENDP

NtStopProfile PROC
	push ebp
	mov ebp, esp
	push 0F7A6F01Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
	push ebp
	mov ebp, esp
	push 01E236FFEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
	push ebp
	mov ebp, esp
	push 05D863A94h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSuspendProcess ENDP

NtSuspendThread PROC
	push ebp
	mov ebp, esp
	push 0F8E372CDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSuspendThread ENDP

NtSystemDebugControl PROC
	push ebp
	mov ebp, esp
	push 0078F011Dh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
	push ebp
	mov ebp, esp
	push 0EEB062A2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
	push ebp
	mov ebp, esp
	push 0269A2407h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtTerminateJobObject ENDP

NtTestAlert PROC
	push ebp
	mov ebp, esp
	push 086D5B57Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtTestAlert ENDP

NtThawRegistry PROC
	push ebp
	mov ebp, esp
	push 040AF3E4Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtThawRegistry ENDP

NtThawTransactions PROC
	push ebp
	mov ebp, esp
	push 0019A1971h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtThawTransactions ENDP

NtTraceControl PROC
	push ebp
	mov ebp, esp
	push 00991F3D7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 6h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtTraceControl ENDP

NtTranslateFilePath PROC
	push ebp
	mov ebp, esp
	push 0CE10E9DEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
	push ebp
	mov ebp, esp
	push 0A73A9CADh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUmsThreadYield ENDP

NtUnloadDriver PROC
	push ebp
	mov ebp, esp
	push 012BF4E12h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnloadDriver ENDP

NtUnloadKey PROC
	push ebp
	mov ebp, esp
	push 0C81F2B67h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnloadKey ENDP

NtUnloadKey2 PROC
	push ebp
	mov ebp, esp
	push 0AFD77AF0h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
	push ebp
	mov ebp, esp
	push 0537819C5h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnloadKeyEx ENDP

NtUnlockFile PROC
	push ebp
	mov ebp, esp
	push 06C3E64A8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 5h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
	push ebp
	mov ebp, esp
	push 003932D05h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
	push ebp
	mov ebp, esp
	push 032890634h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
	push ebp
	mov ebp, esp
	push 04F5F1B6Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
	push ebp
	mov ebp, esp
	push 0A23CD4B4h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 7h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtUpdateWnfStateData ENDP

NtVdmControl PROC
	push ebp
	mov ebp, esp
	push 04794470Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
	push ebp
	mov ebp, esp
	push 05CBE6E69h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
	push ebp
	mov ebp, esp
	push 0008B0B0Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
	push ebp
	mov ebp, esp
	push 0D08A3618h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
	push ebp
	mov ebp, esp
	push 058F0725Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
	push ebp
	mov ebp, esp
	push 027921D3Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
	push ebp
	mov ebp, esp
	push 0C09DC00Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
	push ebp
	mov ebp, esp
	push 00A912008h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
	push ebp
	mov ebp, esp
	push 017AAEFA6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
	push ebp
	mov ebp, esp
	push 0000846DDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
	push ebp
	mov ebp, esp
	push 012151E8Fh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
	push ebp
	mov ebp, esp
	push 076E950BDh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
	push ebp
	mov ebp, esp
	push 00D920904h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 3h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSavepointTransaction ENDP

NtSavepointComplete PROC
	push ebp
	mov ebp, esp
	push 0BD32253Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSavepointComplete ENDP

NtCreateSectionEx PROC
	push ebp
	mov ebp, esp
	push 0FEAD2DF7h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 9h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
	push ebp
	mov ebp, esp
	push 09CBBA109h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
	push ebp
	mov ebp, esp
	push 040CB3F38h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
	push ebp
	mov ebp, esp
	push 001953933h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtListTransactions ENDP

NtMarshallTransaction PROC
	push ebp
	mov ebp, esp
	push 030AB12FFh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtMarshallTransaction ENDP

NtPullTransaction PROC
	push ebp
	mov ebp, esp
	push 0178C151Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
	push ebp
	mov ebp, esp
	push 058E781AEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
	push ebp
	mov ebp, esp
	push 00D973101h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtWaitForWnfNotifications ENDP

NtStartTm PROC
	push ebp
	mov ebp, esp
	push 0438F257Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 0h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtStartTm ENDP

NtSetInformationProcess PROC
	push ebp
	mov ebp, esp
	push 07E337FACh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
	push ebp
	mov ebp, esp
	push 01547D013h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
	push ebp
	mov ebp, esp
	push 0BC18A7B8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
	push ebp
	mov ebp, esp
	push 08E97AF13h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 1h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtQuerySystemTime ENDP

NtManageHotPatch PROC
	push ebp
	mov ebp, esp
	push 0E4D93065h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 4h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtManageHotPatch ENDP

NtContinueEx PROC
	push ebp
	mov ebp, esp
	push 053AD7510h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber
	lea esp, [esp+4]
	mov ecx, 2h
push_argument:
	dec ecx
	push [ebp + 08h + ecx * 4]
	jnz push_argument
	push ret_address_epilog ;ret address
	call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
	lea esp, [esp+4]
ret_address_epilog:
	mov esp, ebp
	pop ebp
	ret
NtContinueEx ENDP



END