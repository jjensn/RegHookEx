#include "RegHook.h"
#include "fde\fde64.h"

class RegHookShared {
public:
	static size_t min_size;
	static byte* hkpatch;
	static byte* funcpatch;
	const static SIZE_T hkpatch_size;
	const static SIZE_T funcpatch_size;
	static size_t GetInstructionLength(void*);
	const static size_t instruction_max;
};

size_t RegHookShared::GetInstructionLength(void* buff) {
	void *ptr = (void*)buff;
	fde64s cmd;
	decode(ptr, &cmd);
	ptr = (void *)((uintptr_t)ptr + cmd.len);
	return cmd.len;
}

size_t RegHookShared::min_size = 22;
const size_t RegHookShared::instruction_max = 15;

/*

bits 64
section .text
global start

default REL

start:

	mov rax, [my_rax]
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	mov [my_rcx], rcx 
	mov [my_rdx], rdx 
	mov [my_rbp], rbp 
	mov [my_rsi], rsi 
	mov [my_rdi], rdi 
	mov [my_rsp], rsp 
	mov [my_rbx], rbx 
	mov [my_r8], r8;
	mov [my_r9], r9;
	ret

my_rbx:
	dq 0xdeadbeef
my_rsp:
	dq 0xdeadbeef
my_rdi:
	dq 0xdeadbeef
my_rsi:
	dq 0xdeadbeef
my_rbp:
	dq 0xdeadbeef
my_rdx:
	dq 0xdeadbeef
my_rcx:
	dq 0xdeadbeef
my_r8:
	dq 0xdeadbeef
my_r9:
	dq 0xdeadbeef
my_rax:
	dq 0xdeadbeef

*/
const size_t RegHookShared::hkpatch_size = 177;
byte* RegHookShared::hkpatch = new byte[RegHookShared::hkpatch_size]{
0x48, 0x8b, 0x05, 0xa2, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
0x90, 0x90, 0x90, 0x48, 0x89, 0x0d, 0x69, 0x00, 0x00, 0x00, 0x48, 0x89, 0x15, 0x5a, 0x00,
0x00, 0x00, 0x48, 0x89, 0x2d, 0x4b, 0x00, 0x00, 0x00, 0x48, 0x89, 0x35, 0x3c, 0x00, 0x00,
0x00, 0x48, 0x89, 0x3d, 0x2d, 0x00, 0x00, 0x00, 0x48, 0x89, 0x25, 0x1e, 0x00, 0x00, 0x00,
0x48, 0x89, 0x1d, 0x0f, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x05, 0x40, 0x00, 0x00, 0x00, 0x4c,
0x89, 0x0d, 0x41, 0x00, 0x00, 0x00, 0xc3, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00,
0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00,
0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00,
0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde,
0x00, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00
};

const size_t RegHookShared::funcpatch_size = 32;
byte* RegHookShared::funcpatch = new byte[RegHookShared::funcpatch_size]{
	0x48, 0xA3, 0x00, 0x00, 0xA2, 0xDD, 0xC8, 0x02, 0x00, 0x00,
	0x48, 0xB8, 0x00, 0x00, 0xA2, 0xDD,	0xC8, 0x02, 0x00, 0x00, // mov [raxpath], rax
	0xFF, 0xD0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }; // extra nops

bool RegHook::CreateHookV6() {
	if (this->lengthOfInstructions > 26 || this->lengthOfInstructions < RegHookShared::min_size) return false;
	this->HookedAddress = (DWORD_PTR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RegHook::ReadMem((LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions);
	byte* hkpatch = RegHookShared::hkpatch;
	memcpy(hkpatch + 7, &this->toFixPatch, this->lengthOfInstructions);
	RegHook::WriteMem((LPVOID)this->HookedAddress, hkpatch, RegHookShared::hkpatch_size);
	byte* funcpatch = RegHookShared::funcpatch;
	DWORD_PTR raxpatch = this->HookedAddress + 0xA9;
	memcpy(funcpatch + 12, &this->HookedAddress, 8);
	memcpy(funcpatch + 2, &raxpatch, 8);
	RegHook::WriteMem((LPVOID)this->FuncAddress, funcpatch, this->lengthOfInstructions);
	this->HookInstances.push_back(this);
	return true;
}
void RegHook::ReadMem(void* dst, void* src, const size_t size) {
	DWORD protect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &protect);
	memcpy(src, dst, size);
	VirtualProtect(dst, size, protect, nullptr);
}

void RegHook::WriteMem(void* dst, void* src, const size_t size) {
	DWORD protect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &protect);
	memcpy(dst, src, size);
	VirtualProtect(dst, size, protect, nullptr);
}

size_t RegHook::GetFuncLen() {
	DWORD_PTR addr = this->FuncAddress;
	while (this->lengthOfInstructions < RegHookShared::min_size) {
		byte buff[RegHookShared::instruction_max];
		RegHook::ReadMem((LPVOID)addr, &buff, RegHookShared::instruction_max);
		size_t tmpsize = RegHookShared::GetInstructionLength(&buff);
		this->lengthOfInstructions += tmpsize;
		addr += tmpsize;
	}
	return this->lengthOfInstructions;
}

DWORD_PTR RegHook::GetAddressOfHook() {
	if (this->HookedAddress == 0) {
		CreateHookV6();
	}
	return this->HookedAddress;
}

void RegHook::DestroyHook() {
	if (this->toFixPatch[0] != 0)
		RegHook::WriteMem((LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions);
}

void RegHook::DestroyAllHooks() {
	for (int i = 0; i < HookInstances.size(); i++) {
		HookInstances[i]->DestroyHook();
	}
}

RegDump RegHook::GetRegDump() {
	RegDump pDump;
	RegHook::ReadMem((LPVOID)this->GetAddressOfHook(), &pDump, sizeof(RegDump));
	return pDump;
}

RegHook::RegHook(DWORD_PTR _FuncAddress) {
	this->FuncAddress = _FuncAddress;
	this->lengthOfInstructions = 0;
	this->lengthOfInstructions = this->GetFuncLen();
}

std::vector<RegHook*> RegHook::HookInstances;

// ------------------------------------------------------------

bool RegHookEx::CreateHookV6() {
	if (this->lengthOfInstructions > 26 || this->lengthOfInstructions < RegHookShared::min_size) return false;
	this->HookedAddress = (DWORD_PTR)VirtualAllocEx(this->hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	ReadProcessMemory(this->hProcess, (LPCVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
	byte* hkpatch = RegHookShared::hkpatch;
	memcpy(hkpatch + 7, &this->toFixPatch, this->lengthOfInstructions);
	WriteProcessMemory(this->hProcess, (LPVOID)this->HookedAddress, hkpatch, RegHookShared::hkpatch_size, NULL);
	byte* funcpatch = RegHookShared::funcpatch;
	DWORD_PTR raxpatch = this->HookedAddress + 0x90;
	memcpy(funcpatch + 11, &this->HookedAddress, 4);
	memcpy(funcpatch + 4, &raxpatch, 4);
	WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, funcpatch, this->lengthOfInstructions, NULL);
	this->HookInstances.push_back(this);
	return true;
}

size_t RegHookEx::GetFuncLen() {
	DWORD_PTR addr = this->FuncAddress;
	while (this->lengthOfInstructions < RegHookShared::min_size) {
		byte buff[RegHookShared::instruction_max];
		ReadProcessMemory(this->hProcess, (LPCVOID)addr, &buff, RegHookShared::instruction_max, NULL);
		size_t tmpsize = RegHookShared::GetInstructionLength(&buff);
		this->lengthOfInstructions += tmpsize;
		addr += tmpsize;
	}
	return this->lengthOfInstructions;
}

DWORD_PTR RegHookEx::GetAddressOfHook() {
	if (this->HookedAddress == 0) {
		CreateHookV6();
	}
	return this->HookedAddress;
}

void RegHookEx::DestroyHook() {
	if (this->toFixPatch[0] != 0)
		WriteProcessMemory(this->hProcess, (LPVOID)this->FuncAddress, &this->toFixPatch, this->lengthOfInstructions, NULL);
}

void RegHookEx::DestroyAllHooks() {
	for (int i = 0; i < HookInstances.size(); i++) {
		HookInstances[i]->DestroyHook();
	}
}

RegDump RegHookEx::GetRegDump() {
	RegDump pDump;
	ReadProcessMemory(this->hProcess, (LPVOID)this->GetAddressOfHook(), &pDump, sizeof(RegDump), nullptr);
	return pDump;
}

RegHookEx::RegHookEx(HANDLE _hProcess, DWORD_PTR _FuncAddress) {
	this->hProcess = _hProcess;
	this->FuncAddress = _FuncAddress;
	this->lengthOfInstructions = this->GetFuncLen();
}

std::vector<RegHookEx*> RegHookEx::HookInstances;
