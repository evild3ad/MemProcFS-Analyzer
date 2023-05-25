/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule CobaltStrike_Resources_Bypassuactoken_x64_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.x64.dll from v3.11 to v3.14 (64-bit version)"
		hash =  "853068822bbc6b1305b2a9780cf1034f5d9d7127001351a6917f9dbb42f30d67"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		83 F8 7A          cmp     eax, 7Ah ; 'z'
		75 59             jnz     short loc_1800014BC
		8B 54 24 48       mov     edx, dword ptr [rsp+38h+uBytes]; uBytes
		33 C9             xor     ecx, ecx; uFlags
		FF 15 49 9C 00 00 call    cs:LocalAlloc
		44 8B 4C 24 48    mov     r9d, dword ptr [rsp+38h+uBytes]; TokenInformationLength
		8D 53 19          lea     edx, [rbx+19h]; TokenInformationClass
		48 8B F8          mov     rdi, rax
		48 8D 44 24 48    lea     rax, [rsp+38h+uBytes]
		48 8B CE          mov     rcx, rsi; TokenHandle
		4C 8B C7          mov     r8, rdi; TokenInformation
		48 89 44 24 20    mov     [rsp+38h+ReturnLength], rax; ReturnLength
		FF 15 B0 9B 00 00 call    cs:GetTokenInformation
		85 C0             test    eax, eax
		74 2D             jz      short loc_1800014C1
		48 8B 0F          mov     rcx, [rdi]; pSid
		FF 15 AB 9B 00 00 call    cs:GetSidSubAuthorityCount
		8D 73 01          lea     esi, [rbx+1]
		8A 08             mov     cl, [rax]
		40 2A CE          sub     cl, sil
		0F B6 D1          movzx   edx, cl; nSubAuthority
		48 8B 0F          mov     rcx, [rdi]; pSid
		FF 15 9F 9B 00 00 call    cs:GetSidSubAuthority
		81 38 00 30 00 00 cmp     dword ptr [rax], 3000h
	*/

	$isHighIntegrityProcess = {
			83 ?? 7A
			75 ??
			8B [3]
			33 ??
			FF 15 [4]
			44 [4]
			8D [2]
			48 8B ??
			48 8D [3]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 15 [4]
			85 C0
			74 ??
			48 8B ??
			FF 15 [4]
			8D [2]
			8A ??
			40 [2]
			0F B6 D1
			48 8B 0F
			FF 15 [4]
			81 ?? 00 30 00 00
		}

	/*
		44 8D 42 70             lea     r8d, [rdx+70h]; Size
		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; void *
		E8 2E 07 00 00          call    memset
		83 64 24 50 00          and     [rsp+98h+pExecInfo.nShow], 0
		48 8D 05 E2 9B 00 00    lea     rax, aTaskmgrExe; "taskmgr.exe"
		0F 57 C0                xorps   xmm0, xmm0
		66 0F 7F 44 24 40       movdqa  xmmword ptr [rsp+98h+pExecInfo.lpParameters], xmm0
		48 89 44 24 38          mov     [rsp+98h+pExecInfo.lpFile], rax
		48 8D 05 E5 9B 00 00    lea     rax, aRunas; "runas"
		48 8D 4C 24 20          lea     rcx, [rsp+98h+pExecInfo]; pExecInfo
		C7 44 24 20 70 00 00 00 mov     [rsp+98h+pExecInfo.cbSize], 70h ; 'p'
		C7 44 24 24 40 00 00 00 mov     [rsp+98h+pExecInfo.fMask], 40h ; '@'
		48 89 44 24 30          mov     [rsp+98h+pExecInfo.lpVerb], rax
		FF 15 05 9B 00 00       call    cs:ShellExecuteExW
	*/

	$executeTaskmgr = {
			44 8D ?? 70
			48 8D [3]
			E8 [4]
			83 [3] 00
			48 8D [5]
			0F 57 ??
			66 0F 7F [3]
			48 89 [3]
			48 8D [5]
			48 8D [3]
			C7 [3] 70 00 00 00
			C7 [3] 40 00 00 00
			48 89 [3]
			FF 15 
		}


	condition:
		all of them
}
