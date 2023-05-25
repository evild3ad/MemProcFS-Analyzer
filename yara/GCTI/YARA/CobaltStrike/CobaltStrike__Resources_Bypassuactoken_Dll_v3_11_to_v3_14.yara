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

rule CobaltStrike_Resources_Bypassuactoken_Dll_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/bypassuactoken.dll from v3.11 to v3.14 (32-bit version)"
		hash =  "df1c7256dfd78506e38c64c54c0645b6a56fc56b2ffad8c553b0f770c5683070"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		5?                 push    eax; ReturnLength
		5?                 push    edi; TokenInformationLength
		5?                 push    edi; TokenInformation
		8B ??              mov     ebx, ecx
		6A 19              push    19h; TokenInformationClass
		5?                 push    ebx; TokenHandle
		FF 15 [4]          call    ds:GetTokenInformation
		85 C0              test    eax, eax
		75 ??              jnz     short loc_10001100
		FF 15 [4]          call    ds:GetLastError
		83 ?? 7A           cmp     eax, 7Ah ; 'z'
		75 ??              jnz     short loc_10001100
		FF [2]             push    [ebp+ReturnLength]; uBytes
		5?                 push    edi; uFlags
		FF 15 [4]          call    ds:LocalAlloc
		8B ??              mov     esi, eax
		8D [2]             lea     eax, [ebp+ReturnLength]
		5?                 push    eax; ReturnLength
		FF [2]             push    [ebp+ReturnLength]; TokenInformationLength
		5?                 push    esi; TokenInformation
		6A 19              push    19h; TokenInformationClass
		5?                 push    ebx; TokenHandle
		FF 15 [4]          call    ds:GetTokenInformation
		85 C0              test    eax, eax
		74 ??              jz      short loc_10001103
		FF ??              push    dword ptr [esi]; pSid
		FF 15 [4]          call    ds:GetSidSubAuthorityCount
		8A ??              mov     al, [eax]
		FE C8              dec     al
		0F B6 C0           movzx   eax, al
		5?                 push    eax; nSubAuthority
		FF ??              push    dword ptr [esi]; pSid
		FF 15 [4]          call    ds:GetSidSubAuthority
		B? 01 00 00 00     mov     ecx, 1
		5?                 push    esi; hMem
		81 ?? 00 30 00 00  cmp     dword ptr [eax], 3000h
	*/

	$isHighIntegrityProcess = {
			5? 
			5? 
			5? 
			8B ?? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			75 ?? 
			FF 15 [4]
			83 ?? 7A 
			75 ?? 
			FF [2]
			5? 
			FF 15 [4]
			8B ?? 
			8D [2]
			5? 
			FF [2]
			5? 
			6A 19
			5? 
			FF 15 [4]
			85 C0
			74 ?? 
			FF ?? 
			FF 15 [4]
			8A ?? 
			FE C8
			0F B6 C0
			5? 
			FF ?? 
			FF 15 [4]
			B? 01 00 00 00 
			5? 
			81 ?? 00 30 00 00 
		}

	/*
		6A 3C               push    3Ch ; '<'; Size
		8D ?? C4            lea     eax, [ebp+pExecInfo]
		8B ??               mov     edi, edx
		6A 00               push    0; Val
		5?                  push    eax; void *
		8B ??               mov     esi, ecx
		E8 [4]              call    _memset
		83 C4 0C            add     esp, 0Ch
		C7 [2] 3C 00 00 00  mov     [ebp+pExecInfo.cbSize], 3Ch ; '<'
		8D [2]              lea     eax, [ebp+pExecInfo]
		C7 [2] 40 00 00 00  mov     [ebp+pExecInfo.fMask], 40h ; '@'
		C7 [6]              mov     [ebp+pExecInfo.lpFile], offset aTaskmgrExe; "taskmgr.exe"
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpParameters], 0
		5?                  push    eax; pExecInfo
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.lpDirectory], 0
		C7 [6]              mov     [ebp+pExecInfo.lpVerb], offset aRunas; "runas"
		C7 [2] 00 00 00 00  mov     [ebp+pExecInfo.nShow], 0
		FF 15 [4]           call    ds:ShellExecuteExW
		FF 75 FC            push    [ebp+pExecInfo.hProcess]; Process
	*/

	$executeTaskmgr = {
			6A 3C
			8D ?? C4 
			8B ?? 
			6A 00
			5? 
			8B ?? 
			E8 [4]
			83 C4 0C
			C7 [2] 3C 00 00 00 
			8D [2]
			C7 [2] 40 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			5? 
			C7 [2] 00 00 00 00 
			C7 [6]
			C7 [2] 00 00 00 00 
			FF 15 [4]
			FF 75 FC
		}
		
	condition:
		all of them
}