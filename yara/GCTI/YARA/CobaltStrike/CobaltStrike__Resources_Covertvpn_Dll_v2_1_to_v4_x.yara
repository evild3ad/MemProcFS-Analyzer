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

rule CobaltStrike_Resources_Covertvpn_Dll_v2_1_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/covertvpn.dll signature for version v2.2 to v4.4"
		hash =  "0a452a94d53e54b1df6ba02bc2f02e06d57153aad111171a94ec65c910d22dcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		5?                  push    esi
		68 [4]              push    offset ProcName; "IsWow64Process"
		68 [4]              push    offset ModuleName; "kernel32"
		C7 [3-5] 00 00 00 00  mov     [ebp+var_9C], 0                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x
		FF 15 [4]           call    ds:GetModuleHandleA
		50                  push    eax; hModule
		FF 15 [4]           call    ds:GetProcAddress
		8B ??               mov     esi, eax
		85 ??               test    esi, esi
		74 ??               jz      short loc_1000298B
		8D [3-5]            lea     eax, [ebp+var_9C]                 // the displacement bytes are only 3 in v2.x, 5 in v3.x->v4.x
		5?                  push    eax
		FF 15 [4]           call    ds:GetCurrentProcess
		50                  push    eax
	*/

	$dropComponentsAndActivateDriver_prologue = {
			5? 
			68 [4]
			68 [4]
			C7 [3-5] 00 00 00 00 
			FF 15 [4]
			50
			FF 15 [4]
			8B ?? 
			85 ?? 
			74 ??
			8D [3-5]
			5? 
			FF 15 [4]
			50
		}

	/*
		6A 00          push    0; AccessMode
		5?             push    esi; FileName
		E8 [4]         call    __access
		83 C4 08       add     esp, 8
		83 F8 FF       cmp     eax, 0FFFFFFFFh
		74 ??          jz      short loc_100028A7
		5?             push    esi
		68 [4]         push    offset aWarningSExists; "Warning: %s exists\n"   // this may not exist in v2.x samples
		E8 [4]         call    nullsub_1
		83 C4 08       add     esp, 8             // if the push doesnt exist, then this is 04, not 08
		// v2.x has a PUSH ESI here... so we need to skip that
		6A 00          push    0; hTemplateFile
		68 80 01 00 00 push    180h; dwFlagsAndAttributes
		6A 02          push    2; dwCreationDisposition
		6A 00          push    0; lpSecurityAttributes
		6A 05          push    5; dwShareMode
		68 00 00 00 40 push    40000000h; dwDesiredAccess
		5?             push    esi; lpFileName
		FF 15 [4]      call    ds:CreateFileA
		8B ??          mov     edi, eax
		83 ?? FF       cmp     edi, 0FFFFFFFFh
		75 ??          jnz     short loc_100028E2
		FF 15 [4]      call    ds:GetLastError
		5?             push    eax
	*/

	$dropFile = {
			6A 00
			5? 
			E8 [4]
			83 C4 08
			83 F8 FF
			74 ?? 
			5? 
			[0-5]
			E8 [4]
			83 C4 ??
			[0-2]
			6A 00
			68 80 01 00 00
			6A 02
			6A 00
			6A 05
			68 00 00 00 40
			5? 
			FF 15 [4]
			8B ?? 
			83 ?? FF 
			75 ?? 
			FF 15 [4]
			5? 
		}
	
	$nfp = "npf.sys" nocase
	$wpcap = "wpcap.dll" nocase

	condition:
		all of them
}