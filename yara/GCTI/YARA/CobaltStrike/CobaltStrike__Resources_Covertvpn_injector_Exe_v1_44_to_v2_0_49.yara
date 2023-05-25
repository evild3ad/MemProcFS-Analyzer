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

rule CobaltStrike_Resources_Covertvpn_injector_Exe_v1_44_to_v2_0_49
{
	meta:
		description = "Cobalt Strike's resources/covertvpn-injector.exe signature for version v1.44 to v2.0.49"
		hash =  "d741751520f46602f5a57d1ed49feaa5789115aeeba7fa4fc7cbb534ee335462"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		C7 04 24 [4]    mov     dword ptr [esp], offset aKernel32; "kernel32"
		E8 [4]          call    GetModuleHandleA
		83 EC 04        sub     esp, 4
		C7 44 24 04 [4] mov     dword ptr [esp+4], offset aIswow64process; "IsWow64Process"
		89 04 24        mov     [esp], eax; hModule
		E8 59 14 00 00  call    GetProcAddress
		83 EC 08        sub     esp, 8
		89 45 ??        mov     [ebp+var_C], eax
		83 7D ?? 00     cmp     [ebp+var_C], 0
		74 ??           jz      short loc_4019BA
		E8 [4]          call    GetCurrentProcess
		8D [2]          lea     edx, [ebp+fIs64bit]
		89 [3]          mov     [esp+4], edx
		89 04 24        mov     [esp], eax
	*/

	$dropComponentsAndActivateDriver_prologue = {
			C7 04 24 [4]
			E8 [4]
			83 EC 04
			C7 44 24 04 [4]
			89 04 24
			E8 59 14 00 00
			83 EC 08
			89 45 ?? 
			83 7D ?? 00 
			74 ?? 
			E8 [4]
			8D [2]
			89 [3]
			89 04 24
		}

	/*
		C7 44 24 04 00 00 00 00 mov     dword ptr [esp+4], 0; AccessMode
		8B [2]                  mov     eax, [ebp+FileName]
		89 ?? 24                mov     [esp], eax; FileName
		E8 [4]                  call    _access
		83 F8 FF                cmp     eax, 0FFFFFFFFh
		74 ??                   jz      short loc_40176D
		8B [2]                  mov     eax, [ebp+FileName]
		89 ?? 24 04             mov     [esp+4], eax
		C7 04 24 [4]            mov     dword ptr [esp], offset aWarningSExists; "Warning: %s exists\n"
		E8 [4]                  call    log
		E9 [4]                  jmp     locret_401871
		C7 44 24 18 00 00 00 00 mov     dword ptr [esp+18h], 0; hTemplateFile
		C7 44 24 14 80 01 00 00 mov     dword ptr [esp+14h], 180h; dwFlagsAndAttributes
		C7 44 24 10 02 00 00 00 mov     dword ptr [esp+10h], 2; dwCreationDisposition
		C7 44 24 0C 00 00 00 00 mov     dword ptr [esp+0Ch], 0; lpSecurityAttributes
		C7 44 24 08 05 00 00 00 mov     dword ptr [esp+8], 5; dwShareMode
		C7 44 24 04 00 00 00 40 mov     dword ptr [esp+4], 40000000h; dwDesiredAccess
		8B [2]                  mov     eax, [ebp+FileName]
		89 04 24                mov     [esp], eax; lpFileName
		E8 [4]                  call    CreateFileA
		83 EC 1C                sub     esp, 1Ch
		89 45 ??                mov     [ebp+hFile], eax
	*/

	$dropFile = {
			C7 44 24 04 00 00 00 00
			8B [2]
			89 ?? 24 
			E8 [4]
			83 F8 FF
			74 ?? 
			8B [2]
			89 ?? 24 04 
			C7 04 24 [4]
			E8 [4]
			E9 [4]
			C7 44 24 18 00 00 00 00
			C7 44 24 14 80 01 00 00
			C7 44 24 10 02 00 00 00
			C7 44 24 0C 00 00 00 00
			C7 44 24 08 05 00 00 00
			C7 44 24 04 00 00 00 40
			8B [2]
			89 04 24
			E8 [4]
			83 EC 1C
			89 45 ?? 
		}

	$nfp = "npf.sys" nocase
	$wpcap = "wpcap.dll" nocase
			
	condition:
		all of them
}
