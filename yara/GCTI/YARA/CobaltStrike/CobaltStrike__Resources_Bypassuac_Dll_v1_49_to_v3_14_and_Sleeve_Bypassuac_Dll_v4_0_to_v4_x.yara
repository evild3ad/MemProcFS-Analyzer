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

rule CobaltStrike_Resources_Bypassuac_Dll_v1_49_to_v3_14_and_Sleeve_Bypassuac_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac(-x86).dll from v1.49 to v3.14 (32-bit version) and sleeve/bypassuac.dll from v4.0 to at least v4.4"
		hash =  "91d12e1d09a642feedee5da966e1c15a2c5aea90c79ac796e267053e466df365"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		A1 [4]    mov     eax, fileop
		6A 00     push    0
		8B ??     mov     ecx, [eax]
		5?        push    edx
		5?        push    eax
		FF ?? 48  call    dword ptr [ecx+48h]
		85 ??     test    eax, eax
		75 ??     jnz     short loc_10001177
		A1 [4]    mov     eax, fileop
		5?        push    eax
		8B ??     mov     ecx, [eax]
		FF ?? 54  call    dword ptr [ecx+54h]
	*/

	$deleteFileCOM = {
			A1 [4]
			6A 00
			8B ?? 
			5? 
			5? 
			FF ?? 48 
			85 ?? 
			75 ?? 
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}

	/*
		A1 [4]    mov     eax, fileop
		6A 00     push    0
		FF ?? 08  push    [ebp+copyName]
		8B ??     mov     ecx, [eax]
		FF [5]    push    dstFile
		FF [5]    push    srcFile
		5?        push    eax
		FF ?? 40  call    dword ptr [ecx+40h]
		85 ??     test    eax, eax
		75 ??     jnz     short loc_10001026  // this line can also be 0F 85 <32-bit offset>
		A1 [4]    mov     eax, fileop
		5?        push    eax
		8B ??     mov     ecx, [eax]
		FF ?? 54  call    dword ptr [ecx+54h]
	*/

	$copyFileCOM = {
			A1 [4]
			6A 00
			FF [2]
			8B ?? 
			FF [5]
			FF [5]
			5? 
			FF ?? 40 
			85 ?? 
			[2 - 6]
			A1 [4]
			5? 
			8B ?? 
			FF ?? 54 
		}
		
				
	condition:
		all of them
}
