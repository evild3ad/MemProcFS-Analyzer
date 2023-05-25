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

rule CobaltStrike_Resources_Bypassuac_x64_Dll_v3_3_to_v3_14_and_Sleeve_Bypassuac_x64_Dll_v4_0_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac-x64.dll from v3.3 to v3.14 (64-bit version) and sleeve/bypassuac.x64.dll from v4.0 to at least v4.4"
		hash =  "9ecf56e9099811c461d592c325c65c4f9f27d947cbdf3b8ef8a98a43e583aecb"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		48 8B 0D 07 A4 01 00 mov     rcx, cs:fileop
		45 33 C0             xor     r8d, r8d
		48 8B 01             mov     rax, [rcx]
		FF 90 90 00 00 00    call    qword ptr [rax+90h]
		85 C0                test    eax, eax
		75 D9                jnz     short loc_180001022
		48 8B 0D F0 A3 01 00 mov     rcx, cs:fileop
		48 8B 11             mov     rdx, [rcx]
		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]
		85 C0                test    eax, eax
	*/

	$deleteFileCOM = {
			48 8B [5]
			45 33 ??
			48 8B ??
			FF 90 90 00 00 00
			85 C0
			75 ??
			48 8B [5]
			48 8B ??
			FF 92 A8 00 00 00
			85 C0
		}	
	
	
	/*
		48 8B 0D 32 A3 01 00 mov     rcx, cs:fileop
		4C 8B 05 3B A3 01 00 mov     r8, cs:dstFile
		48 8B 15 2C A3 01 00 mov     rdx, cs:srcFile
		48 8B 01             mov     rax, [rcx]
		4C 8B CD             mov     r9, rbp
		48 89 5C 24 20       mov     [rsp+38h+var_18], rbx
		FF 90 80 00 00 00    call    qword ptr [rax+80h]
		85 C0                test    eax, eax
		0F 85 7B FF FF FF    jnz     loc_1800010B0
		48 8B 0D 04 A3 01 00 mov     rcx, cs:fileop
		48 8B 11             mov     rdx, [rcx]
		FF 92 A8 00 00 00    call    qword ptr [rdx+0A8h]
	*/

	$copyFileCOM = {
			48 8B [5]
			4C 8B [5]
			48 8B [5]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 90 80 00 00 00
			85 C0
			0F 85 [4]
			48 8B [5]
			48 8B 11
			FF 92 A8 00 00 00
		}

	condition:
		all of them
}
