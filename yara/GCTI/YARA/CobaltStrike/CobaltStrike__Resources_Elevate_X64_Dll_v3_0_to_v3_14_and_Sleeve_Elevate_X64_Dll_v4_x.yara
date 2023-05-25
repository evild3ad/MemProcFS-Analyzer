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

rule CobaltStrike_Resources_Elevate_X64_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_X64_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.x64.dll signature for v3.0 to v3.14 and sleeve/elevate.x64.dll for v4.x"
		hash =  "c3ee8a9181fed39cec3bd645b32b611ce98d2e84c5a9eff31a8acfd9c26410ec"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		81 FA 21 01 00 00             cmp     edx, 121h
		75 4A                         jnz     short loc_1800017A9
		83 3D 5A 7E 01 00 00          cmp     cs:dword_1800195C0, 0
		75 41                         jnz     short loc_1800017A9
		45 33 C9                      xor     r9d, r9d; lParam
		8D 57 DF                      lea     edx, [rdi-21h]; Msg
		C7 05 48 7E 01 00 01 00 00 00 mov     cs:dword_1800195C0, 1
		45 8D 41 28                   lea     r8d, [r9+28h]; wParam
		FF 15 36 DB 00 00             call    cs:PostMessageA
		45 33 C9                      xor     r9d, r9d; lParam
		8D 57 DF                      lea     edx, [rdi-21h]; Msg
		45 8D 41 27                   lea     r8d, [r9+27h]; wParam
		48 8B CB                      mov     rcx, rbx; hWnd
		FF 15 23 DB 00 00             call    cs:PostMessageA
		45 33 C9                      xor     r9d, r9d; lParam
		45 33 C0                      xor     r8d, r8d; wParam
		BA 01 02 00 00                mov     edx, 201h; Msg
		48 8B CB                      mov     rcx, rbx; hWnd
	*/

	$wnd_proc = {
			81 ?? 21 01 00 00
			75 ??
			83 [5] 00
			75 ??
			45 33 ??
			8D [2]
			C7 [5] 01 00 00 00
			45 [2] 28
			FF 15 [4]
			45 33 ??
			8D [2]
			45 [2] 27
			48 [2]
			FF 15 [4]
			45 33 ??
			45 33 ??
			BA 01 02 00 00
			48 
		}

	condition:
		$wnd_proc
}
