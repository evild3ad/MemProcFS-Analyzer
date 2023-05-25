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

rule CobaltStrike_Resources_Elevate_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.dll signature for v3.0 to v3.14 and sleeve/elevate.dll for v4.x"
		hash =  "6deeb2cafe9eeefe5fc5077e63cc08310f895e9d5d492c88c4e567323077aa2f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		6A 00               push    0; lParam
		6A 28               push    28h ; '('; wParam
		68 00 01 00 00      push    100h; Msg
		5?                  push    edi; hWnd
		C7 [5] 01 00 00 00  mov     dword_10017E70, 1
		FF ??               call    esi ; PostMessageA
		6A 00               push    0; lParam
		6A 27               push    27h ; '''; wParam
		68 00 01 00 00      push    100h; Msg
		5?                  push    edi; hWnd
		FF ??               call    esi ; PostMessageA
		6A 00               push    0; lParam
		6A 00               push    0; wParam
		68 01 02 00 00      push    201h; Msg
		5?                  push    edi; hWnd
		FF ??               call    esi ; PostMessageA
	*/

	$wnd_proc = {
			6A 00
			6A 28
			68 00 01 00 00
			5? 
			C7 [5] 01 00 00 00 
			FF ?? 
			6A 00
			6A 27
			68 00 01 00 00
			5? 
			FF ?? 
			6A 00
			6A 00
			68 01 02 00 00
			5? 
			FF ?? 
		}

		
	condition:
		$wnd_proc
}
