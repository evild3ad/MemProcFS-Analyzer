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

rule CobaltStrike_Resources_Smbstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/smbstager.bin signature for versions 2.5 to 4.x"
		hash =  "946af5a23e5403ea1caccb2e0988ec1526b375a3e919189f16491eeabc3e7d8c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 ??     xor     eax, eax
		AC        lodsb
		C1 ?? 0D  ror     edi, 0Dh
		01 ??     add     edi, eax
		38 ??     cmp     al, ah
		75 ??     jnz     short loc_10000054
		03 [2]    add     edi, [ebp-8]
		3B [2]    cmp     edi, [ebp+24h]
		75 ??     jnz     short loc_1000004A
		5?        pop     eax
		8B ?? 24  mov     ebx, [eax+24h]
		01 ??     add     ebx, edx
		66 8B [2] mov     cx, [ebx+ecx*2]
		8B ?? 1C  mov     ebx, [eax+1Ch]
		01 ??     add     ebx, edx
		8B ?? 8B  mov     eax, [ebx+ecx*4]
		01 ??     add     eax, edx
		89 [3]    mov     [esp+28h+var_4], eax
		5?        pop     ebx
		5?        pop     ebx
	*/

	$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}

    // the signature for the stagers overlap significantly. Looking for smbstager.bin specific bytes helps delineate sample types
	  $smb = { 68 C6 96 87 52 }	
	  
	  // This code block helps differentiate between smbstager.bin and metasploit's engine which has reasonable level of overlap
	  	/*
		6A 40          push    40h ; '@'
		68 00 10 00 00 push    1000h
		68 FF FF 07 00 push    7FFFFh
		6A 00          push    0
		68 58 A4 53 E5 push    VirtualAlloc
	*/

	$smbstart = {
			6A 40
			68 00 10 00 00
			68 FF FF 07 00
			6A 00
			68 58 A4 53 E5
		}
	
	condition:
		$apiLocator and $smb and $smbstart
}
