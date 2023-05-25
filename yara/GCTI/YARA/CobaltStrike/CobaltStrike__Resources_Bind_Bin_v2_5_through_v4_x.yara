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

rule CobaltStrike_Resources_Bind_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind.bin signature for versions 2.5 to 4.x"
		hash =  "3727542c0e3c2bf35cacc9e023d1b2d4a1e9e86ee5c62ee5b66184f46ca126d1"
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

    // the signature for the stagers overlap significantly. Looking for bind.bin specific bytes helps delineate sample types
	/*
		5D             pop     ebp
		68 33 32 00 00 push    '23'
		68 77 73 32 5F push    '_2sw'
	*/

	$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}

  // bind.bin, unlike reverse.bin, listens for incoming connections. Using the API hashes for listen and accept is a solid
  // approach to finding bind.bin specific samples
	/*
		5?             push    ebx
		5?             push    edi
		68 B7 E9 38 FF push    listen
		FF ??          call    ebp
		5?             push    ebx
		5?             push    ebx
		5?             push    edi
		68 74 EC 3B E1 push    accept
	*/
	$listenaccept = {
			5? 
			5? 
			68 B7 E9 38 FF
			FF ?? 
			5? 
			5? 
			5? 
			68 74 EC 3B E1
		}
	
	condition:
		$apiLocator and $ws2_32 and $listenaccept
}
