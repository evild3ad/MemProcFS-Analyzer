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

rule CobaltStrike_Resources_Artifact32_and_Resources_Dropper_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.exe,.dll,big.exe,big.dll} and resources/dropper.exe signature for versions 1.49 to 3.14"
		hash =  "40fc605a8b95bbd79a3bd7d9af73fbeebe3fada577c99e7a111f6168f6a0d37a"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
  // Decoder function for the embedded payload
	$payloadDecoder = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 18 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 03 [2] 0F B6 00 31 ?? 88 ?? 8B [2] 89 ?? 03 [2] 8B [2] 03 [2] 0F B6 12 }

	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32_v3_1_and_v3_2
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,svc.exe,big.exe,big.dll,bigsvc.exe} and resources/artifact32uac(alt).dll signature for versions 3.1 and 3.2"
		hash =  "4f14bcd7803a8e22e81e74d6061d0df9e8bac7f96f1213d062a29a8523ae4624"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		89 ??           mov     eax, ecx
		B? 04 00 00 00  mov     edi, 4
		99              cdq
		F7 FF           idiv    edi
		8B [2]          mov     edi, [ebp+arg_8]
		8A [2]          mov     al, [edi+edx]
		30 ??           xor     [ebx], al
		8A ??           mov     al, [ebx]
		4?              inc     ebx
		88 [2]          mov     [esi+ecx], al
	*/

	$decoderFunc = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 ?? 8A ?? 4? 88 }
	condition:
		all of them
}

rule CobaltStrike_Resources_Artifact32_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32{.dll,.exe,big.exe,big.dll,bigsvc.exe} signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x and resources/artifact32uac.dll for v3.14 and v4.0"
		hash =  "888bae8d89c03c1d529b04f9e4a051140ce3d7b39bc9ea021ad9fc7c9f467719"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+28h], 5Ch ; '\'
		C7 [3] 65 00 00 00  mov     dword ptr [esp+24h], 65h ; 'e'
		C7 [3] 70 00 00 00  mov     dword ptr [esp+20h], 70h ; 'p'
		C7 [3] 69 00 00 00  mov     dword ptr [esp+1Ch], 69h ; 'i'
		C7 [3] 70 00 00 00  mov     dword ptr [esp+18h], 70h ; 'p'
		F7 F1               div     ecx
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+14h], 5Ch ; '\'
		C7 [3] 2E 00 00 00  mov     dword ptr [esp+10h], 2Eh ; '.'
		C7 [3] 5C 00 00 00  mov     dword ptr [esp+0Ch], 5Ch ; '\'
	*/

	$pushFmtStr = {	C7 [3] 5C 00 00 00 C7 [3] 65 00 00 00 C7 [3] 70 00 00 00 C7 [3] 69 00 00 00 C7 [3] 70 00 00 00 F7 F1 C7 [3] 5C 00 00 00  C7 [3] 2E 00 00 00 C7 [3] 5C 00 00 00 }
  $fmtStr = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:
		all of them
}
