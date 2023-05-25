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

rule CobaltStrike_Resources_Artifact32svc_Exe_v1_49_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe and resources/artifact32uac(alt).exe signature for versions v1.49 to v3.14"
		hash =  "323ddf9623368b550def9e8980fde0557b6fe2dcd945fda97aa3b31c6c36d682"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		8B [2]   mov     eax, [ebp+var_C]
		89 ??    mov     ecx, eax
		03 [2]   add     ecx, [ebp+lpBuffer]
		8B [2]   mov     eax, [ebp+var_C]
		03 [2]   add     eax, [ebp+lpBuffer]
		0F B6 18 movzx   ebx, byte ptr [eax]
		8B [2]   mov     eax, [ebp+var_C]
		89 ??    mov     edx, eax
		C1 [2]   sar     edx, 1Fh
		C1 [2]   shr     edx, 1Eh
		01 ??    add     eax, edx
		83 [2]   and     eax, 3
		29 ??    sub     eax, edx
		03 [2]   add     eax, [ebp+arg_8]
		0F B6 00 movzx   eax, byte ptr [eax]
		31 ??    xor     eax, ebx
		88 ??    mov     [ecx], al
	*/

	$decoderFunc = { 8B [2] 89 ?? 03 [2] 8B [2] 03 [5] 8B [2] 89 ?? C1 [2] C1 [2] 01 ?? 83 [2] 29 ?? 03 [5] 31 ?? 88 }
	
	condition:
		any of them
}

rule CobaltStrike_Resources_Artifact32svc_Exe_v3_1_v3_2_v3_14_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact32svc(big).exe signature for versions 3.1 and 3.2 (with overlap with v3.14 through v4.x)"
		hash =  "871390255156ce35221478c7837c52d926dfd581173818620b738b4b029e6fd9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		89 ??           mov     eax, ecx
		B? 04 00 00 00  mov     edi, 4
		99              cdq
		F7 FF           idiv    edi
		8B [2]          mov     edi, [ebp+var_20]
		8A [2]          mov     al, [edi+edx]
		30 [2]          xor     [ebx+ecx], al
	*/

	$decoderFunc  = { 89 ?? B? 04 00 00 00 99 F7 FF 8B [2] 8A [2] 30 }

	condition:
		$decoderFunc
}
