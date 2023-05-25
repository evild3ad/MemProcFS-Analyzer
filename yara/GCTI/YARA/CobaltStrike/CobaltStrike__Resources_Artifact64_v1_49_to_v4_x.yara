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

rule CobaltStrike_Resources_Artifact64_v1_49_v2_x_v3_0_v3_3_thru_v3_14
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.dll,.exe,big.exe,big.dll,bigsvc.exe,big.x64.dll} and resources/rtifactuac(alt)64.dll signature for versions v1.49, v2.x, v3.0, and v3.3 through v3.14"
		hash =  "9ec57d306764517b5956b49d34a3a87d4a6b26a2bb3d0fdb993d055e0cc9920d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		8B [2]      mov     eax, [rbp+var_4]
		48 98       cdqe
		48 89 C1    mov     rcx, rax
		48 03 4D 10 add     rcx, [rbp+arg_0]
		8B 45 FC    mov     eax, [rbp+var_4]
		48 98       cdqe
		48 03 45 10 add     rax, [rbp+arg_0]
		44 0F B6 00 movzx   r8d, byte ptr [rax]
		8B 45 FC    mov     eax, [rbp+var_4]
		89 C2       mov     edx, eax
		C1 FA 1F    sar     edx, 1Fh
		C1 EA 1E    shr     edx, 1Eh
		01 D0       add     eax, edx
		83 E0 03    and     eax, 3
		29 D0       sub     eax, edx
		48 98       cdqe
		48 03 45 20 add     rax, [rbp+arg_10]
		0F B6 00    movzx   eax, byte ptr [rax]
		44 31 C0    xor     eax, r8d
		88 01       mov     [rcx], al
	*/

	$a = { 8B [2] 48 98 48 [2] 48 [3] 8B [2] 48 98 48 [3] 44 [3] 8B [2] 89 ?? C1 ?? 1F C1 ?? 1E 01 ?? 83 ?? 03 29 ?? 48 98 48 [3] 0F B6 00 44 [2] 88 }
		
	condition:
		$a
}

rule CobaltStrike_Resources_Artifact64_v3_1_v3_2_v3_14_and_v4_0
{
	meta:
		description = "Cobalt Strike's resources/artifact64{svcbig.exe,.dll,big.dll,svc.exe} and resources/artifactuac(big)64.dll signature for versions 3.14 to 4.x and resources/artifact32svc.exe for 3.14 to 4.x"
		hash =  "2e7a39bd6ac270f8f548855b97c4cef2c2ce7f54c54dd4d1aa0efabeecf3ba90"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		31 C0                xor     eax, eax
		EB 0F                jmp     short loc_6BAC16B5
		41 83 E1 03          and     r9d, 3
		47 8A 0C 08          mov     r9b, [r8+r9]
		44 30 0C 01          xor     [rcx+rax], r9b
		48 FF C0             inc     rax
		39 D0                cmp     eax, edx
		41 89 C1             mov     r9d, eax
		7C EA                jl      short loc_6BAC16A6
		4C 8D 05 53 29 00 00 lea     r8, aRundll32Exe; "rundll32.exe"
		E9 D1 FE FF FF       jmp     sub_6BAC1599
	*/

	$decoderFunction = { 31 ?? EB 0F 41 [2] 03 47 [3] 44 [3] 48 [2] 39 ?? 41 [2] 7C EA 4C [6] E9 }

	condition:
		$decoderFunction
}

rule CobaltStrike_Resources_Artifact64_v3_14_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/artifact64{.exe,.dll,svc.exe,svcbig.exe,big.exe,big.dll,.x64.dll,big.x64.dll} and resource/artifactuac(alt)64.exe signature for versions v3.14 through v4.x"
		hash =  "decfcca0018f2cec4a200ea057c804bb357300a67c6393b097d52881527b1c44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		41 B8 5C 00 00 00       mov     r8d, 5Ch ; '\'
		C7 44 24 50 5C 00 00 00 mov     [rsp+68h+var_18], 5Ch ; '\'
		C7 44 24 48 65 00 00 00 mov     [rsp+68h+var_20], 65h ; 'e'
		C7 44 24 40 70 00 00 00 mov     [rsp+68h+var_28], 70h ; 'p'
		C7 44 24 38 69 00 00 00 mov     [rsp+68h+var_30], 69h ; 'i'
		C7 44 24 30 70 00 00 00 mov     [rsp+68h+var_38], 70h ; 'p'
		C7 44 24 28 5C 00 00 00 mov     dword ptr [rsp+68h+lpThreadId], 5Ch ; '\'
		C7 44 24 20 2E 00 00 00 mov     [rsp+68h+dwCreationFlags], 2Eh ; '.'
		89 54 24 58             mov     [rsp+68h+var_10], edx
		48 8D 15 22 38 00 00    lea     rdx, Format; Format
		E8 0D 17 00 00          call    sprintf
	*/

	$fmtBuilder = {
			41 ?? 5C 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 65 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 69 00 00 00
			C7 [3] 70 00 00 00
			C7 [3] 5C 00 00 00
			C7 [3] 2E 00 00 00
			89 [3]
			48 [6]
			E8
		}

  $fmtString = "%c%c%c%c%c%c%c%c%cMSSE-%d-server"
		
	condition:
		all of them
}
