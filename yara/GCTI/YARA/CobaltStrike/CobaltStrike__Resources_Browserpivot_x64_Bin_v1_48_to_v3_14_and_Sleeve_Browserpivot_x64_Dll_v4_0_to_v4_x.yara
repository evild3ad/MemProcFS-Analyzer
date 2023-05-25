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

rule CobaltStrike_Resources_Browserpivot_x64_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_x64_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.x64.bin from v1.48 to v3.14 and sleeve/browserpivot.x64.dll from v4.0 to at least v4.4"
		hash =  "0ad32bc4fbf3189e897805cec0acd68326d9c6f714c543bafb9bc40f7ac63f55"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		FF 15 [4]         call    cs:recv
		83 ?? FF          cmp     eax, 0FFFFFFFFh
		74 ??             jz      short loc_1800018FB
		85 ??             test    eax, eax
		74 ??             jz      short loc_1800018FB
		03 ??             add     ebx, eax
		83 ?? 02          cmp     ebx, 2
		72 ??             jb      short loc_1800018F7
		8D ?? FF          lea     eax, [rbx-1]
		80 [2] 0A         cmp     byte ptr [rax+rdi], 0Ah
		75 ??             jnz     short loc_1800018F7
		8D ?? FE          lea     eax, [rbx-2]
		80 [2] 0D         cmp     byte ptr [rax+rdi], 0Dh
	*/

	$socket_recv = {
			FF 15 [4]
			83 ?? FF
			74 ??
			85 ??
			74 ??
			03 ??
			83 ?? 02
			72 ??
			8D ?? FF
			80 [2] 0A
			75 ??
			8D ?? FE
			80 [2] 0D
		}

  // distinctive regex (sscanf) format string
  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"
		
	condition:
		all of them
}
