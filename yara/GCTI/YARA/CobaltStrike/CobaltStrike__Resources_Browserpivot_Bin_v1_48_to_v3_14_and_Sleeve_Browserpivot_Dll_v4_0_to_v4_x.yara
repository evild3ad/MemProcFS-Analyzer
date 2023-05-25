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

rule  CobaltStrike__Resources_Browserpivot_Bin_v1_48_to_v3_14_and_Sleeve_Browserpivot_Dll_v4_0_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/browserpivot.bin from v1.48 to v3.14 and sleeve/browserpivot.dll from v4.0 to at least v4.4"
		hash =  "12af9f5a7e9bfc49c82a33d38437e2f3f601639afbcdc9be264d3a8d84fd5539"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	/*
		FF [1-5]        call    ds:recv               // earlier versions (v1.x to 2.x) this is CALL EBP
		83 ?? FF        cmp     eax, 0FFFFFFFFh
		74 ??           jz      short loc_100020D5
		85 C0           test    eax, eax
		(74  | 76) ??   jz      short loc_100020D5    // earlier versions (v1.x to 2.x) used jbe (76) here
		03 ??           add     esi, eax
		83 ?? 02        cmp     esi, 2
		72 ??           jb      short loc_100020D1
		80 ?? 3E FF 0A  cmp     byte ptr [esi+edi-1], 0Ah
		75 ??           jnz     short loc_100020D1
		80 ?? 3E FE 0D  cmp     byte ptr [esi+edi-2], 0Dh
	*/

	$socket_recv = {
			FF [1-5]
			83 ?? FF 
			74 ?? 
			85 C0
			(74 | 76) ?? 
			03 ?? 
			83 ?? 02 
			72 ?? 
			80 ?? 3E FF 0A 
			75 ?? 
			80 ?? 3E FE 0D 
		}
		
  // distinctive regex (sscanf) format string
  $fmt = "%1024[^ ] %8[^:]://%1016[^/]%7168[^ ] %1024[^ ]"

	condition:
		all of them
}