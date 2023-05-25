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

rule CobaltStrike_Resources_Xor_Bin_v2_x_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor.bin signature for version 2.x through 4.x"
		hash =  "211ccc5d28b480760ec997ed88ab2fbc5c19420a3d34c1df7991e65642638a6f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	  /* The method for making this signatures consists of extracting each stub from the various resources/xor.bin files
	     in the cobaltstrike.jar files. For each stub found, sort them by byte count (size). Then for all entries in the 
	     same size category, compare them nibble by nibble. Any mismatched nibbles get 0'd. After all stubs have been
	     compared to each other thereby creating a mask, any 0 nibbles are turned to ? wildcards. The results are seen below */
    $stub52 = {fc e8 ?? ?? ?? ?? [1-32] eb 27 5? 8b ??    83 c? ?4 8b ??    31 ?? 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb ea 5? ff e? e8 d4 ff ff ff}
    $stub56 = {fc e8 ?? ?? ?? ?? [1-32] eb 2b 5d 8b ?? ?? 83 c5 ?4 8b ?? ?? 31 ?? 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e8 5? ff e? e8 d? ff ff ff}

  condition:
    any of them
}


