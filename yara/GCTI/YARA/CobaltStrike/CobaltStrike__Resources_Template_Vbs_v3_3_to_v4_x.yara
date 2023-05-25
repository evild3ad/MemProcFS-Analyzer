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

rule CobaltStrike_Resources__Template_Vbs_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		hash =  "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	  $ea = "Excel.Application" nocase
    $vis = "Visible = False" nocase
    $wsc = "Wscript.Shell" nocase
    $regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
    $regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
    $regwrite = ".RegWrite" nocase
    $dw = "REG_DWORD"
    $code = ".CodeModule.AddFromString"
	 /* Hex encoded Auto_*/ /*Open */
    $ao = { 41 75 74 6f 5f 4f 70 65 6e }
    $da = ".DisplayAlerts"

  condition:
    all of them
}