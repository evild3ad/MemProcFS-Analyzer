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

rule CobaltStrike_Resources_Template__x32_x64_Ps1_v1_45_to_v2_5_and_v3_11_to_v3_14
{
	meta:
		description = "Cobalt Strike's resources/template.x64.ps1, resources/template.x32 from v3.11 to v3.14 and resources/template.ps1 from v1.45 to v2.5 "
		hash =  "ff743027a6bcc0fee02107236c1f5c96362eeb91f3a5a2e520a85294741ded87"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		
	strings:
	
		$importVA = "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc" nocase
		$importCT = "[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread" nocase
		$importWFSO = "[DllImport(\"kernel32.dll\")] public static extern int WaitForSingleObject" nocase
    $compiler = "New-Object Microsoft.CSharp.CSharpCodeProvider" nocase
    $params = "New-Object System.CodeDom.Compiler.CompilerParameters" nocase
    $paramsSys32 = ".ReferencedAssemblies.AddRange(@(\"System.dll\", [PsObject].Assembly.Location))" nocase
    $paramsGIM = ".GenerateInMemory = $True" nocase
    $result = "$compiler.CompileAssemblyFromSource($params, $assembly)" nocase
    //$data = "[Byte[]]$var_code = [System.Convert]::FromBase64String(" nocase

    //$64bitSpecific = "[IntPtr]::size -eq 8"
    
    
  condition:
    all of them
}