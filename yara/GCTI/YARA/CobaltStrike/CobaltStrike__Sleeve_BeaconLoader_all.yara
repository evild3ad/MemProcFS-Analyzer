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

rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
    hash =  "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
   
  strings:
    /*
      C6 45 F0 48 mov     [ebp+var_10], 48h ; 'H'
      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'
      C6 45 F2 61 mov     [ebp+var_E], 61h ; 'a'
      C6 45 F3 70 mov     [ebp+var_D], 70h ; 'p'
      C6 45 F4 41 mov     [ebp+var_C], 41h ; 'A'
      C6 45 F5 6C mov     [ebp+var_B], 6Ch ; 'l'
      C6 45 F6 6C mov     [ebp+var_A], 6Ch ; 'l'
      C6 45 F7 6F mov     [ebp+var_9], 6Fh ; 'o'
      C6 45 F8 63 mov     [ebp+var_8], 63h ; 'c'
      C6 45 F9 00 mov     [ebp+var_7], 0
    */

    $core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 9B 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_MVF_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x86.o (MapViewOfFile) Versions 4.3 through at least 4.6"
    hash =  "cded3791caffbb921e2afa2de4c04546067c3148c187780066e8757e67841b44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 EC 4D mov     [ebp+var_14], 4Dh ; 'M'
      C6 45 ED 61 mov     [ebp+var_13], 61h ; 'a'
      C6 45 EE 70 mov     [ebp+var_12], 70h ; 'p'
      C6 45 EF 56 mov     [ebp+var_11], 56h ; 'V'
      C6 45 F0 69 mov     [ebp+var_10], 69h ; 'i'
      C6 45 F1 65 mov     [ebp+var_F], 65h ; 'e'
      C6 45 F2 77 mov     [ebp+var_E], 77h ; 'w'
      C6 45 F3 4F mov     [ebp+var_D], 4Fh ; 'O'
      C6 45 F4 66 mov     [ebp+var_C], 66h ; 'f'
      C6 45 F5 46 mov     [ebp+var_B], 46h ; 'F'
      C6 45 F6 69 mov     [ebp+var_A], 69h ; 'i'
      C6 45 F7 6C mov     [ebp+var_9], 6Ch ; 'l'
      C6 45 F8 65 mov     [ebp+var_8], 65h ; 'e'
      C6 45 F9 00 mov     [ebp+var_7], 0
    */

    $core_sig = {
      C6 45 EC 4D
      C6 45 ED 61
      C6 45 EE 70
      C6 45 EF 56
      C6 45 F0 69
      C6 45 F1 65
      C6 45 F2 77
      C6 45 F3 4F
      C6 45 F4 66
      C6 45 F5 46
      C6 45 F6 69
      C6 45 F7 6C
      C6 45 F8 65
      C6 45 F9 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 9C 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { 55 F8 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}


rule CobaltStrike_Sleeve_BeaconLoader_VA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x86.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'
      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'
      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'
      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'
      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'
      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'
      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'
      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'
      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'
      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'
      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'
      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'
      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0
    */

    $core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }

    /*
      8B 4D FC    mov     ecx, [ebp+var_4]
      83 C1 01    add     ecx, 1
      89 4D FC    mov     [ebp+var_4], ecx
      8B 55 FC    mov     edx, [ebp+var_4]
      3B 55 0C    cmp     edx, [ebp+arg_4]
      73 19       jnb     short loc_231
      0F B6 45 10 movzx   eax, [ebp+arg_8]
      8B 4D 08    mov     ecx, [ebp+arg_0]
      03 4D FC    add     ecx, [ebp+var_4]
      0F BE 11    movsx   edx, byte ptr [ecx]
      33 D0       xor     edx, eax
      8B 45 08    mov     eax, [ebp+arg_0]
      03 45 FC    add     eax, [ebp+var_4]
      88 10       mov     [eax], dl
      EB D6       jmp     short loc_207
    */

    $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.x86.o Versions 4.3 through at least 4.6"
    hash =  "94d1b993a9d5786e0a9b44ea1c0dc27e225c9eb7960154881715c47f9af78cc1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 45 B0 56 mov     [ebp+var_50], 56h ; 'V'
      C6 45 B1 69 mov     [ebp+var_50+1], 69h ; 'i'
      C6 45 B2 72 mov     [ebp+var_50+2], 72h ; 'r'
      C6 45 B3 74 mov     [ebp+var_50+3], 74h ; 't'
      C6 45 B4 75 mov     [ebp+var_50+4], 75h ; 'u'
      C6 45 B5 61 mov     [ebp+var_50+5], 61h ; 'a'
      C6 45 B6 6C mov     [ebp+var_50+6], 6Ch ; 'l'
      C6 45 B7 41 mov     [ebp+var_50+7], 41h ; 'A'
      C6 45 B8 6C mov     [ebp+var_50+8], 6Ch ; 'l'
      C6 45 B9 6C mov     [ebp+var_50+9], 6Ch ; 'l'
      C6 45 BA 6F mov     [ebp+var_50+0Ah], 6Fh ; 'o'
      C6 45 BB 63 mov     [ebp+var_50+0Bh], 63h ; 'c'
      C6 45 BC 00 mov     [ebp+var_50+0Ch], 0
    */

    $core_sig = {
      C6 45 B0 56
      C6 45 B1 69
      C6 45 B2 72
      C6 45 B3 74
      C6 45 B4 75
      C6 45 B5 61
      C6 45 B6 6C
      C6 45 B7 41
      C6 45 B8 6C
      C6 45 B9 6C
      C6 45 BA 6F
      C6 45 BB 63
      C6 45 BC 00
    }

    /*
      8B 4D FC    mov     ecx, [ebp+var_4]
      83 C1 01    add     ecx, 1
      89 4D FC    mov     [ebp+var_4], ecx
      8B 55 FC    mov     edx, [ebp+var_4]
      3B 55 0C    cmp     edx, [ebp+arg_4]
      73 19       jnb     short loc_231
      0F B6 45 10 movzx   eax, [ebp+arg_8]
      8B 4D 08    mov     ecx, [ebp+arg_0]
      03 4D FC    add     ecx, [ebp+var_4]
      0F BE 11    movsx   edx, byte ptr [ecx]
      33 D0       xor     edx, eax
      8B 45 08    mov     eax, [ebp+arg_0]
      03 45 FC    add     eax, [ebp+var_4]
      88 10       mov     [eax], dl
      EB D6       jmp     short loc_207
    */

    $deobfuscator = {
      8B 4D FC
      83 C1 01
      89 4D FC
      8B 55 FC
      3B 55 0C
      73 19
      0F B6 45 10
      8B 4D 08
      03 4D FC
      0F BE 11
      33 D0
      8B 45 08
      03 45 FC
      88 10
      EB D6
    }
    
  condition:
    $core_sig and not $deobfuscator
}


// 64-bit BeaconLoaders

rule CobaltStrike_Sleeve_BeaconLoader_HA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.HA.x64.o (HeapAlloc) Versions 4.3 through at least 4.6"
    hash =  "d64f10d5a486f0f2215774e8ab56087f32bef19ac666e96c5627c70d345a354d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 38 48 mov     [rsp+78h+var_40], 48h ; 'H'
      C6 44 24 39 65 mov     [rsp+78h+var_3F], 65h ; 'e'
      C6 44 24 3A 61 mov     [rsp+78h+var_3E], 61h ; 'a'
      C6 44 24 3B 70 mov     [rsp+78h+var_3D], 70h ; 'p'
      C6 44 24 3C 41 mov     [rsp+78h+var_3C], 41h ; 'A'
      C6 44 24 3D 6C mov     [rsp+78h+var_3B], 6Ch ; 'l'
      C6 44 24 3E 6C mov     [rsp+78h+var_3A], 6Ch ; 'l'
      C6 44 24 3F 6F mov     [rsp+78h+var_39], 6Fh ; 'o'
      C6 44 24 40 63 mov     [rsp+78h+var_38], 63h ; 'c'
      C6 44 24 41 00 mov     [rsp+78h+var_37], 0
    */

    $core_sig = {
      C6 44 24 38 48
      C6 44 24 39 65
      C6 44 24 3A 61
      C6 44 24 3B 70
      C6 44 24 3C 41
      C6 44 24 3D 6C
      C6 44 24 3E 6C
      C6 44 24 3F 6F
      C6 44 24 40 63
      C6 44 24 41 00
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { D1 56 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}


rule CobaltStrike_Sleeve_BeaconLoader_MVF_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.MVF.x64.o (MapViewOfFile) Versions 4.3 through at least 4.6"
    hash =  "9d5b6ccd0d468da389657309b2dc325851720390f9a5f3d3187aff7d2cd36594"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 58 4D mov     [rsp+98h+var_40], 4Dh ; 'M'
      C6 44 24 59 61 mov     [rsp+98h+var_3F], 61h ; 'a'
      C6 44 24 5A 70 mov     [rsp+98h+var_3E], 70h ; 'p'
      C6 44 24 5B 56 mov     [rsp+98h+var_3D], 56h ; 'V'
      C6 44 24 5C 69 mov     [rsp+98h+var_3C], 69h ; 'i'
      C6 44 24 5D 65 mov     [rsp+98h+var_3B], 65h ; 'e'
      C6 44 24 5E 77 mov     [rsp+98h+var_3A], 77h ; 'w'
      C6 44 24 5F 4F mov     [rsp+98h+var_39], 4Fh ; 'O'
      C6 44 24 60 66 mov     [rsp+98h+var_38], 66h ; 'f'
      C6 44 24 61 46 mov     [rsp+98h+var_37], 46h ; 'F'
      C6 44 24 62 69 mov     [rsp+98h+var_36], 69h ; 'i'
      C6 44 24 63 6C mov     [rsp+98h+var_35], 6Ch ; 'l'
      C6 44 24 64 65 mov     [rsp+98h+var_34], 65h ; 'e'
    */

    $core_sig = {
      C6 44 24 58 4D
      C6 44 24 59 61
      C6 44 24 5A 70
      C6 44 24 5B 56
      C6 44 24 5C 69
      C6 44 24 5D 65
      C6 44 24 5E 77
      C6 44 24 5F 4F
      C6 44 24 60 66
      C6 44 24 61 46
      C6 44 24 62 69
      C6 44 24 63 6C
      C6 44 24 64 65
    }

    // These strings can narrow down the specific version
    //$ver_43 = { 96 2C 3E 60 }         // Version 4.3
    //$ver_44_45_46 = { D2 57 86 5F }   // Versions 4.4, 4.5, and 4.6
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.VA.x64.o (VirtualAlloc) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      C6 44 24 48 56 mov     [rsp+88h+var_40], 56h ; 'V'
      C6 44 24 49 69 mov     [rsp+88h+var_40+1], 69h ; 'i'
      C6 44 24 4A 72 mov     [rsp+88h+var_40+2], 72h ; 'r'
      C6 44 24 4B 74 mov     [rsp+88h+var_40+3], 74h ; 't'
      C6 44 24 4C 75 mov     [rsp+88h+var_40+4], 75h ; 'u'
      C6 44 24 4D 61 mov     [rsp+88h+var_40+5], 61h ; 'a'
      C6 44 24 4E 6C mov     [rsp+88h+var_40+6], 6Ch ; 'l'
      C6 44 24 4F 41 mov     [rsp+88h+var_40+7], 41h ; 'A'
      C6 44 24 50 6C mov     [rsp+88h+var_40+8], 6Ch ; 'l'
      C6 44 24 51 6C mov     [rsp+88h+var_40+9], 6Ch ; 'l'
      C6 44 24 52 6F mov     [rsp+88h+var_40+0Ah], 6Fh ; 'o'
      C6 44 24 53 63 mov     [rsp+88h+var_40+0Bh], 63h ; 'c'
      C6 44 24 54 00 mov     [rsp+88h+var_40+0Ch], 0
    */

    $core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69
      C6 44 24 4A 72
      C6 44 24 4B 74
      C6 44 24 4C 75
      C6 44 24 4D 61
      C6 44 24 4E 6C
      C6 44 24 4F 41
      C6 44 24 50 6C
      C6 44 24 51 6C
      C6 44 24 52 6F
      C6 44 24 53 63
      C6 44 24 54 00
    }


    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_BeaconLoader_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/BeaconLoader.x64.o (Base) Versions 4.3 through at least 4.6"
    hash =  "ac090a0707aa5ccd2c645b523bd23a25999990cf6895fce3bfa3b025e3e8a1c9"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      33 C0                      xor     eax, eax
      83 F8 01                   cmp     eax, 1
      74 63                      jz      short loc_378
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      0F B7 00                   movzx   eax, word ptr [rax]
      3D 4D 5A 00 00             cmp     eax, 5A4Dh
      75 45                      jnz     short loc_369
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      48 63 40 3C                movsxd  rax, dword ptr [rax+3Ch]
      48 89 44 24 28             mov     [rsp+38h+var_10], rax
      48 83 7C 24 28 40          cmp     [rsp+38h+var_10], 40h ; '@'
      72 2F                      jb      short loc_369
      48 81 7C 24 28 00 04 00 00 cmp     [rsp+38h+var_10], 400h
      73 24                      jnb     short loc_369
      48 8B 44 24 20             mov     rax, [rsp+38h+var_18]
      48 8B 4C 24 28             mov     rcx, [rsp+38h+var_10]
      48 03 C8                   add     rcx, rax
      48 8B C1                   mov     rax, rcx
      48 89 44 24 28             mov     [rsp+38h+var_10], rax
      48 8B 44 24 28             mov     rax, [rsp+38h+var_10]
      81 38 50 45 00 00          cmp     dword ptr [rax], 4550h
      75 02                      jnz     short loc_369
    */

    $core_sig = {
      33 C0
      83 F8 01
      74 63
      48 8B 44 24 20
      0F B7 00
      3D 4D 5A 00 00
      75 45
      48 8B 44 24 20
      48 63 40 3C
      48 89 44 24 28
      48 83 7C 24 28 40
      72 2F
      48 81 7C 24 28 00 04 00 00
      73 24
      48 8B 44 24 20
      48 8B 4C 24 28
      48 03 C8
      48 8B C1
      48 89 44 24 28
      48 8B 44 24 28
      81 38 50 45 00 00
      75 02
    }

    /*
      8B 04 24       mov     eax, [rsp+18h+var_18]
      FF C0          inc     eax
      89 04 24       mov     [rsp+18h+var_18], eax
      8B 44 24 28    mov     eax, [rsp+18h+arg_8]
      39 04 24       cmp     [rsp+18h+var_18], eax
      73 20          jnb     short loc_2E7
      8B 04 24       mov     eax, [rsp+18h+var_18]
      0F B6 4C 24 30 movzx   ecx, [rsp+18h+arg_10]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      0F BE 04 02    movsx   eax, byte ptr [rdx+rax]
      33 C1          xor     eax, ecx
      8B 0C 24       mov     ecx, [rsp+18h+var_18]
      48 8B 54 24 20 mov     rdx, [rsp+18h+arg_0]
      88 04 0A       mov     [rdx+rcx], al
    */

    $deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

    
  condition:
    $core_sig and not $deobfuscator
}
