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

rule CobaltStrike_Resources_Beacon_Dll_v1_44
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.44"
    hash = "75102e8041c58768477f5f982500da7e03498643b6ece86194f4b3396215f9c2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      0F B7 D2  movzx   edx, dx
      4A        dec     edx; switch 5 cases
      53        push    ebx
      8B D9     mov     ebx, ecx; a2
      83 FA 04  cmp     edx, 4
      77 36     ja      short def_1000106C; jumptable 1000106C default case
      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump
    */
    $version_sig = { 0F B7 D2 4A 53 8B D9 83 FA 04 77 36 FF 24 }
    
    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_10018F20[eax], cl
      40             inc     eax
      3D 28 01 00 00 cmp     eax, 128h
      7C F2          jl      short loc_10001AD4
    */
    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }    
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_45
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.45"
    hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      51        push    ecx
      0F B7 D2  movzx   edx, dx
      4A        dec     edx; switch 9 cases
      53        push    ebx
      56        push    esi
      83 FA 08  cmp     edx, 8
      77 6B     ja      short def_1000106C; jumptable 1000106C default case
      FF 24 ??  jmp     ds:jpt_1000106C[edx*4]; switch jump
    */
    $version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_10019F20[eax], cl
      40             inc     eax
      3D 28 01 00 00 cmp     eax, 128h
      7C F2          jl      short loc_10002664
    */
    $decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_46
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.46"
    hash = "44e34f4024878024d4804246f57a2b819020c88ba7de160415be38cd6b5e2f76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      8B F2             mov     esi, edx
      83 F9 0C          cmp     ecx, 0Ch
      0F 87 8E 00 00 00 ja      def_1000107F; jumptable 1000107F default case, case 8
      FF 24 ??          jmp     ds:jpt_1000107F[ecx*4]; switch jump
    */   
    $version_sig = { 8B F2 83 F9 0C 0F 87 8E 00 00 00 FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001D040[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
      7C F2          jl      short loc_10002A04
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_47
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.47"
    hash = "8ff6dc80581804391183303bb39fca2a5aba5fe13d81886ab21dbd183d536c8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 F8 12  cmp     eax, 12h
      77 10     ja      short def_100010BB; jumptable 100010BB default case, case 8
      FF 24 ??  jmp     ds:jpt_100010BB[eax*4]; switch jump
    */
    $version_sig = { 83 F8 12 77 10 FF 24 }

    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001E040[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_48
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.48"
    hash = "dd4e445572cd5e32d7e9cc121e8de337e6f19ff07547e3f2c6b7fce7eafd15e4"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48        dec     eax; switch 24 cases
      57        push    edi
      8B F1     mov     esi, ecx
      8B DA     mov     ebx, edx
      83 F8 17  cmp     eax, 17h
      77 12     ja      short def_1000115D; jumptable 1000115D default case, case 8
      FF 24 ??  jmp     ds:jpt_1000115D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 8B DA 83 F8 17 77 12 FF 24 }
    
    /*
      B1 69          mov     cl, 69h ; 'i'
      30 88 [4]      xor     byte ptr word_1001F048[eax], cl
      40             inc     eax
      3D A8 01 00 00 cmp     eax, 1A8h
      7C F2          jl      short loc_100047B4
    */
    $decode = { B1 ?? 30 88 [4] 40 3D A8 01 00 00 7C F2 }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v1_49
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 1.49"
    hash = "52b4bd87e21ee0cbaaa0fc007fd3f894c5fc2c4bae5cbc2a37188de3c2c465fe"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                   dec     eax; switch 31 cases
      56                   push    esi
      83 F8 1E             cmp     eax, 1Eh
      0F 87 23 01 00 00    ja      def_1000115B; jumptable 1000115B default case, cases 8,30
      FF 24 85 80 12 00 10 jmp     ds:jpt_1000115B[eax*4]; switch jump
    */
    $version_sig = { 48 56 83 F8 1E 0F 87 23 01 00 00 FF 24 }
    
    /*
      B1 69            mov     cl, 69h ; 'i'
      90               nop
      30 88 [4]        xor     byte ptr word_10022038[eax], cl
      40               inc     eax
      3D A8 01 00 00   cmp     eax, 1A8h
      7C F2            jl      short loc_10005940
    */    
    $decoder = { B1 ?? 90 30 88 [4] 40 3D A8 01 00 00 7C F2 }
      
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_0_49
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Version 2.0.49"
    hash = "ed08c1a21906e313f619adaa0a6e5eb8120cddd17d0084a30ada306f2aca3a4e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 F8 22          cmp     eax, 22h
      0F 87 96 01 00 00 ja      def_1000115D; jumptable 1000115D default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000115D[eax*4]; switch jump
    */
    $version_sig = { 83 F8 22 0F 87 96 01 00 00 FF 24 }

    /*
      B1 69            mov     cl, 69h ; 'i'
      EB 03            jmp     short loc_10006930
      8D 49 00         lea     ecx, [ecx+0]
      30 88 [4]        xor     byte ptr word_10023038[eax], cl
      40               inc     eax
      3D 30 05 00 00   cmp     eax, 530h
      72 F2            jb      short loc_10006930
    */
    $decoder = { B1 ?? EB 03 8D 49 00 30 88 [4] 40 3D 30 05 00 00 72 F2  }
  
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_1_and_v2_2
{
  // v2.1 and v2.2 use the exact same beacon binary (matching hashes)
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.1 and 2.2"
    hash = "ae7a1d12e98b8c9090abe19bcaddbde8db7b119c73f7b40e76cdebb2610afdc2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      49                dec     ecx; switch 37 cases
      56                push    esi
      57                push    edi
      83 F9 24          cmp     ecx, 24h
      0F 87 8A 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump
    */
    $version_sig = { 49 56 57 83 F9 24 0F 87 8A 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_3
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.3"
    hash = "00dd982cb9b37f6effb1a5a057b6571e533aac5e9e9ee39a399bb3637775ff83"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      49                dec     ecx; switch 39 cases
      56                push    esi
      57                push    edi
      83 F9 26          cmp     ecx, 26h
      0F 87 A9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 8,30
      FF 24 ??          jmp     ds:jpt_1000112E[ecx*4]; switch jump
    */
    $version_sig = { 49 56 57 83 F9 26 0F 87 A9 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_4
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.4"
    hash = "78c6f3f2b80e6140c4038e9c2bcd523a1b205d27187e37dc039ede4cf560beed"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      4A                dec     edx; switch 48 cases
      56                push    esi
      57                push    edi
      83 FA 2F          cmp     edx, 2Fh
      0F 87 F9 01 00 00 ja      def_1000112E; jumptable 1000112E default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_1000112E[edx*4]; switch jump
    */
    $version_sig = { 4A 56 57 83 FA 2F 0F 87 F9 01 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v2_5
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 2.5"
    hash = "d99693e3e521f42d19824955bef0cefb79b3a9dbf30f0d832180577674ee2b58"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 59 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3A          cmp     eax, 3Ah
      0F 87 6E 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3A 0F 87 6E 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_0
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.0"
    hash = "30251f22df7f1be8bc75390a2f208b7514647835f07593f25e470342fd2e3f52"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 61 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3C          cmp     eax, 3Ch
      0F 87 89 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3C 0F 87 89 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_1
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.1"
    hash = "4de723e784ef4e1633bbbd65e7665adcfb03dd75505b2f17d358d5a40b7f35cf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  // v3.1 and v3.2 share the same C2 handler code. We are using a function that
  // is not included in v3.2 to mark the v3.1 version along with the decoder
  // which allows us to narrow in on only v3.1 samples
  strings:
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_2
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.2"
    hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"
    rs2 ="a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 62 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3D          cmp     eax, 3Dh
      0F 87 83 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

    // Since v3.1 and v3.2 are so similiar, we use the v3.1 version_sig
    // as a negating condition to diff between 3.1 and 3.2
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

  condition:
    $version_sig and $decoder and not $version3_1_sig
}

rule CobaltStrike_Resources_Beacon_Dll_v3_3
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.3"
    hash = "158dba14099f847816e2fc22f254c60e09ac999b6c6e2ba6f90c6dd6d937bc42"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 66 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 41          cmp     eax, 41h
      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 41 0F 87 F0 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_4
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.4"
    hash = "5c40bfa04a957d68a095dd33431df883e3a075f5b7dea3e0be9834ce6d92daa3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 67 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 42          cmp     eax, 42h
      0F 87 F0 02 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 42 0F 87 F0 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_5_hf1_and_3_5_1
{
  // Version 3.5-hf1 and 3.5.1 use the exact same beacon binary (same hash)
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.5-hf1 and 3.5.1 (3.5.x)"
    hash = "c78e70cd74f4acda7d1d0bd85854ccacec79983565425e98c16a9871f1950525"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 68 cases
      57                push    edi
      8B F1             mov     esi, ecx
      83 F8 43          cmp     eax, 43h
      0F 87 07 03 00 00 ja      def_1000112D; jumptable 1000112D default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000112D[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F1 83 F8 43 0F 87 07 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_6
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.6"
    hash = "495a744d0a0b5f08479c53739d08bfbd1f3b9818d8a9cbc75e71fcda6c30207d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 72 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 47          cmp     eax, 47h
      0F 87 2F 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F9 83 F8 47 0F 87 2F 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_7
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.7"
    hash = "f18029e6b12158fb3993f4951dab2dc6e645bb805ae515d205a53a1ef41ca9b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 74 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 49          cmp     eax, 49h
      0F 87 47 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */   
    $version_sig = { 48 57 8B F9 83 F8 49 0F 87 47 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_8
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.8"
    hash = "67b6557f614af118a4c409c992c0d9a0cc800025f77861ecf1f3bbc7c293d603"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 76 cases
      57                push    edi
      8B F9             mov     edi, ecx
      83 F8 4B          cmp     eax, 4Bh
      0F 87 5D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 6-8,26,30
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F9 83 F8 4B 0F 87 5D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

    // XMRig uses a v3.8 sample to trick sandboxes into running their code. 
    // These samples are the same and useless. This string removes many
    // of them from our detection
    $xmrig_srcpath = "C:/Users/SKOL-NOTE/Desktop/Loader/script.go"
    // To remove others, we look for known xmrig C2 domains in the config:
    $c2_1 = "ns7.softline.top" xor
    $c2_2 = "ns8.softline.top" xor
    $c2_3 = "ns9.softline.top" xor
    //$a = /[A-Za-z]{1020}.{4}$/
    
  condition:
    $version_sig and $decoder and (2 of ($c2_*) or $xmrig_srcpath)
}

/*

  missing specific signatures for 3.9 and 3.10 since we don't have samples

*/

rule CobaltStrike_Resources_Beacon_Dll_v3_11
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.11"
    hash = "2428b93464585229fd234677627431cae09cfaeb1362fe4f648b8bee59d68f29"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  // Original version from April 9, 2018
  strings:
    /*
      48                dec     eax; switch 81 cases
      57                push    edi
      8B FA             mov     edi, edx
      83 F8 50          cmp     eax, 50h
      0F 87 11 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 11 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_11_bugfix_and_v3_12
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.11-bugfix and 3.12"
    hash = "5912c96fffeabb2c5c5cdd4387cfbfafad5f2e995f310ace76ca3643b866e3aa"
    rs2 ="4476a93abe48b7481c7b13dc912090b9476a2cdf46a1c4287b253098e3523192"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  // Covers both 3.11 (bug fix form May 25, 2018) and v3.12
  strings:
    /*
      48                dec     eax; switch 81 cases
      57                push    edi
      8B FA             mov     edi, edx
      83 F8 50          cmp     eax, 50h
      0F 87 0D 03 00 00 ja      def_1000100F; jumptable 1000100F default case, cases 2,6-8,26,30,36
      FF 24 ??          jmp     ds:jpt_1000100F[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B FA 83 F8 50 0F 87 0D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_13
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.13"
    hash = "362119e3bce42e91cba662ea80f1a7957a5c2b1e92075a28352542f31ac46a0c"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      4A                dec     edx; switch 91 cases
      56                push    esi
      57                push    edi
      83 FA 5A          cmp     edx, 5Ah
      0F 87 2D 03 00 00 ja      def_10008D01; jumptable 10008D01 default case, cases 2,6-8,20,21,26,30,36,63-66
      FF 24 ??          jmp     ds:jpt_10008D01[edx*4]; switch jump
    */
    $version_sig = { 4A 56 57 83 FA 5A 0F 87 2D 03 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_Dll_v3_14
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.14"
    hash = "254c68a92a7108e8c411c7b5b87a2f14654cd9f1324b344f036f6d3b6c7accda"
    rs2 ="87b3eb55a346b52fb42b140c03ac93fc82f5a7f80697801d3f05aea1ad236730"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      83 FA 5B  cmp     edx, 5Bh
      77 15     ja      short def_1000939E; jumptable 1000939E default case, cases 2,6-8,20,21,26,30,36,63-66
      FF 24 ??  jmp     ds:jpt_1000939E[edx*4]; switch jump
    */
    $version_sig = { 83 FA 5B 77 15 FF 24 }

    /*
      80 B0 [4] 69   xor     byte_1002E020[eax], 69h
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10008741
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_0_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.0 (suspected, not confirmed)"
    hash =  "e2b2b72454776531bbc6a4a5dd579404250901557f887a6bccaee287ac71b248"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      51                   push    ecx
      4A                   dec     edx; switch 99 cases
      56                   push    esi
      57                   push    edi
      83 FA 62             cmp     edx, 62h
      0F 87 8F 03 00 00    ja      def_100077C3; jumptable 100077C3 default case, cases 2,6-8,20,21,25,26,30,34-36,63-66
      FF 24 95 56 7B 00 10 jmp     ds:jpt_100077C3[edx*4]; switch jump
    */

    $version_sig = { 51 4A 56 57 83 FA 62 0F 87 8F 03 00 00 FF 24 95 56 7B 00 10 }

    /*
      80 B0 20 00 03 10 ??  xor     byte_10030020[eax], 2Eh
      40                    inc     eax
      3D 00 10 00 00        cmp     eax, 1000h
      7C F1                 jl      short loc_1000912B
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_1_and_v4_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.1 and 4.2"
    hash = "daa42f4380cccf8729129768f3588bb98e4833b0c40ad0620bb575b5674d5fc3"
    rs2 ="9de55f27224a4ddb6b2643224a5da9478999c7b2dea3a3d6b3e1808148012bcf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 100 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 63          cmp     eax, 63h
      0F 87 3C 03 00 00 ja      def_10007F28; jumptable 10007F28 default case, cases 2,6-8,20,21,25,26,29,30,34-36,58,63-66,80,81,95-97
      FF 24 ??          jmp     ds:jpt_10007F28[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 63 0F 87 3C 03 00 00 FF 24 }

    /*
      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10009791
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_3_v4_4_v4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"
    hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"
    rs2 ="78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      48                dec     eax; switch 102 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 65          cmp     eax, 65h
      0F 87 47 03 00 00 ja      def_10007EAD; jumptable 10007EAD default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
      FF 24 ??          jmp     ds:jpt_10007EAD[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }

    /*
      80 B0 [4] 3E   xor     byte_10031010[eax], 3Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_10009791
    */
    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_Dll_v4_7_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.dll Versions 4.7 (suspected, not confirmed)"
    hash =  "da9e91b3d8df3d53425dd298778782be3bdcda40037bd5c92928395153160549"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:

    /*
      53                push    ebx
      56                push    esi
      48                dec     eax; switch 104 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 67          cmp     eax, 67h
      0F 87 5E 03 00 00 ja      def_10008997; jumptable 10008997 default case, cases 2,6-8,20,21,25,26,29,30,34-36,48,58,63-66,80,81,95-97
    */
    $version_sig = { 53 56 48 57 8B F2 83 F8 67 0F 87 5E 03 00 00  }

    /*
      80 B0 [5]      xor     byte_10033020[eax], 2Eh
      40             inc     eax
      3D 00 10 00 00 cmp     eax, 1000h
      7C F1          jl      short loc_1000ADA1
    */

    $decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

/*

 64-bit Beacons.
 
 These signatures are a bit different. The decoders are all identical in the 4.x
 series and the command processor doesn't use a switch/case idiom, but rather
 an expanded set of if/then/else branches. This invalidates our method for
 detecting the versions of the beacons by looking at the case count check
 used by the 32-bit versions. As such, we are locking in on "random",
 non-overlapping between version, sections of code in the command processor. 
 While a reasonable method is to look for blocks of Jcc which will have specific
 address offsets per version, this generally is insufficient due to the lack of 
 code changes. As such, the best method appears to be to look for specific
 function call offsets

 NOTE: There are only VERY subtle differences between the following versions:
  * 3.2 and 3.3
  * 3.4 and 3.5-hf1/3.5.1
  * 3.12, 3.13 and 3.14
  * 4.3 and 4.4-4.6 . 
  
 Be very careful if you modify the $version_sig field for either of those rules. 
*/


rule CobaltStrike_Resources_Beacon_x64_v3_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.2"
    hash =  "5993a027f301f37f3236551e6ded520e96872723a91042bfc54775dcb34c94a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      4C 8D 05 9F F8 FF FF lea     r8, sub_18000C4B0
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 05 1A 00 00       call    sub_18000E620
      EB 0A                jmp     short loc_18000CC27
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 41 21 00 00       call    sub_18000ED68
      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20          add     rsp, 20h
    */

    $version_sig = { 4C 8D 05 9F F8 FF FF 8B D3 48 8B CF E8 05 1A 00 00
                     EB 0A 8B D3 48 8B CF E8 41 21 00 00 48 8B 5C 24 30
                     48 83 C4 20 }
    
    /*
      80 31 ??          xor     byte ptr [rcx], 69h
      FF C2             inc     edx
      48 FF C1          inc     rcx
      48 63 C2          movsxd  rax, edx
      48 3D 10 06 00 00 cmp     rax, 610h
    */

    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_3
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.3"
    hash =  "7b00721efeff6ed94ab108477d57b03022692e288cc5814feb5e9d83e3788580"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3                mov     edx, ebx
      48 8B CF             mov     rcx, rdi
      E8 89 66 00 00       call    sub_1800155E8
      E9 23 FB FF FF       jmp     loc_18000EA87
      41 B8 01 00 00 00    mov     r8d, 1
      E9 F3 FD FF FF       jmp     loc_18000ED62
      48 8D 0D 2A F8 FF FF lea     rcx, sub_18000E7A0
      E8 8D 2B 00 00       call    sub_180011B08
      48 8B 5C 24 30       mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20          add     rsp, 20h
    */

    $version_sig = { 8B D3 48 8B CF E8 89 66 00 00 E9 23 FB FF FF 
                     41 B8 01 00 00 00 E9 F3 FD FF FF 48 8D 0D 2A F8 FF FF
                     E8 8D 2B 00 00 48 8B 5C 24 30 48 83 C4 20 }

    /*
      80 31 ??          xor     byte ptr [rcx], 69h
      FF C2             inc     edx
      48 FF C1          inc     rcx
      48 63 C2          movsxd  rax, edx
      48 3D 10 06 00 00 cmp     rax, 610h
    */

    $decoder = { 80 31 ?? FF C2 48 FF C1 48 63 C2 48 3D 10 06 00 00 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_4
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.4"
    hash =  "5a4d48c2eda8cda79dc130f8306699c8203e026533ce5691bf90363473733bf0"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 56 6F 00 00    call    sub_180014458
      E9 17 FB FF FF    jmp     loc_18000D01E
      41 B8 01 00 00 00 mov     r8d, 1
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 41 4D 00 00    call    sub_180012258
      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20       add     rsp, 20h
    */
    $version_sig = { 8B D3 48 8B CF E8 56 6F 00 00 E9 17 FB FF FF
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 41 4D 00 00
                     48 8B 5C 24 30 48 83 C4 20 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_18001600E
    */
    
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_5_hf1_and_v3_5_1
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.5-hf1 and 3.5.1"
    hash =  "934134ab0ee65ec76ae98a9bb9ad0e9571d80f4bf1eb3491d58bacf06d42dc8d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 38 70 00 00    call    sub_180014548
      E9 FD FA FF FF    jmp     loc_18000D012
      41 B8 01 00 00 00 mov     r8d, 1
      8B D3             mov     edx, ebx
      48 8B CF          mov     rcx, rdi
      E8 3F 4D 00 00    call    sub_180012264
      48 8B 5C 24 30    mov     rbx, [rsp+28h+arg_0]
      48 83 C4 20       add     rsp, 20h
      5F                pop     rdi
    */

    $version_sig = { 8B D3 48 8B CF E8 38 70 00 00 E9 FD FA FF FF 
                     41 B8 01 00 00 00 8B D3 48 8B CF E8 3F 4D 00 00 
                     48 8B 5C 24 30 48 83 C4 20 5F }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016B3E
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.6"
    hash =  "92b0a4aec6a493bcb1b72ce04dd477fd1af5effa0b88a9d8283f26266bb019a1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 89 5C 24 08    mov     [rsp+arg_0], rbx
      57                push    rdi
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 27          cmp     ecx, 27h ; '''
      0F 87 47 03 00 00 ja      loc_18000D110
      0F 84 30 03 00 00 jz      loc_18000D0FF
      83 F9 14          cmp     ecx, 14h
      0F 87 A4 01 00 00 ja      loc_18000CF7C
      0F 84 7A 01 00 00 jz      loc_18000CF58
      83 F9 0C          cmp     ecx, 0Ch
      0F 87 C8 00 00 00 ja      loc_18000CEAF
      0F 84 B3 00 00 00 jz      loc_18000CEA0
    */
    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 27
                     0F 87 47 03 00 00 0F 84 30 03 00 00 83 F9 14
                     0F 87 A4 01 00 00 0F 84 7A 01 00 00 83 F9 0C
                     0F 87 C8 00 00 00 0F 84 B3 00 00 00 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016B3E
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_7
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.7"
    hash =  "81296a65a24c0f6f22208b0d29e7bb803569746ce562e2fa0d623183a8bcca60"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 89 5C 24 08    mov     [rsp+arg_0], rbx
      57                push    rdi
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 28          cmp     ecx, 28h ; '('
      0F 87 7F 03 00 00 ja      loc_18000D148
      0F 84 67 03 00 00 jz      loc_18000D136
      83 F9 15          cmp     ecx, 15h
      0F 87 DB 01 00 00 ja      loc_18000CFB3
      0F 84 BF 01 00 00 jz      loc_18000CF9D
    */

    $version_sig = { 48 89 5C 24 08 57 48 83 EC 20 41 8B D8 48 8B FA 83 F9 28
                     0F 87 7F 03 00 00 0F 84 67 03 00 00 83 F9 15
                     0F 87 DB 01 00 00 0F 84 BF 01 00 00 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180016ECA
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_8
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.8"
    hash =  "547d44669dba97a32cb9e95cfb8d3cd278e00599e6a11080df1a9d09226f33ae"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 7A 52 00 00 call    sub_18001269C
      EB 0D          jmp     short loc_18000D431
      45 33 C0       xor     r8d, r8d
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi; Src
      E8 8F 55 00 00 call    sub_1800129C0
    */

    $version_sig = { 8B D3 48 8B CF E8 7A 52 00 00 EB 0D 45 33 C0 8B D3 48 8B CF
                     E8 8F 55 00 00 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_18001772E
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_11
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.11 (two subversions)"
    hash =  "64007e104dddb6b5d5153399d850f1e1f1720d222bed19a26d0b1c500a675b1a"
    rs2 = "815f313e0835e7fdf4a6d93f2774cf642012fd21ce870c48ff489555012e0047"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
	
    /*
      48 83 EC 20       sub     rsp, 20h
      41 8B D8          mov     ebx, r8d
      48 8B FA          mov     rdi, rdx
      83 F9 2D          cmp     ecx, 2Dh ; '-'
      0F 87 B2 03 00 00 ja      loc_18000D1EF
      0F 84 90 03 00 00 jz      loc_18000D1D3
      83 F9 17          cmp     ecx, 17h
      0F 87 F8 01 00 00 ja      loc_18000D044
      0F 84 DC 01 00 00 jz      loc_18000D02E
      83 F9 0E          cmp     ecx, 0Eh
      0F 87 F9 00 00 00 ja      loc_18000CF54
      0F 84 DD 00 00 00 jz      loc_18000CF3E
      FF C9             dec     ecx
      0F 84 C0 00 00 00 jz      loc_18000CF29
      83 E9 02          sub     ecx, 2
      0F 84 A6 00 00 00 jz      loc_18000CF18
      FF C9             dec     ecx
    */

    $version_sig = { 48 83 EC 20 41 8B D8 48 8B FA 83 F9 2D 0F 87 B2 03 00 00
                     0F 84 90 03 00 00 83 F9 17 0F 87 F8 01 00 00
                     0F 84 DC 01 00 00 83 F9 0E 0F 87 F9 00 00 00
                     0F 84 DD 00 00 00 FF C9 0F 84 C0 00 00 00 83 E9 02
                     0F 84 A6 00 00 00 FF C9 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180017DCA
    */

    $decoder = {
      80 34 28 ?? 
      48 FF C0
      48 3D 00 10 00 00
      7C F1
    }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_12
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.12"
    hash =  "8a28b7a7e32ace2c52c582d0076939d4f10f41f4e5fa82551e7cc8bdbcd77ebc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 F8 2E 00 00 call    sub_180010384
      EB 16          jmp     short loc_18000D4A4
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 00 5C 00 00 call    f_OTH__Command_75
      EB 0A          jmp     short loc_18000D4A4
      8B D3          mov     edx, ebx
      48 8B CF       mov     rcx, rdi
      E8 64 4F 00 00 call    f_OTH__Command_74
    */
    $version_sig = { 8B D3 48 8B CF E8 F8 2E 00 00 EB 16 8B D3 48 8B CF
                     E8 00 5C 00 00 EB 0A 8B D3 48 8B CF E8 64 4F 00 00 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018205
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Resources_Beacon_x64_v3_13
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.13"
    hash =  "945e10dcd57ba23763481981c6035e0d0427f1d3ba71e75decd94b93f050538e"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      48 8D 0D 01 5B FF FF lea     rcx, f_NET__ExfiltrateData
      48 83 C4 28          add     rsp, 28h
      E9 A8 54 FF FF       jmp     f_OTH__Command_85
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; lpSrc
      E8 22 55 FF FF       call    f_OTH__Command_84
    */

    $version_sig = { 48 8D 0D 01 5B FF FF 48 83 C4 28 E9 A8 54 FF FF 8B D0
                     49 8B CA E8 22 55 FF FF }
      
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018C01
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Resources_Beacon_x64_v3_14
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.14"
    hash =  "297a8658aaa4a76599a7b79cb0da5b8aa573dd26c9e2c8f071e591200cf30c93"
    rs2 = "39b9040e3dcd1421a36e02df78fe031cbdd2fb1a9083260b8aedea7c2bc406bf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:

    /*
      8B D0          mov     edx, eax
      49 8B CA       mov     rcx, r10; Src
      48 83 C4 28    add     rsp, 28h
      E9 B1 1F 00 00 jmp     f_OTH__Command_69
      8B D0          mov     edx, eax
      49 8B CA       mov     rcx, r10; Source
      48 83 C4 28    add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA
                     48 83 C4 28 }
    
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 69h
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800196BD
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Sleeve_Beacon_Dll_x86_v4_0_suspected
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.0 (suspected, not confirmed)"
    hash =  "55aa2b534fcedc92bb3da54827d0daaa23ece0f02a10eb08f5b5247caaa63a73"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      41 B8 01 00 00 00    mov     r8d, 1
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
      E9 D1 B3 FF FF       jmp     sub_180010C5C
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
      E9 AF F5 FF FF       jmp     f_UNK__Command_92__ChangeFlag
      45 33 C0             xor     r8d, r8d
      4C 8D 0D 8D 70 FF FF lea     r9, sub_18000C930
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      E8 9B B0 FF FF       call    f_OTH__Command_91__WrapInjection
    */

    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF
                     8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0
                     4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_1_and_v_4_2
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.1 and 4.2"
    hash =  "29ec171300e8d2dad2e1ca2b77912caf0d5f9d1b633a81bb6534acb20a1574b2"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      83 F9 34          cmp     ecx, 34h ; '4'
      0F 87 8E 03 00 00 ja      loc_180016259
      0F 84 7A 03 00 00 jz      loc_18001624B
      83 F9 1C          cmp     ecx, 1Ch
      0F 87 E6 01 00 00 ja      loc_1800160C0
      0F 84 D7 01 00 00 jz      loc_1800160B7
      83 F9 0E          cmp     ecx, 0Eh
      0F 87 E9 00 00 00 ja      loc_180015FD2
      0F 84 CE 00 00 00 jz      loc_180015FBD
      FF C9             dec     ecx
      0F 84 B8 00 00 00 jz      loc_180015FAF
      83 E9 02          sub     ecx, 2
      0F 84 9F 00 00 00 jz      loc_180015F9F
      FF C9             dec     ecx
    */

    $version_sig = { 83 F9 34 0F 87 8E 03 00 00 0F 84 7A 03 00 00 83 F9 1C 0F 87 E6 01 00 00
                     0F 84 D7 01 00 00 83 F9 0E 0F 87 E9 00 00 00 0F 84 CE 00 00 00 FF C9
                     0F 84 B8 00 00 00 83 E9 02 0F 84 9F 00 00 00 FF C9 }


    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_3
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Version 4.3"
    hash =  "3ac9c3525caa29981775bddec43d686c0e855271f23731c376ba48761c27fa3d"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
  
    /*
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; Source
      48 83 C4 28          add     rsp, 28h
      E9 D3 88 FF FF       jmp     f_OTH__CommandAbove_10
      4C 8D 05 84 6E FF FF lea     r8, f_NET__ExfiltrateData
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 D3 88 FF FF
                     4C 8D 05 84 6E FF FF 8B D0 49 8B CA 48 83 C4 28 }
  
    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800186E1
    */
    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}


rule CobaltStrike_Sleeve_Beacon_x64_v4_4_v_4_5_and_v4_6
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.4 through at least 4.6"
    hash = "3280fec57b7ca94fd2bdb5a4ea1c7e648f565ac077152c5a81469030ccf6ab44"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

  strings:
    /*
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10; Source
      48 83 C4 28          add     rsp, 28h
      E9 83 88 FF FF       jmp     f_OTH__CommandAbove_10
      4C 8D 05 A4 6D FF FF lea     r8, f_NET__ExfiltrateData
      8B D0                mov     edx, eax
      49 8B CA             mov     rcx, r10
      48 83 C4 28          add     rsp, 28h
    */

    $version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 83 88 FF FF
                     4C 8D 05 A4 6D FF FF 8B D0 49 8B CA 48 83 C4 28 }

    /*
      80 34 28 2E       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_1800184D9
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

  condition:
    all of them
}

rule CobaltStrike_Sleeve_Beacon_x64_v4_5_variant
{
  meta:
    description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.5 (variant)"
    hash =  "8f0da7a45945b630cd0dfb5661036e365dcdccd085bc6cff2abeec6f4c9f1035"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
    
  strings:
    /*
      41 B8 01 00 00 00 mov     r8d, 1
      8B D0             mov     edx, eax
      49 8B CA          mov     rcx, r10
      48 83 C4 28       add     rsp, 28h
      E9 E8 AB FF FF    jmp     sub_1800115A4
      8B D0             mov     edx, eax
      49 8B CA          mov     rcx, r10
      E8 1A EB FF FF    call    f_UNK__Command_92__ChangeFlag
      48 83 C4 28       add     rsp, 28h
    */
    $version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 E8 AB FF FF
                     8B D0 49 8B CA E8 1A EB FF FF 48 83 C4 28 }

    /*
      80 34 28 ??       xor     byte ptr [rax+rbp], 2Eh
      48 FF C0          inc     rax
      48 3D 00 10 00 00 cmp     rax, 1000h
      7C F1             jl      short loc_180018E1F
    */

    $decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }
    
  condition:
    all of them
}
