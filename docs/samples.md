# Sample walkthroughs

Five representative samples that show what disunity surfaces, across IL2CPP v24 through v31, including one encrypted binary.

Each example runs `disunity signal <lib> <meta>` which produces `script.json`, `il2cpp.h`, `unity_meta.json`, and a classified signal graph.

## 1. Heavy crypto: Unity 2020 puzzle game (v27)

A mobile puzzle game built with Unity 2020. 54,615 methods in metadata, 91,374 resolved after generic expansion.

```text
signal 44 signal + 7412 context, 43224 edges
  encryption: 39
  auth: 2
  data: 2
  device: 1
```

The signal graph surfaces five distinct cryptographic subsystems in the app-specific code:

```text
[encryption] Encrypt.AESHelper$$Encrypt
[encryption] Encrypt.AESHelper$$Decrypt
[encryption] Encrypt.AESHelper$$GenerateIV
[encryption] KittyBlastMainTea$$Encrypt
[encryption] KittyBlastMainTea$$DecryptBase64StringToString
[encryption] UnityCipher.RSAEncryption$$Encrypt
[encryption] UnityCipher.RSAEncryption$$GenrateKeyPair
[encryption] Net.Encrypt.MD5Helper$$CreateMD5
[auth]       DeriveBytes$$set_Password
[encryption] DeriveBytes$$set_Salt
```

Three interesting findings:

- **AES with custom IV**: `Encrypt.AESHelper` implements AES with a custom `GenerateIV` method, not the standard framework one. Worth inspecting how the IV is derived.
- **XXTEA in Unity**: `KittyBlastMainTea` is an XXTEA implementation. This cipher is common in Cocos2d-x games, rarely seen in Unity. Someone ported protection code over.
- **PBKDF2 keys**: `DeriveBytes.set_Password` and `set_Salt` indicate PBKDF2 key derivation from a password. The password source is the next thing to look at.

Without signal analysis you would be staring at 91,374 methods. With it, you have 10 functions worth reading.

## 2. Region cloaking: Unity 2021 app (v29)

A Unity 2021 app with 39,212 methods. The signal graph caught something unusual:

```text
signal 26 signal + 3657 context, 25111 edges
  encryption: 14
  auth: 4
  device: 3
  data: 2
  webview: 2
  cloaking: 1
```

The `cloaking` hit:

```text
[cloaking] SmartLocalization.LanguageDataHandler$$CheckLanguageOverrideCode
[device]   SmartLocalization.LanguageManager$$GetDeviceCultureIfSupported
```

An app that overrides its localization based on device culture is not inherently malicious. But combined with:

```text
[auth]       <>c$$<Authenticate>b__1_0
[auth]       Secret$$.ctor
[auth]       Secret$$Start
[encryption] unitytls_tlsctx_get_ciphersuite_t$$Invoke
[encryption] EncryptedPrivateKeyInfo$$Decode
```

A class literally named `Secret` with a `Start` method (Unity lifecycle) that runs on boot, alongside TLS ciphersuite manipulation and locale-based behavior switching, is worth 15 minutes of your time.

The signal graph gives you that starting point in under 10 seconds.

## 3. Old-style binary: Unity 2018 game (v24, pre-CodeGenModules)

A Unity 2018 game. IL2CPP v24 with the pre-CodeGenModules CodeRegistration layout. Most tools fail or require manual configuration.

```text
[il2cpp static] Version: 24.0, imageCount: 3
[il2cpp static] Found mscorlib.dll at VA 0x2fa408
[il2cpp static] Old-style CodeRegistration at VA 0x29d5fc0 (methodPointersCount=24403)
[il2cpp static] Old-style methodPointers: 24403 entries from VA 0x2929600
[il2cpp static] Old-style genericMethodPointers: 30472 entries
  resolved: 24403 methods (30472 generic)
```

disunity detects the absence of CodeGenModules, falls back to the flat method pointer array, reads generic pointers from the old-style offsets, and produces a complete script.json for import into Ghidra or IDA.

Signal count is low (3 net signals) because most of the app is framework code and the business logic was inlined by the IL2CPP compiler.

## 4. Modern baseline: Unity 2022 app (v31)

A contemporary Unity 2022 app. 52,297 methods, 90,581 after generic resolution.

```text
signal 8 signal + 4370 context, 25646 edges
  encryption: 6
  data: 2
```

A clean app. Encryption hits are all framework TLS and `EncryptedPrivateKeyInfo` classes. No custom crypto, no cloaking, no suspicious device fingerprinting. The signal graph tells you exactly that: nothing to worry about in under 30 seconds.

This is the common case. Most Unity apps are boring. The value of signal analysis is that you know the app is boring without reading any of it.

## 5. Encrypted metadata: FairGuard-style protection

The most interesting demo is the one that fails well.

```bash
$ disunity --fast encrypted/libil2cpp.so encrypted/global-metadata.dat

meta global-metadata.dat
  parse failed: metadata is encrypted: magic=0x6CF1F3AC (expected 0xFAB11BAF)
  attempting auto-decrypt...
error: parse metadata: metadata is encrypted: magic=0x6CF1F3AC
```

disunity cannot decrypt this sample. The encryption is not simple XOR, so the Kasiski attack fails. Il2CppDumper also fails on this file with `ERROR: This file may be protected`.

But the failure message is the signal. In three lines of output you learn:

- The metadata is encrypted, not corrupt
- The custom magic bytes are `0x6CF1F3AC`
- Standard decryption approaches do not work

For a security researcher, that is exactly the starting point you want. An app that encrypts its IL2CPP metadata is hiding its type hierarchy from static analysis. The next steps are runtime instrumentation, examining the loader in `libil2cpp.so` for the decryption routine, or searching for the XOR key in the native library.

Detection is useful even when decryption is not possible. The alternative is silent failure or a crash.

## Reproducing

```bash
disunity signal libil2cpp.so global-metadata.dat
```

Outputs land in `./<basename>.disunity/`. The interactive HTML viewer is at `signal.html`. The raw graph for programmatic analysis is at `signal_graph.json`. Ghidra and IDA import scripts are generated alongside.
