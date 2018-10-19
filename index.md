---
title: Noise.NET
---

# AES-GCM-SIV

[![nuget][nuget-shield]][nuget-link]
[![docs][docs-shield]][docs-link]
[![license][license-shield]][license-link]

C# implementation of [AES-GCM-SIV] nonce misuse-resistant authenticated encryption,
defined in [draft-irtf-cfrg-gcmsiv-08].

[nuget-shield]: https://img.shields.io/nuget/v/AES-GCM-SIV.svg
[nuget-link]: https://www.nuget.org/packages/AES-GCM-SIV
[docs-shield]: https://img.shields.io/badge/docs-API-orange.svg?style=flat
[docs-link]: https://metalnem.github.io/aes-gcm-siv/api/Cryptography.AesGcmSiv.html
[license-shield]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat
[license-link]: https://github.com/metalnem/aes-gcm-siv/blob/master/LICENSE
[AES-GCM-SIV]: https://eprint.iacr.org/2017/168.pdf
[draft-irtf-cfrg-gcmsiv-08]: https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-08

## Usage

```csharp
// Plaintext to encrypt.
var plaintext = "I'm cooking MC's like a pound of bacon";

// Create a 32-byte key.
var key = new byte[32];
RandomNumberGenerator.Fill(key);

// Create a 12-byte nonce.
var nonce = new byte[12];
RandomNumberGenerator.Fill(key);

// Create a new AesGcmSiv instance. It implements the IDisposable
// interface, so it's best to create it inside using statement.
using (var siv = new AesGcmSiv(key))
{
  // If the message is string, convert it to byte array first.
  var bytes = Encoding.UTF8.GetBytes(plaintext);

  // Encrypt the message.
  var ciphertext = new byte[bytes.Length];
  var tag = new byte[16];
  siv.Encrypt(nonce, bytes, ciphertext, tag);

  // To decrypt the message, call the Decrypt method with the
  // ciphertext and the same nonce that you generated previously.
  siv.Decrypt(nonce, ciphertext, tag, bytes);

  // If the message was originally string,
  // convert if from byte array to string.
  plaintext = Encoding.UTF8.GetString(bytes);

  // Print the decrypted message to the standard output.
  Console.WriteLine(plaintext);
}
```

## Installation

```
> dotnet add package AES-GCM-SIV --version 0.1.0-alpha
```

## Performance (macOS)

``` ini
BenchmarkDotNet=v0.11.1, OS=macOS Mojave 10.14 (18A391) [Darwin 18.0.0]
Intel Core i7-5557U CPU 3.10GHz (Broadwell), 1 CPU, 4 logical and 2 physical cores
.NET Core SDK=3.0.100-alpha1-009640
  [Host] : .NET Core 3.0.0-preview1-27004-04 (CoreCLR 4.6.27003.04, CoreFX 4.6.27003.02), 64bit RyuJIT
```
|                Method |     Categories | Size |       Mean |     Error |    StdDev | Scaled | ScaledSD |
|---------------------- |--------------- |----- |-----------:|----------:|----------:|-------:|---------:|
|    **AES-GCM (native)** |     **Encryption** |  **128** |   **559.2 ns** | **10.967 ns** | **14.641 ns** |   **1.00** |     **0.00** |
| AES-GCM (libsodium) |     Encryption |  128 |   303.5 ns |  6.033 ns |  7.409 ns |   0.54 |     0.02 |
|           AES-GCM-SIV |     Encryption |  128 |   339.6 ns |  6.735 ns |  9.442 ns |   0.61 |     0.02 |
|                       |                |      |            |           |           |        |          |
|    AES-GCM (native) |     Decryption |  128 |   580.0 ns | 11.576 ns | 16.602 ns |   1.00 |     0.00 |
| AES-GCM (libsodium) |     Decryption |  128 |   320.0 ns |  6.172 ns |  7.347 ns |   0.55 |     0.02 |
|           AES-GCM-SIV |     Decryption |  128 |   462.1 ns |  9.075 ns | 11.476 ns |   0.80 |     0.03 |
|                       |                |      |            |           |           |        |          |
|      GHASH (native) | Authentication |  128 |   606.0 ns |  6.667 ns |  6.236 ns |   1.00 |     0.00 |
|   GHASH (libsodium) | Authentication |  128 |   223.3 ns |  2.342 ns |  2.190 ns |   0.37 |     0.01 |
|               POLYVAL | Authentication |  128 |   289.6 ns |  1.746 ns |  1.633 ns |   0.48 |     0.01 |
|                       |                |      |            |           |           |        |          |
|    **AES-GCM (native)** |     **Encryption** | **1024** |   **872.7 ns** | **12.488 ns** | **11.681 ns** |   **1.00** |     **0.00** |
| AES-GCM (libsodium) |     Encryption | 1024 |   974.4 ns | 11.510 ns | 10.767 ns |   1.12 |     0.02 |
|           AES-GCM-SIV |     Encryption | 1024 |   713.3 ns | 13.748 ns | 15.832 ns |   0.82 |     0.02 |
|                       |                |      |            |           |           |        |          |
|    AES-GCM (native) |     Decryption | 1024 |   865.5 ns | 11.977 ns | 11.203 ns |   1.00 |     0.00 |
| AES-GCM (libsodium) |     Decryption | 1024 | 1,062.8 ns | 16.638 ns | 15.563 ns |   1.23 |     0.02 |
|           AES-GCM-SIV |     Decryption | 1024 |   817.3 ns | 16.283 ns | 21.172 ns |   0.94 |     0.03 |
|                       |                |      |            |           |           |        |          |
|      GHASH (native) | Authentication | 1024 |   684.6 ns | 12.848 ns | 12.018 ns |   1.00 |     0.00 |
|   GHASH (libsodium) | Authentication | 1024 |   401.4 ns |  5.557 ns |  5.198 ns |   0.59 |     0.01 |
|               POLYVAL | Authentication | 1024 |   382.6 ns |  3.637 ns |  3.402 ns |   0.56 |     0.01 |
|                       |                |      |            |           |           |        |          |
|    **AES-GCM (native)** |     **Encryption** | **4096** | **1,935.8 ns** | **15.805 ns** | **14.011 ns** |   **1.00** |     **0.00** |
| AES-GCM (libsodium) |     Encryption | 4096 | 3,233.8 ns | 33.903 ns | 30.054 ns |   1.67 |     0.02 |
|           AES-GCM-SIV |     Encryption | 4096 | 1,992.1 ns | 33.792 ns | 31.609 ns |   1.03 |     0.02 |
|                       |                |      |            |           |           |        |          |
|    AES-GCM (native) |     Decryption | 4096 | 1,964.1 ns | 22.410 ns | 20.963 ns |   1.00 |     0.00 |
| AES-GCM (libsodium) |     Decryption | 4096 | 3,586.1 ns | 20.767 ns | 18.410 ns |   1.83 |     0.02 |
|           AES-GCM-SIV |     Decryption | 4096 | 2,043.7 ns |  9.741 ns |  8.135 ns |   1.04 |     0.01 |
|                       |                |      |            |           |           |        |          |
|      GHASH (native) | Authentication | 4096 |   983.9 ns | 19.705 ns | 19.353 ns |   1.00 |     0.00 |
|   GHASH (libsodium) | Authentication | 4096 | 1,033.7 ns | 20.042 ns | 28.096 ns |   1.05 |     0.03 |
|               POLYVAL | Authentication | 4096 |   678.8 ns |  7.496 ns |  7.012 ns |   0.69 |     0.01 |
|                       |                |      |            |           |           |        |          |
|    **AES-GCM (native)** |     **Encryption** | **8192** | **3,274.5 ns** | **65.362 ns** | **91.629 ns** |   **1.00** |     **0.00** |
| AES-GCM (libsodium) |     Encryption | 8192 | 6,275.5 ns | 79.991 ns | 74.824 ns |   1.92 |     0.06 |
|           AES-GCM-SIV |     Encryption | 8192 | 3,595.7 ns | 70.647 ns | 75.591 ns |   1.10 |     0.04 |
|                       |                |      |            |           |           |        |          |
|    AES-GCM (native) |     Decryption | 8192 | 3,307.4 ns | 46.589 ns | 41.300 ns |   1.00 |     0.00 |
| AES-GCM (libsodium) |     Decryption | 8192 | 6,558.1 ns | 10.236 ns |  9.575 ns |   1.98 |     0.02 |
|           AES-GCM-SIV |     Decryption | 8192 | 3,309.5 ns |  5.528 ns |  4.900 ns |   1.00 |     0.01 |
|                       |                |      |            |           |           |        |          |
|      GHASH (native) | Authentication | 8192 | 1,302.0 ns |  4.306 ns |  3.817 ns |   1.00 |     0.00 |
|   GHASH (libsodium) | Authentication | 8192 | 1,749.7 ns |  2.524 ns |  2.361 ns |   1.34 |     0.00 |
|               POLYVAL | Authentication | 8192 | 1,004.0 ns |  4.088 ns |  3.824 ns |   0.77 |     0.00 |
