# AES-GCM-SIV

[![NuGet][nuget-shield]][nuget-link]
[![Build Status][build-shield]][build-link]
[![Blazing Fast][speed-shield]][speed-link]
[![API Docs][docs-shield]][docs-link]
[![License][license-shield]][license-link]

C# implementation of [AES-GCM-SIV] nonce misuse-resistant authenticated encryption,
defined in [draft-irtf-cfrg-gcmsiv-08]. Fastest available authenticated encryption
library for .NET Core, with the encryption/decryption rate of roughly 8 Gbps/core.
Implemented using .NET Core 3.0 platform intrinsics.

[nuget-shield]: https://img.shields.io/nuget/v/AES-GCM-SIV.svg
[nuget-link]: https://www.nuget.org/packages/AES-GCM-SIV
[build-shield]: https://dev.azure.com/metalnem/aes-gcm-siv/_apis/build/status/Metalnem.aes-gcm-siv
[build-link]: https://dev.azure.com/metalnem/aes-gcm-siv/_build/latest?definitionId=1
[speed-shield]: https://img.shields.io/badge/speed-blazing%20%F0%9F%94%A5-brightgreen.svg
[speed-link]: https://twitter.com/acdlite/status/974390255393505280
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
> dotnet add package AES-GCM-SIV --version 0.3.1
```

## Acknowledgements

This implementation is based on the [C intrinsics code] written by Shay Gueron.

[C intrinsics code]: https://github.com/Shay-Gueron/AES-GCM-SIV

## Resources

[AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption draft-irtf-cfrg-gcmsiv-08](https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-08)  
[AES-GCM-SIV: Specification and Analysis](https://eprint.iacr.org/2017/168.pdf)  
[Webpage for the AES-GCM-SIV Mode of Operation](https://cyber.biu.ac.il/aes-gcm-siv/)  
[AES-GCM-SIV implementations (128 and 256 bit)](https://github.com/Shay-Gueron/AES-GCM-SIV)  
[Go implementation](https://github.com/agl/gcmsiv)  
[Java implementation](https://github.com/codahale/aes-gcm-siv)  
[AES-GCM-SIV (Adam Langley)](https://www.imperialviolet.org/2017/05/14/aesgcmsiv.html)  
[Towards A Safer Footgun (Coda Hale)](https://codahale.com/towards-a-safer-footgun/)

## Performance (Windows)

``` ini
BenchmarkDotNet=v0.11.1, OS=Windows 10.0.17134.345 (1803/April2018Update/Redstone4)
Intel Core i7-4800MQ CPU 2.70GHz (Max: 2.69GHz) (Haswell), 1 CPU, 8 logical and 4 physical cores
Frequency=2630636 Hz, Resolution=380.1362 ns, Timer=TSC
.NET Core SDK=3.0.100-alpha1-009638
  [Host] : .NET Core 3.0.0-preview1-27003-04 (CoreCLR 4.6.27002.04, CoreFX 4.6.27002.03), 64bit RyuJIT
```
|      Method | Categories | Size |       Mean |      Error |      StdDev | Scaled |
|------------ |----------- |----- |-----------:|-----------:|------------:|-------:|
|     **AES-GCM** | **Encryption** |  **128** |   **306.2 ns** |  **0.5986 ns** |   **0.5307 ns** |   **1.00** |
| AES-GCM-SIV | Encryption |  128 |   287.7 ns |  3.6306 ns |   3.2185 ns |   0.94 |
|             |            |      |            |            |             |        |
|     AES-GCM | Decryption |  128 |   311.7 ns |  0.2751 ns |   0.2438 ns |   1.00 |
| AES-GCM-SIV | Decryption |  128 |   329.5 ns |  2.6803 ns |   2.2382 ns |   1.06 |
|             |            |      |            |            |             |        |
|     **AES-GCM** | **Encryption** | **1024** |   **681.1 ns** |  **1.5380 ns** |   **1.3634 ns** |   **1.00** |
| AES-GCM-SIV | Encryption | 1024 |   663.0 ns |  2.6639 ns |   2.4918 ns |   0.97 |
|             |            |      |            |            |             |        |
|     AES-GCM | Decryption | 1024 |   681.0 ns |  0.7810 ns |   0.6923 ns |   1.00 |
| AES-GCM-SIV | Decryption | 1024 |   715.3 ns |  1.3908 ns |   1.3009 ns |   1.05 |
|             |            |      |            |            |             |        |
|     **AES-GCM** | **Encryption** | **4096** | **1,984.3 ns** |  **6.5387 ns** |   **5.4601 ns** |   **1.00** |
| AES-GCM-SIV | Encryption | 4096 | 1,877.8 ns |  0.5862 ns |   0.5196 ns |   0.95 |
|             |            |      |            |            |             |        |
|     AES-GCM | Decryption | 4096 | 1,988.5 ns |  1.0060 ns |   0.8401 ns |   1.00 |
| AES-GCM-SIV | Decryption | 4096 | 1,882.5 ns |  7.0526 ns |   6.5970 ns |   0.95 |
|             |            |      |            |            |             |        |
|     **AES-GCM** | **Encryption** | **8192** | **3,754.4 ns** | **84.4706 ns** |  **79.0138 ns** |   **1.00** |
| AES-GCM-SIV | Encryption | 8192 | 3,503.4 ns |  2.5222 ns |   2.1061 ns |   0.93 |
|             |            |      |            |            |             |        |
|     AES-GCM | Decryption | 8192 | 4,038.8 ns | 79.7916 ns | 114.4348 ns |   1.00 |
| AES-GCM-SIV | Decryption | 8192 | 3,609.7 ns | 66.9556 ns |  62.6303 ns |   0.89 |

## Performance (macOS)

``` ini
BenchmarkDotNet=v0.11.1, OS=macOS Mojave 10.14 (18A391) [Darwin 18.0.0]
Intel Core i7-5557U CPU 3.10GHz (Broadwell), 1 CPU, 4 logical and 2 physical cores
.NET Core SDK=3.0.100-alpha1-009640
  [Host] : .NET Core 3.0.0-preview1-27004-04 (CoreCLR 4.6.27003.04, CoreFX 4.6.27003.02), 64bit RyuJIT
```
|      Method | Categories | Size |       Mean |     Error |    StdDev | Scaled |
|------------ |----------- |----- |-----------:|----------:|----------:|-------:|
|     **AES-GCM** | **Encryption** |  **128** |   **503.1 ns** | **0.2081 ns** | **0.1737 ns** |   **1.00** |
| AES-GCM-SIV | Encryption |  128 |   315.4 ns | 0.1813 ns | 0.1514 ns |   0.63 |
|             |            |      |            |           |           |        |
|     AES-GCM | Decryption |  128 |   517.2 ns | 0.4337 ns | 0.3621 ns |   1.00 |
| AES-GCM-SIV | Decryption |  128 |   368.2 ns | 0.1659 ns | 0.1385 ns |   0.71 |
|             |            |      |            |           |           |        |
|     **AES-GCM** | **Encryption** | **1024** |   **795.1 ns** | **1.0668 ns** | **0.9979 ns** |   **1.00** |
| AES-GCM-SIV | Encryption | 1024 |   666.7 ns | 0.5449 ns | 0.4830 ns |   0.84 |
|             |            |      |            |           |           |        |
|     AES-GCM | Decryption | 1024 |   779.5 ns | 1.2164 ns | 0.9497 ns |   1.00 |
| AES-GCM-SIV | Decryption | 1024 |   697.7 ns | 0.8535 ns | 0.7566 ns |   0.90 |
|             |            |      |            |           |           |        |
|     **AES-GCM** | **Encryption** | **4096** | **1,711.2 ns** | **2.1837 ns** | **2.0426 ns** |   **1.00** |
| AES-GCM-SIV | Encryption | 4096 | 1,767.6 ns | 2.5230 ns | 2.2366 ns |   1.03 |
|             |            |      |            |           |           |        |
|     AES-GCM | Decryption | 4096 | 1,711.9 ns | 6.3718 ns | 5.9602 ns |   1.00 |
| AES-GCM-SIV | Decryption | 4096 | 1,780.6 ns | 1.7417 ns | 1.5440 ns |   1.04 |
|             |            |      |            |           |           |        |
|     **AES-GCM** | **Encryption** | **8192** | **2,981.2 ns** | **8.2092 ns** | **7.6789 ns** |   **1.00** |
| AES-GCM-SIV | Encryption | 8192 | 3,276.0 ns | 4.5095 ns | 3.7657 ns |   1.10 |
|             |            |      |            |           |           |        |
|     AES-GCM | Decryption | 8192 | 2,991.5 ns | 6.8195 ns | 6.3789 ns |   1.00 |
| AES-GCM-SIV | Decryption | 8192 | 3,205.7 ns | 4.4109 ns | 4.1260 ns |   1.07 |
