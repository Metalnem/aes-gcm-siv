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

## Performance (Windows)

``` ini
BenchmarkDotNet=v0.11.1, OS=Windows 10.0.17134.345 (1803/April2018Update/Redstone4)
Intel Core i7-4800MQ CPU 2.70GHz (Max: 2.69GHz) (Haswell), 1 CPU, 8 logical and 4 physical cores
Frequency=2630637 Hz, Resolution=380.1361 ns, Timer=TSC
.NET Core SDK=3.0.100-alpha1-009638
  [Host] : .NET Core 3.0.0-preview1-27003-04 (CoreCLR 4.6.27002.04, CoreFX 4.6.27002.03), 64bit RyuJIT
```
|                Method |     Categories | Size |       Mean |      Error |     StdDev | Scaled | ScaledSD |
|---------------------- |--------------- |----- |-----------:|-----------:|-----------:|-------:|---------:|
|    **AES-GCM (native)** |     **Encryption** |  **128** |   **304.9 ns** |  **0.2947 ns** |  **0.2461 ns** |   **1.00** |     **0.00** |
| AES-GCM (libsodium) |     Encryption |  128 |   261.5 ns |  0.3746 ns |  0.3128 ns |   0.86 |     0.00 |
|           AES-GCM-SIV |     Encryption |  128 |   285.3 ns |  0.9613 ns |  0.8027 ns |   0.94 |     0.00 |
|                       |                |      |            |            |            |        |          |
|    AES-GCM (native) |     Decryption |  128 |   304.8 ns |  0.2339 ns |  0.1953 ns |   1.00 |     0.00 |
| AES-GCM (libsodium) |     Decryption |  128 |   260.8 ns |  0.2872 ns |  0.2546 ns |   0.86 |     0.00 |
|           AES-GCM-SIV |     Decryption |  128 |   377.7 ns |  0.5921 ns |  0.5248 ns |   1.24 |     0.00 |
|                       |                |      |            |            |            |        |          |
|      GHASH (native) | Authentication |  128 |   267.3 ns |  0.2349 ns |  0.2083 ns |   1.00 |     0.00 |
|   GHASH (libsodium) | Authentication |  128 |   198.5 ns |  0.2222 ns |  0.1969 ns |   0.74 |     0.00 |
|               POLYVAL | Authentication |  128 |   237.5 ns |  0.2820 ns |  0.2499 ns |   0.89 |     0.00 |
|                       |                |      |            |            |            |        |          |
|    **AES-GCM (native)** |     **Encryption** | **1024** |   **692.6 ns** |  **0.2705 ns** |  **0.2259 ns** |   **1.00** |     **0.00** |
| AES-GCM (libsodium) |     Encryption | 1024 |   805.3 ns |  0.4027 ns |  0.3570 ns |   1.16 |     0.00 |
|           AES-GCM-SIV |     Encryption | 1024 |   666.2 ns |  0.3535 ns |  0.3134 ns |   0.96 |     0.00 |
|                       |                |      |            |            |            |        |          |
|    AES-GCM (native) |     Decryption | 1024 |   677.4 ns |  0.9437 ns |  0.7368 ns |   1.00 |     0.00 |
| AES-GCM (libsodium) |     Decryption | 1024 |   879.1 ns | 22.5680 ns | 21.1101 ns |   1.30 |     0.03 |
|           AES-GCM-SIV |     Decryption | 1024 |   810.5 ns |  4.5300 ns |  4.2374 ns |   1.20 |     0.01 |
|                       |                |      |            |            |            |        |          |
|      GHASH (native) | Authentication | 1024 |   423.1 ns |  0.9522 ns |  0.7951 ns |   1.00 |     0.00 |
|   GHASH (libsodium) | Authentication | 1024 |   408.4 ns |  0.3715 ns |  0.3475 ns |   0.97 |     0.00 |
|               POLYVAL | Authentication | 1024 |   421.6 ns |  1.0462 ns |  0.8736 ns |   1.00 |     0.00 |
|                       |                |      |            |            |            |        |          |
|    **AES-GCM (native)** |     **Encryption** | **4096** | **2,097.6 ns** | **13.4482 ns** | **12.5795 ns** |   **1.00** |     **0.00** |
| AES-GCM (libsodium) |     Encryption | 4096 | 2,769.7 ns |  5.6692 ns |  4.7341 ns |   1.32 |     0.01 |
|           AES-GCM-SIV |     Encryption | 4096 | 2,035.3 ns | 15.5301 ns | 14.5269 ns |   0.97 |     0.01 |
|                       |                |      |            |            |            |        |          |
|    AES-GCM (native) |     Decryption | 4096 | 2,095.7 ns |  3.5219 ns |  3.1221 ns |   1.00 |     0.00 |
| AES-GCM (libsodium) |     Decryption | 4096 | 3,164.9 ns |  9.1115 ns |  8.5229 ns |   1.51 |     0.00 |
|           AES-GCM-SIV |     Decryption | 4096 | 2,024.8 ns |  2.6653 ns |  2.4931 ns |   0.97 |     0.00 |
|                       |                |      |            |            |            |        |          |
|      GHASH (native) | Authentication | 4096 |   926.8 ns |  7.8589 ns |  7.3512 ns |   1.00 |     0.00 |
|   GHASH (libsodium) | Authentication | 4096 | 1,083.3 ns |  3.9336 ns |  3.6795 ns |   1.17 |     0.01 |
|               POLYVAL | Authentication | 4096 |   894.5 ns |  6.7395 ns |  6.3042 ns |   0.97 |     0.01 |
|                       |                |      |            |            |            |        |          |
|    **AES-GCM (native)** |     **Encryption** | **8192** | **3,918.0 ns** |  **7.2812 ns** |  **6.8109 ns** |   **1.00** |     **0.00** |
| AES-GCM (libsodium) |     Encryption | 8192 | 5,356.0 ns | 14.7993 ns | 13.8433 ns |   1.37 |     0.00 |
|           AES-GCM-SIV |     Encryption | 8192 | 3,706.5 ns |  9.6054 ns |  8.9849 ns |   0.95 |     0.00 |
|                       |                |      |            |            |            |        |          |
|    AES-GCM (native) |     Decryption | 8192 | 3,912.5 ns | 12.2199 ns | 11.4305 ns |   1.00 |     0.00 |
| AES-GCM (libsodium) |     Decryption | 8192 | 6,138.9 ns | 34.2531 ns | 32.0404 ns |   1.57 |     0.01 |
|           AES-GCM-SIV |     Decryption | 8192 | 3,692.4 ns | 71.4367 ns | 59.6529 ns |   0.94 |     0.01 |
|                       |                |      |            |            |            |        |          |
|      GHASH (native) | Authentication | 8192 | 1,572.0 ns |  5.0056 ns |  4.4373 ns |   1.00 |     0.00 |
|   GHASH (libsodium) | Authentication | 8192 | 2,013.1 ns |  7.7082 ns |  7.2102 ns |   1.28 |     0.01 |
|               POLYVAL | Authentication | 8192 | 1,543.9 ns |  3.5905 ns |  3.3586 ns |   0.98 |     0.00 |

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
