# AES-GCM-SIV

[![docs][docs-shield]][docs-link]
[![license][license-shield]][license-link]

C# implementation of [AES-GCM-SIV] nonce misuse-resistant authenticated encryption,
defined in [draft-irtf-cfrg-gcmsiv-08].

[docs-shield]: https://img.shields.io/badge/docs-API-orange.svg?style=flat
[docs-link]: https://metalnem.github.io/aes-gcm-siv/api/Cryptography.html
[license-shield]: https://img.shields.io/badge/license-MIT-blue.svg?style=flat
[license-link]: https://github.com/metalnem/aes-gcm-siv/blob/master/LICENSE
[AES-GCM-SIV]: https://eprint.iacr.org/2017/168.pdf
[draft-irtf-cfrg-gcmsiv-08]: https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-08

## Performance

``` ini
BenchmarkDotNet=v0.11.1, OS=macOS Mojave 10.14 (18A391) [Darwin 18.0.0]
Intel Core i7-5557U CPU 3.10GHz (Broadwell), 1 CPU, 4 logical and 2 physical cores
.NET Core SDK=3.0.100-alpha1-009640
  [Host] : .NET Core 3.0.0-preview1-27004-04 (CoreCLR 4.6.27003.04, CoreFX 4.6.27003.02), 64bit RyuJIT
```
|                Method | Size |     Mean |     Error |    StdDev | Scaled |
|---------------------- |----- |---------:|----------:|----------:|-------:|
|    **AES-GCM (native)** | **4096** | **1.722 us** | **0.0023 us** | **0.0022 us** |   **1.00** |
| AES-GCM (libsodium) | 4096 | 3.012 us | 0.0021 us | 0.0020 us |   1.75 |
|           AES-GCM-SIV | 4096 | 1.795 us | 0.0011 us | 0.0010 us |   1.04 |
|                       |      |          |           |           |        |
|    **AES-GCM (native)** | **8192** | **2.961 us** | **0.0017 us** | **0.0015 us** |   **1.00** |
| AES-GCM (libsodium) | 8192 | 5.824 us | 0.0021 us | 0.0017 us |   1.97 |
|           AES-GCM-SIV | 8192 | 3.262 us | 0.0014 us | 0.0012 us |   1.10 |


``` ini
BenchmarkDotNet=v0.11.1, OS=Windows 10.0.17134.285 (1803/April2018Update/Redstone4)
Intel Core i7-4800MQ CPU 2.70GHz (Max: 1.35GHz) (Haswell), 1 CPU, 8 logical and 4 physical cores
Frequency=2630637 Hz, Resolution=380.1361 ns, Timer=TSC
.NET Core SDK=3.0.100-alpha1-009638
  [Host] : .NET Core 3.0.0-preview1-27003-04 (CoreCLR 4.6.27002.04, CoreFX 4.6.27002.03), 64bit RyuJIT
```
|                Method | Size |     Mean |     Error |    StdDev | Scaled |
|---------------------- |----- |---------:|----------:|----------:|-------:|
|    **AES-GCM (native)** | **4096** | **1.996 us** | **0.0040 us** | **0.0035 us** |   **1.00** |
| AES-GCM (libsodium) | 4096 | 2.628 us | 0.0064 us | 0.0060 us |   1.32 |
|           AES-GCM-SIV | 4096 | 1.911 us | 0.0033 us | 0.0031 us |   0.96 |
|                       |      |          |           |           |        |
|    **AES-GCM (native)** | **8192** | **3.710 us** | **0.0042 us** | **0.0039 us** |   **1.00** |
| AES-GCM (libsodium) | 8192 | 5.050 us | 0.0055 us | 0.0049 us |   1.36 |
|           AES-GCM-SIV | 8192 | 3.534 us | 0.0407 us | 0.0340 us |   0.95 |
