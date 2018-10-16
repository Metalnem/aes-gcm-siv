# AES-GCM-SIV [![license][license-shield]][license-link]

C# implementation of [AES-GCM-SIV] nonce misuse-resistant authenticated encryption,
defined in [draft-irtf-cfrg-gcmsiv-08]. Work in progress.

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
|    **&#39;AES-GCM (native)&#39;** | **4096** | **1.742 us** | **0.0013 us** | **0.0012 us** |   **1.00** |
| &#39;AES-GCM (libsodium)&#39; | 4096 | 3.010 us | 0.0032 us | 0.0029 us |   1.73 |
|           AES-GCM-SIV | 4096 | 1.811 us | 0.0045 us | 0.0038 us |   1.04 |
|                       |      |          |           |           |        |
|    **&#39;AES-GCM (native)&#39;** | **8192** | **2.994 us** | **0.0074 us** | **0.0066 us** |   **1.00** |
| &#39;AES-GCM (libsodium)&#39; | 8192 | 5.799 us | 0.0072 us | 0.0068 us |   1.94 |
|           AES-GCM-SIV | 8192 | 3.296 us | 0.0046 us | 0.0040 us |   1.10 |
