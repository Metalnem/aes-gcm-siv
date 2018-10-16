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
|      Method | Size |     Mean |     Error |    StdDev | Scaled |
|------------ |----- |---------:|----------:|----------:|-------:|
|     **AES-GCM** | **4096** | **1.718 us** | **0.0020 us** | **0.0018 us** |   **1.00** |
| AES-GCM-SIV | 4096 | 1.833 us | 0.0020 us | 0.0019 us |   1.07 |
|             |      |          |           |           |        |
|     **AES-GCM** | **8192** | **3.019 us** | **0.0064 us** | **0.0053 us** |   **1.00** |
| AES-GCM-SIV | 8192 | 3.338 us | 0.0235 us | 0.0220 us |   1.11 |
