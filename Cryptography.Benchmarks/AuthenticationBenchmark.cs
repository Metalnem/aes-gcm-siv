using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Cryptography.Benchmarks
{
	[InProcess]
	[MarkdownExporter]
	public class AuthenticationBenchmark
	{
		private byte[] key;
		private byte[] nonce;
		private byte[] plaintext;
		private byte[] ciphertext;
		private byte[] tag;
		private byte[] associatedData;

		private AesGcm gcm;
		private AesGcmSiv siv;

		[Params(4096, 8192)]
		public int Size { get; set; }

		[GlobalSetup]
		public void GlobalSetup()
		{
			key = new byte[32];
			nonce = new byte[12];
			plaintext = new byte[0];
			ciphertext = new byte[0];
			tag = new byte[16];
			associatedData = new byte[Size];

			gcm = new AesGcm(key);
			siv = new AesGcmSiv(key);
		}

		[Benchmark(Baseline = true, Description = "GHASH (native)")]
		public void BenchmarkAesGcmNative()
		{
			gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		}

		[Benchmark(Description = "GHASH (libsodium)")]
		public void BenchmarkAesGcmLibsodium()
		{
			Libsodium.Encrypt(key, nonce, plaintext, ciphertext, tag, associatedData);
		}

		[Benchmark(Description = "POLYVAL")]
		public void BenchmarkAesGcmSiv()
		{
			siv.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		}
	}
}
