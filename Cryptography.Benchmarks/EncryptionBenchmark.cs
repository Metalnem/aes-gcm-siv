using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Cryptography.Benchmarks
{
	[InProcess]
	[MarkdownExporter]
	public class EncryptionBenchmark
	{
		private byte[] key;
		private byte[] nonce;
		private byte[] plaintext;
		private byte[] ciphertext;
		private byte[] tag;

		private AesGcm gcm;
		private AesGcmSiv siv;

		[Params(4096, 8192)]
		public int Size { get; set; }

		[GlobalSetup]
		public void GlobalSetup()
		{
			key = new byte[32];
			nonce = new byte[12];
			plaintext = new byte[Size];
			ciphertext = new byte[Size];
			tag = new byte[16];

			gcm = new AesGcm(key);
			siv = new AesGcmSiv(key);
		}

		[Benchmark(Baseline = true, Description = "AES-GCM (native)")]
		public void BenchmarkAesGcmNative()
		{
			gcm.Encrypt(nonce, plaintext, ciphertext, tag);
		}

		[Benchmark(Description = "AES-GCM (libsodium)")]
		public void BenchmarkAesGcmLibsodium()
		{
			Libsodium.Encrypt(key, nonce, plaintext, ciphertext, tag, null);
		}

		[Benchmark(Description = "AES-GCM-SIV")]
		public void BenchmarkAesGcmSiv()
		{
			siv.Encrypt(nonce, plaintext, ciphertext, tag);
		}
	}
}
