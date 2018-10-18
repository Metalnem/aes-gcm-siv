using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Cryptography.Benchmarks
{
	[InProcess]
	[MarkdownExporter]
	public class DecryptionBenchmark
	{
		private byte[] key;
		private byte[] nonce;
		private byte[] plaintext;
		private byte[] ciphertextGcm;
		private byte[] ciphertextSiv;
		private byte[] tagGcm;
		private byte[] tagSiv;

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
			ciphertextGcm = new byte[Size];
			ciphertextSiv = new byte[Size];
			tagGcm = new byte[16];
			tagSiv = new byte[16];

			gcm = new AesGcm(key);
			siv = new AesGcmSiv(key);

			gcm.Encrypt(nonce, plaintext, ciphertextGcm, tagGcm);
			siv.Encrypt(nonce, plaintext, ciphertextSiv, tagSiv);
		}

		[Benchmark(Baseline = true, Description = "AES-GCM (native)")]
		public void BenchmarkAesGcmNative()
		{
			gcm.Decrypt(nonce, ciphertextGcm, tagGcm, plaintext);
		}

		[Benchmark(Description = "AES-GCM (libsodium)")]
		public void BenchmarkAesGcmLibsodium()
		{
			Libsodium.Decrypt(key, nonce, default, ciphertextGcm, tagGcm, plaintext);
		}

		[Benchmark(Description = "AES-GCM-SIV")]
		public void BenchmarkAesGcmSiv()
		{
			siv.Decrypt(nonce, ciphertextSiv, tagSiv, plaintext);
		}
	}
}
