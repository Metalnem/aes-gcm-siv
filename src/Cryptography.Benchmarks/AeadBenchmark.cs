using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;

namespace Cryptography.Benchmarks
{
	[CategoriesColumn]
	[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
	[MarkdownExporter]
	public class AeadBenchmark
	{
		private byte[] key;
		private byte[] nonce;
		private byte[] plaintext;
		private byte[] ciphertext;
		private byte[] tag;
		private byte[] empty;

		private byte[] ciphertextGcm;
		private byte[] ciphertextSiv;
		private byte[] tagGcm;
		private byte[] tagSiv;

		private AesGcm gcm;
		private AesGcmSiv siv;

		[Params(128, 1024, 4096, 8192)]
		public int Size { get; set; }

		[GlobalSetup]
		public void GlobalSetup()
		{
			key = new byte[32];
			nonce = new byte[12];
			plaintext = new byte[Size];
			ciphertext = new byte[Size];
			tag = new byte[16];
			empty = new byte[0];

			ciphertextGcm = new byte[Size];
			ciphertextSiv = new byte[Size];
			tagGcm = new byte[16];
			tagSiv = new byte[16];

			gcm = new AesGcm(key);
			siv = new AesGcmSiv(key);

			gcm.Encrypt(nonce, plaintext, ciphertextGcm, tagGcm);
			siv.Encrypt(nonce, plaintext, ciphertextSiv, tagSiv);
		}

		[BenchmarkCategory("Encryption"), Benchmark(Baseline = true, Description = "AES-GCM")]
		public void BenchmarkAesGcmNativeEncryption() => gcm.Encrypt(nonce, plaintext, ciphertext, tag);

		[BenchmarkCategory("Encryption"), Benchmark(Description = "AES-GCM-SIV")]
		public void BenchmarkAesGcmSivEncryption() => siv.Encrypt(nonce, plaintext, ciphertext, tag);

		[BenchmarkCategory("Decryption"), Benchmark(Baseline = true, Description = "AES-GCM")]
		public void BenchmarkAesGcmNativeDecryption() => gcm.Decrypt(nonce, ciphertextGcm, tagGcm, plaintext);

		[BenchmarkCategory("Decryption"), Benchmark(Description = "AES-GCM-SIV")]
		public void BenchmarkAesGcmSivDecryption() => siv.Decrypt(nonce, ciphertextSiv, tagSiv, plaintext);
	}
}
