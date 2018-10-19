using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;

namespace Cryptography.Benchmarks
{
	[InProcess]
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
		private byte[] associatedData;
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
			associatedData = new byte[Size];
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

		[BenchmarkCategory("Encryption"), Benchmark(Baseline = true, Description = "AES-GCM (native)")]
		public void BenchmarkAesGcmNativeEncryption() => gcm.Encrypt(nonce, plaintext, ciphertext, tag);

		[BenchmarkCategory("Encryption"), Benchmark(Description = "AES-GCM (libsodium)")]
		public void BenchmarkAesGcmLibsodiumEncryption() => Libsodium.Encrypt(key, nonce, plaintext, ciphertext, tag, default);

		[BenchmarkCategory("Encryption"), Benchmark(Description = "AES-GCM-SIV")]
		public void BenchmarkAesGcmSivEncryption() => siv.Encrypt(nonce, plaintext, ciphertext, tag);

		[BenchmarkCategory("Decryption"), Benchmark(Baseline = true, Description = "AES-GCM (native)")]
		public void BenchmarkAesGcmNativeDecryption() => gcm.Decrypt(nonce, ciphertextGcm, tagGcm, plaintext);

		[BenchmarkCategory("Decryption"), Benchmark(Description = "AES-GCM (libsodium)")]
		public void BenchmarkAesGcmLibsodiumDecryption() => Libsodium.Decrypt(key, nonce, default, ciphertextGcm, tagGcm, plaintext);

		[BenchmarkCategory("Decryption"), Benchmark(Description = "AES-GCM-SIV")]
		public void BenchmarkAesGcmSivDecryption() => siv.Decrypt(nonce, ciphertextSiv, tagSiv, plaintext);

		[BenchmarkCategory("Authentication"), Benchmark(Baseline = true, Description = "GHASH (native)")]
		public void BenchmarkAesGcmNativeAuthentication() => gcm.Encrypt(nonce, empty, empty, tag, associatedData);

		[BenchmarkCategory("Authentication"), Benchmark(Description = "GHASH (libsodium)")]
		public void BenchmarkAesGcmLibsodiumAuthentication() => Libsodium.Encrypt(key, nonce, empty, empty, tag, associatedData);

		[BenchmarkCategory("Authentication"), Benchmark(Description = "POLYVAL")]
		public void BenchmarkAesGcmSivAuthentication() => siv.Encrypt(nonce, empty, empty, tag, associatedData);
	}
}
