using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Cryptography.Benchmarks
{
	[InProcess]
	public class AeadBenchmark
	{
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
			nonce = new byte[12];
			plaintext = new byte[Size];
			ciphertext = new byte[Size];
			tag = new byte[16];

			var key = new byte[32];

			gcm = new AesGcm(key);
			siv = new AesGcmSiv(key);
		}

		[Benchmark(Description = "AES-GCM")]
		public void BenchmarkAesGcm()
		{
			gcm.Encrypt(nonce, plaintext, ciphertext, tag);
		}

		[Benchmark(Description = "AES-GCM-SIV")]
		public void BenchmarkAesGcmSiv()
		{
			siv.Encrypt(nonce, plaintext, ciphertext, tag);
		}
	}
}
