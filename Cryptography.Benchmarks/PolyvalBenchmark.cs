using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Cryptography.Benchmarks
{
	[InProcess]
	public class PolyvalBenchmark
	{
		private byte[] tag;
		private byte[] hashKey;
		private byte[] input;

		[Params(128, 1024, 4096, 8192)]
		public int Size { get; set; }

		[GlobalSetup]
		public void GlobalSetup()
		{
			tag = new byte[16];
			hashKey = new byte[16];
			input = new byte[Size];

			using (var sha = SHA256.Create())
			{
				hashKey = sha.ComputeHash(hashKey).AsSpan(0, 16).ToArray();
			}
		}

		[Benchmark]
		public void BenchmarkPolyvalHorner()
		{
			AesGcmSiv.PolyvalHorner(tag, hashKey, input);
		}
	}
}
