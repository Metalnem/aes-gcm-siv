using BenchmarkDotNet.Running;

namespace Cryptography.Benchmarks
{
	public class Program
	{
		public static void Main(string[] args)
		{
			BenchmarkRunner.Run<AeadBenchmark>();
		}
	}
}
