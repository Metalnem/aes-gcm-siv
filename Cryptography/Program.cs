using System;
using Cryptography;

namespace Cryptography
{
	public static class Program
	{
		public static void Main(string[] args)
		{
			var tag = new byte[16];
			var hashKey = Hex.Decode("66e94bd4ef8a2c3b884cfa59ca342b2e");
			var input = Hex.Decode("ff000000000000000000000000000000");

			AesGcmSiv.PolyvalHorner(tag, hashKey, input);
			Console.WriteLine(Hex.Encode(tag));
		}
	}

	internal static class Hex
	{
		public static string Encode(byte[] raw)
		{
			return BitConverter.ToString(raw).Replace("-", String.Empty).ToLowerInvariant();
		}

		public static byte[] Decode(string hex)
		{
			byte[] raw = new byte[hex.Length / 2];

			for (int i = 0; i < raw.Length; ++i)
			{
				raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
			}

			return raw;
		}
	}
}
