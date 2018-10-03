using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Cryptography.Tests
{
	public class AesGcmSivTest
	{
		[Fact]
		public void TestPolyvalHorner()
		{
			var files = new List<string>
			{
				"Vectors/aes-128-gcm-siv.json",
				"Vectors/aes-256-gcm-siv.json",
				"Vectors/counter-wrap.json"
			};

			foreach (var file in files)
			{
				var s = File.ReadAllText(file);
				var json = JObject.Parse(s);

				foreach (var vector in json["vectors"])
				{
					var tag = new byte[16];
					var hashKey = GetBytes(vector, "record_authentication_key");
					var input = GetBytes(vector, "polyval_input");
					var polyval = GetString(vector, "polyval_result");

					AesGcmSiv.PolyvalHorner(tag, hashKey, input);
					Assert.Equal(polyval, Hex.Encode(tag));
				}
			}
		}

		[Fact]
		public void TestInitPowersTable8() => TestInitPowersTable(8);

		[Fact]
		public void TestInitPowersTable6() => TestInitPowersTable(6);

		private void TestInitPowersTable(int size)
		{
			var powersTable = new byte[size * 16];
			var hashKey = Hex.Decode("d8733394680050b0610782116bed63c4");

			AesGcmSiv.InitPowersTable(powersTable, hashKey);

			var powers = new byte[size][];
			powers[0] = hashKey;

			for (int i = 1; i < size; ++i)
			{
				powers[i] = new byte[16];
				AesGcmSiv.PolyvalHorner(powers[i], hashKey, powers[i - 1]);
			}

			var expected = Hex.Encode(powersTable);
			var actual = Hex.Encode(powers.SelectMany(b => b).ToArray());

			Assert.Equal(expected, actual);
		}

		private static string GetString(JToken token, string property)
		{
			return (string)token[property] ?? String.Empty;
		}

		private static byte[] GetBytes(JToken token, string property)
		{
			return Hex.Decode(GetString(token, property));
		}
	}
}
