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
		public void TestKeySchedule()
		{
			var key = Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
			var roundKeys = new byte[15 * 16];

			AesGcmSiv.KeySchedule(key, roundKeys);

			var expected = "000102030405060708090a0b0c0d0e0f"
				+ "101112131415161718191a1b1c1d1e1f"
				+ "a573c29fa176c498a97fce93a572c09c"
				+ "1651a8cd0244beda1a5da4c10640bade"
				+ "ae87dff00ff11b68a68ed5fb03fc1567"
				+ "6de1f1486fa54f9275f8eb5373b8518d"
				+ "c656827fc9a799176f294cec6cd5598b"
				+ "3de23a75524775e727bf9eb45407cf39"
				+ "0bdc905fc27b0948ad5245a4c1871c2f"
				+ "45f5a66017b2d387300d4d33640a820a"
				+ "7ccff71cbeb4fe5413e6bbf0d261a7df"
				+ "f01afafee7a82979d7a5644ab3afe640"
				+ "2541fe719bf500258813bbd55a721c0a"
				+ "4e5a6699a9f24fe07e572baacdf8cdea"
				+ "24fc79ccbf0979e9371ac23c6d68de36";

			Assert.Equal(expected, Hex.Encode(roundKeys));
		}

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
