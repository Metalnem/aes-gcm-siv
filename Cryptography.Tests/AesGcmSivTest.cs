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
		private static readonly List<string> files = new List<string>
		{
			"Vectors/aes-128-gcm-siv.json",
			"Vectors/aes-256-gcm-siv.json",
			"Vectors/counter-wrap.json"
		};

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
		public void TestDeriveKeys()
		{
			foreach (var vector in LoadVectors(files[1]))
			{
				var roundKeys = new byte[15 * 16];
				AesGcmSiv.KeySchedule(vector.Key, roundKeys);

				var hashKey = new byte[16];
				var encryptionKey = new byte[32];
				AesGcmSiv.DeriveKeys(vector.Nonce, hashKey, encryptionKey, roundKeys);

				Assert.Equal(Hex.Encode(vector.RecordAuthenticationKey), Hex.Encode(hashKey));
				Assert.Equal(Hex.Encode(vector.RecordEncryptionKey), Hex.Encode(encryptionKey));
			}
		}

		[Fact]
		public void TestPolyvalHorner()
		{
			foreach (var vector in files.SelectMany(LoadVectors))
			{
				var tag = new byte[16];
				AesGcmSiv.PolyvalHorner(tag, vector.RecordAuthenticationKey, vector.PolyvalInput);
				Assert.Equal(Hex.Encode(vector.PolyvalResult), Hex.Encode(tag));
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

		[Fact]
		public void TestCalculateTag()
		{
			foreach (var vector in LoadVectors(files[1]))
			{
				var roundKeys = new byte[15 * 16];
				AesGcmSiv.KeySchedule(vector.Key, roundKeys);

				var hashKey = new byte[16];
				var encryptionKey = new byte[32];
				AesGcmSiv.DeriveKeys(vector.Nonce, hashKey, encryptionKey, roundKeys);

				var tag = new byte[16];
				AesGcmSiv.CalculateTag(vector.Nonce, vector.Plaintext, vector.Aad, hashKey, encryptionKey, tag);

				Assert.Equal(Hex.Encode(vector.Tag), Hex.Encode(tag));
			}
		}

		[Fact]
		public void TestEncrypt()
		{
			foreach (var vector in LoadVectors(files[1]))
			{
				var roundKeys = new byte[15 * 16];
				AesGcmSiv.KeySchedule(vector.Key, roundKeys);

				var hashKey = new byte[16];
				var encryptionKey = new byte[32];
				AesGcmSiv.DeriveKeys(vector.Nonce, hashKey, encryptionKey, roundKeys);

				var tag = new byte[16];
				var encryptionRoundKeys = AesGcmSiv.CalculateTag(vector.Nonce, vector.Plaintext, vector.Aad, hashKey, encryptionKey, tag);

				var ciphertext = new byte[vector.Plaintext.Length + tag.Length];
				Array.Copy(tag, 0, ciphertext, ciphertext.Length - tag.Length, tag.Length);

				AesGcmSiv.Encrypt4(vector.Plaintext, ciphertext, tag, encryptionRoundKeys);
				Assert.Equal(Hex.Encode(vector.Result), Hex.Encode(ciphertext));

				AesGcmSiv.Encrypt8(vector.Plaintext, ciphertext, tag, encryptionRoundKeys);
				Assert.Equal(Hex.Encode(vector.Result), Hex.Encode(ciphertext));
			}
		}

		[Fact]
		public void TestCompareEncrypt4Encrypt8()
		{
			var key = new byte[32];
			var nonce = new byte[12];
			var associatedData = new byte[0];

			for (int i = 0; i < 1024; ++i)
			{
				var roundKeys = new byte[15 * 16];
				AesGcmSiv.KeySchedule(key, roundKeys);

				var hashKey = new byte[16];
				var encryptionKey = new byte[32];
				AesGcmSiv.DeriveKeys(nonce, hashKey, encryptionKey, roundKeys);

				var plaintext = new byte[i];
				var tag = new byte[16];
				var encryptionRoundKeys = AesGcmSiv.CalculateTag(nonce, plaintext, associatedData, hashKey, encryptionKey, tag);

				var ciphertext4 = new byte[plaintext.Length];
				var ciphertext8 = new byte[plaintext.Length];

				AesGcmSiv.Encrypt4(plaintext, ciphertext4, tag, encryptionRoundKeys);
				AesGcmSiv.Encrypt8(plaintext, ciphertext8, tag, encryptionRoundKeys);

				Assert.Equal(Hex.Encode(ciphertext4), Hex.Encode(ciphertext8));
			}
		}

		private static IEnumerable<Vector> LoadVectors(string file)
		{
			var s = File.ReadAllText(file);
			var json = JObject.Parse(s);

			foreach (var vector in json["vectors"])
			{
				yield return new Vector
				{
					Plaintext = GetBytes(vector, "plaintext"),
					Aad = GetBytes(vector, "aad"),
					Key = GetBytes(vector, "key"),
					Nonce = GetBytes(vector, "nonce"),
					RecordAuthenticationKey = GetBytes(vector, "record_authentication_key"),
					RecordEncryptionKey = GetBytes(vector, "record_encryption_key"),
					PolyvalInput = GetBytes(vector, "polyval_input"),
					PolyvalResult = GetBytes(vector, "polyval_result"),
					PolyvalResultXorNonce = GetBytes(vector, "polyval_result_xor_nonce"),
					PolyvalResultXorNonceMasked = GetBytes(vector, "polyval_result_xor_nonce_masked"),
					Tag = GetBytes(vector, "tag"),
					InitialCounter = GetBytes(vector, "initial_counter"),
					Result = GetBytes(vector, "result")
				};
			}
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
