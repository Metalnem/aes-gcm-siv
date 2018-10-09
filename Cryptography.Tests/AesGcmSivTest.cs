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
		private const string Aes128GcmSiv = "Vectors/aes-128-gcm-siv.json";
		private const string Aes256GcmSiv = "Vectors/aes-256-gcm-siv.json";
		private const string Authentication1000 = "Vectors/authentication-1000.json";
		private const string CounterWrap = "Vectors/counter-wrap.json";
		private const string Encryption1000 = "Vectors/encryption-1000.json";

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
		public void TestEncrypt()
		{
			var files = new string[]
			{
				Aes256GcmSiv,
				Authentication1000,
				CounterWrap,
				Encryption1000
			};

			foreach (var vector in files.SelectMany(LoadVectors))
			{
				var roundKeys = new byte[15 * 16];
				AesGcmSiv.KeySchedule(vector.Key, roundKeys);

				var hashKey = new byte[16];
				var encryptionKey = new byte[32];
				AesGcmSiv.DeriveKeys(vector.Nonce, hashKey, encryptionKey, roundKeys);

				var tag = new byte[16];
				var encryptionRoundKeys = new byte[15 * 16];
				AesGcmSiv.CalculateTag(vector.Nonce, vector.Plaintext, vector.Aad, hashKey, encryptionKey, tag, encryptionRoundKeys);

				var ciphertext = new byte[vector.Plaintext.Length + tag.Length];
				Array.Copy(tag, 0, ciphertext, ciphertext.Length - tag.Length, tag.Length);

				AesGcmSiv.Encrypt4(vector.Plaintext, ciphertext, tag, encryptionRoundKeys);
				Assert.Equal(Hex.Encode(vector.Result), Hex.Encode(ciphertext));

				AesGcmSiv.Encrypt8(vector.Plaintext, ciphertext, tag, encryptionRoundKeys);
				Assert.Equal(Hex.Encode(vector.Result), Hex.Encode(ciphertext));

				using (var siv = new AesGcmSiv(vector.Key))
				{
					var output = new byte[vector.Plaintext.Length];
					siv.Encrypt(vector.Nonce, vector.Plaintext, output, tag, vector.Aad);

					output.CopyTo(ciphertext, 0);
					tag.AsSpan().CopyTo(ciphertext.AsSpan(ciphertext.Length - tag.Length));

					Assert.Equal(Hex.Encode(vector.Result), Hex.Encode(ciphertext));
				}
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
