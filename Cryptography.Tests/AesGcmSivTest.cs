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
				using (var siv = new AesGcmSiv(vector.Key))
				{
					var tag = new byte[16];
					var ciphertext = new byte[vector.Plaintext.Length];

					siv.Encrypt(vector.Nonce, vector.Plaintext, ciphertext, tag, vector.Aad);
					Assert.Equal(Hex.Encode(vector.Result), Hex.Encode(Concat(ciphertext, tag)));

					siv.Encrypt((ReadOnlySpan<byte>)vector.Nonce, vector.Plaintext, ciphertext, tag, vector.Aad);
					Assert.Equal(Hex.Encode(vector.Result), Hex.Encode(Concat(ciphertext, tag)));
				}
			}
		}

		[Fact]
		public void TestMaxInputLength()
		{
			var key = new byte[32];
			var nonce = new byte[12];
			var plaintext = new byte[0x7fffffc7];
			var tag = new byte[16];

			using (var siv = new AesGcmSiv(key))
			{
				siv.Encrypt(nonce, plaintext, plaintext, tag);
				Assert.Equal("b8f9d292c80c757ce0639ee04dba3ebd", Hex.Encode(tag));
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

		private static byte[] Concat(byte[] x, byte[] y)
		{
			var result = new byte[x.Length + y.Length];

			x.CopyTo(result, 0);
			y.CopyTo(result, x.Length);

			return result;
		}
	}
}
