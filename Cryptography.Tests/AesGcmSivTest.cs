using System;
using System.IO;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Cryptography.Tests
{
	public class AesGcmSivTest
	{
		[Fact]
		public void TestPolyvalHorner()
		{
			var s = File.ReadAllText("Vectors/aes-128-gcm-siv.json");
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
