using Xunit;

namespace Cryptography.Tests
{
	public class AesGcmSivTest
	{
		[Fact]
		public void TestPolyvalHorner()
		{
			var tag = new byte[16];
			var hashKey = Hex.Decode("66e94bd4ef8a2c3b884cfa59ca342b2e");
			var input = Hex.Decode("ff000000000000000000000000000000");

			AesGcmSiv.PolyvalHorner(tag, hashKey, input);
			Assert.Equal("ebe563401e7e91ea3ad6426b8140c394", Hex.Encode(tag));
		}
	}
}
