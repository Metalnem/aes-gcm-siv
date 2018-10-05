namespace Cryptography.Tests
{
	internal class Vector
	{
		public byte[] Plaintext;
		public byte[] Aad;
		public byte[] Key;
		public byte[] Nonce;
		public byte[] RecordAuthenticationKey;
		public byte[] RecordEncryptionKey;
		public byte[] PolyvalInput;
		public byte[] PolyvalResult;
		public byte[] PolyvalResultXorNonce;
		public byte[] PolyvalResultXorNonceMasked;
		public byte[] Tag;
		public byte[] InitialCounter;
		public byte[] Result;
	}
}
