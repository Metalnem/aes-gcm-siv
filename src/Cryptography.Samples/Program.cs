using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography.Samples
{
	public class Program
	{
		public static void Main(string[] args)
		{
			// Plaintext to encrypt.
			var plaintext = "I'm cooking MC's like a pound of bacon";

			// Create a 32-byte key.
			var key = new byte[32];
			RandomNumberGenerator.Fill(key);

			// Create a 12-byte nonce.
			var nonce = new byte[12];
			RandomNumberGenerator.Fill(nonce);

			// Create a new AesGcmSiv instance. It implements the IDisposable
			// interface, so it's best to create it inside using statement.
			using (var siv = new AesGcmSiv(key))
			{
				// If the message is string, convert it to byte array first.
				var bytes = Encoding.UTF8.GetBytes(plaintext);

				// Encrypt the message.
				var ciphertext = new byte[bytes.Length];
				var tag = new byte[16];
				siv.Encrypt(nonce, bytes, ciphertext, tag);

				// To decrypt the message, call the Decrypt method with the
				// ciphertext and the same nonce that you generated previously.
				siv.Decrypt(nonce, ciphertext, tag, bytes);

				// If the message was originally string,
				// convert if from byte array to string.
				plaintext = Encoding.UTF8.GetString(bytes);

				// Print the decrypted message to the standard output.
				Console.WriteLine(plaintext);
			}
		}
	}
}
