using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Cryptography.Benchmarks
{
	internal static class Libsodium
	{
		private const string Name = "libsodium";

		static Libsodium()
		{
			if (sodium_init() == -1)
			{
				throw new CryptographicException("Failed to initialize libsodium.");
			}
		}

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		private static extern int sodium_init();

		[DllImport(Name, CallingConvention = CallingConvention.Cdecl)]
		private static extern int crypto_aead_aes256gcm_encrypt_detached(
			ref byte c,
			ref byte mac,
			out long maclen_p,
			ref byte m,
			long mlen,
			ref byte ad,
			long adlen,
			IntPtr nsec,
			ref byte npub,
			ref byte k
		);

		public static void Encrypt(
			ReadOnlySpan<byte> key,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> plaintext,
			Span<byte> ciphertext,
			Span<byte> tag,
			ReadOnlySpan<byte> associatedData)
		{
			int result = Libsodium.crypto_aead_aes256gcm_encrypt_detached(
				ref MemoryMarshal.GetReference(ciphertext),
				ref MemoryMarshal.GetReference(tag),
				out long length,
			 	ref MemoryMarshal.GetReference(plaintext),
				plaintext.Length,
				ref MemoryMarshal.GetReference(associatedData),
				associatedData.Length,
				IntPtr.Zero,
				ref MemoryMarshal.GetReference(nonce),
				ref MemoryMarshal.GetReference(key)
			);

			if (result != 0)
			{
				throw new CryptographicException("Encryption failed.");
			}
		}
	}
}
