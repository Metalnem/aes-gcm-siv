using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace Cryptography
{
	public unsafe sealed class AesGcmSiv : IDisposable
	{
		private const int KeySizeInBytes = 32;
		private const int NonceSizeInBytes = 12;
		private const int TagSizeInBytes = 16;

		private bool disposed;

		public AesGcmSiv(ReadOnlySpan<byte> key)
		{
			if (key.Length != KeySizeInBytes)
			{
				throw new CryptographicException("Specified key is not a valid size for this algorithm.");
			}
		}

		public AesGcmSiv(byte[] key)
		{
			Exceptions.ThrowIfNull(key, nameof(key));

			if (key.Length != KeySizeInBytes)
			{
				throw new CryptographicException("Specified key is not a valid size for this algorithm.");
			}
		}

		public void Encrypt(
			byte[] nonce,
			byte[] plaintext,
			byte[] ciphertext,
			byte[] tag,
			byte[] associatedData = null)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(AesGcmSiv));

			Exceptions.ThrowIfNull(nonce, nameof(nonce));
			Exceptions.ThrowIfNull(plaintext, nameof(plaintext));
			Exceptions.ThrowIfNull(ciphertext, nameof(ciphertext));
			Exceptions.ThrowIfNull(tag, nameof(tag));

			Encrypt((ReadOnlySpan<byte>)nonce, plaintext, ciphertext, tag, associatedData);
		}

		public void Encrypt(
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> plaintext,
			Span<byte> ciphertext,
			Span<byte> tag,
			ReadOnlySpan<byte> associatedData = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(AesGcmSiv));

			CheckParameters(nonce, plaintext, ciphertext, tag);
		}

		public void Decrypt(
			byte[] nonce,
			byte[] ciphertext,
			byte[] tag,
			byte[] plaintext,
			byte[] associatedData = null)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(AesGcmSiv));

			Exceptions.ThrowIfNull(nonce, nameof(nonce));
			Exceptions.ThrowIfNull(plaintext, nameof(plaintext));
			Exceptions.ThrowIfNull(ciphertext, nameof(ciphertext));
			Exceptions.ThrowIfNull(tag, nameof(tag));

			Decrypt((ReadOnlySpan<byte>)nonce, ciphertext, tag, plaintext, associatedData);
		}

		public void Decrypt(
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> tag,
			Span<byte> plaintext,
			ReadOnlySpan<byte> associatedData = default)
		{
			Exceptions.ThrowIfDisposed(disposed, nameof(AesGcmSiv));

			CheckParameters(nonce, plaintext, ciphertext, tag);
		}

		private static void CheckParameters(
			ReadOnlySpan<byte> plaintext,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> tag)
		{
			if (plaintext.Length != ciphertext.Length)
			{
				throw new ArgumentException("Plaintext and ciphertext must have the same length.");
			}

			if (nonce.Length != NonceSizeInBytes)
			{
				throw new ArgumentException("The specified nonce is not a valid size for this algorithm.", nameof(nonce));
			}

			if (tag.Length != TagSizeInBytes)
			{
				throw new ArgumentException("The specified tag is not a valid size for this algorithm.", nameof(tag));
			}
		}

		public static void PolyvalHorner(byte[] tag, byte[] hashKey, byte[] input)
		{
			int length = input.Length / 16;
			Vector128<ulong> tmp1, tmp2, tmp3, tmp4, t, h, poly;

			fixed (byte* tagPtr = tag)
			fixed (byte* hashKeyPtr = hashKey)
			fixed (byte* inputPtr = input)
			{
				t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(tagPtr));
				h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(hashKeyPtr));
				poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));

				for (int i = 0; i < length; ++i)
				{
					t = Sse2.Xor(t, Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&inputPtr[16 * i])));
					tmp1 = Pclmulqdq.CarrylessMultiply(t, h, 0x00);
					tmp4 = Pclmulqdq.CarrylessMultiply(t, h, 0x11);
					tmp2 = Pclmulqdq.CarrylessMultiply(t, h, 0x10);
					tmp3 = Pclmulqdq.CarrylessMultiply(t, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
					tmp2 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
					tmp1 = Sse2.Xor(tmp3, tmp1);
					tmp4 = Sse2.Xor(tmp4, tmp2);
					tmp2 = Pclmulqdq.CarrylessMultiply(tmp1, poly, 0x10);
					tmp3 = Sse.StaticCast<uint, ulong>(Sse2.Shuffle(Sse.StaticCast<ulong, uint>(tmp1), 78));
					tmp1 = Sse2.Xor(tmp3, tmp2);
					tmp2 = Pclmulqdq.CarrylessMultiply(tmp1, poly, 0x10);
					tmp3 = Sse.StaticCast<uint, ulong>(Sse2.Shuffle(Sse.StaticCast<ulong, uint>(tmp1), 78));
					tmp1 = Sse2.Xor(tmp3, tmp2);
					t = Sse2.Xor(tmp4, tmp1);
				}

				Sse2.Store(tagPtr, Sse.StaticCast<ulong, byte>(t));
			}
		}

		public void Dispose()
		{
			if (!disposed)
			{
				disposed = true;
			}
		}
	}
}
