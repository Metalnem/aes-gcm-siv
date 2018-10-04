using System;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.X86.Aes;

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

		public static void KeySchedule(byte[] key, byte[] roundKeys)
		{
			Vector128<byte> xmm1, xmm2, xmm3, xmm14, xmm4, con1, con3, mask;

			fixed (byte* keyPtr = key)
			fixed (byte* roundKeysPtr = roundKeys)
			{
				mask = Sse.StaticCast<int, byte>(Sse2.SetVector128(0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d));
				con1 = Sse.StaticCast<int, byte>(Sse2.SetVector128(1, 1, 1, 1));
				con3 = Sse.StaticCast<sbyte, byte>(Sse2.SetVector128(7, 6, 5, 4, 7, 6, 5, 4, -1, -1, -1, -1, -1, -1, -1, -1));
				xmm4 = Sse2.SetZeroVector128<byte>();
				xmm14 = Sse2.SetZeroVector128<byte>();
				xmm1 = Sse2.LoadVector128(&keyPtr[0]);
				xmm3 = Sse2.LoadVector128(&keyPtr[16]);
				Sse2.Store(&roundKeysPtr[0], xmm1);
				Sse2.Store(&roundKeysPtr[16], xmm3);

				for (int i = 32; i < 14 * 16; i += 32)
				{
					xmm2 = Ssse3.Shuffle(xmm3, mask);
					xmm2 = Aes.EncryptLast(xmm2, con1);
					con1 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(con1), 1));
					xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm1), 32));
					xmm1 = Sse2.Xor(xmm1, xmm4);
					xmm4 = Ssse3.Shuffle(xmm1, con3);
					xmm1 = Sse2.Xor(xmm1, xmm4);
					xmm1 = Sse2.Xor(xmm1, xmm2);
					Sse2.Store(&roundKeysPtr[i], xmm1);
					xmm2 = Sse.StaticCast<uint, byte>(Sse2.Shuffle(Sse.StaticCast<byte, uint>(xmm1), 0xff));
					xmm2 = Aes.EncryptLast(xmm2, xmm14);
					xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm3), 32));
					xmm3 = Sse2.Xor(xmm4, xmm3);
					xmm4 = Ssse3.Shuffle(xmm3, con3);
					xmm3 = Sse2.Xor(xmm4, xmm3);
					xmm3 = Sse2.Xor(xmm2, xmm3);
					Sse2.Store(&roundKeysPtr[i + 16], xmm3);
				}

				xmm2 = Ssse3.Shuffle(xmm3, mask);
				xmm2 = Aes.EncryptLast(xmm2, con1);
				xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm1), 32));
				xmm1 = Sse2.Xor(xmm1, xmm4);
				xmm4 = Ssse3.Shuffle(xmm1, con3);
				xmm1 = Sse2.Xor(xmm1, xmm4);
				xmm1 = Sse2.Xor(xmm1, xmm2);
				Sse2.Store(&roundKeysPtr[14 * 16], xmm1);
			}
		}

		public static void InitPowersTable(byte[] powersTable, byte[] hashKey)
		{
			Vector128<ulong> tmp0, tmp1, tmp2, tmp3, tmp4, poly, t;

			fixed (byte* powersTablePtr = powersTable)
			fixed (byte* hashKeyPtr = hashKey)
			{
				poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));
				t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(hashKeyPtr));
				tmp0 = t;
				Sse2.Store(powersTablePtr, Sse.StaticCast<ulong, byte>(t));

				for (int i = 16; i < powersTable.Length; i += 16)
				{
					tmp1 = Pclmulqdq.CarrylessMultiply(t, tmp0, 0x00);
					tmp4 = Pclmulqdq.CarrylessMultiply(t, tmp0, 0x11);
					tmp2 = Pclmulqdq.CarrylessMultiply(t, tmp0, 0x10);
					tmp3 = Pclmulqdq.CarrylessMultiply(t, tmp0, 0x01);
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
					Sse2.Store(&powersTablePtr[i], Sse.StaticCast<ulong, byte>(t));
				}
			}
		}

		public static void PolyvalHorner(byte[] tag, byte[] hashKey, byte[] input)
		{
			Vector128<ulong> tmp1, tmp2, tmp3, tmp4, poly, t, h;

			fixed (byte* tagPtr = tag)
			fixed (byte* hashKeyPtr = hashKey)
			fixed (byte* inputPtr = input)
			{
				poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));
				t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(tagPtr));
				h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(hashKeyPtr));

				for (int i = 0; i < input.Length; i += 16)
				{
					t = Sse2.Xor(t, Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&inputPtr[i])));
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
