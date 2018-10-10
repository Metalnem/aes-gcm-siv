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

		private readonly byte[] roundKeys;
		private bool disposed;

		// TODO: fix code duplication in two CalculateTag methods
		// TODO: call Marshal.AllocHGlobal for round keys in constructor and align the result
		// TODO: implement the correct key derivation method for encrypting large inputs
		// TODO: add benchmark results to README
		// TODO: add libsodium and miscreant to benchmarks
		// TODO: more consistent naming and indexing (shorter names for pointers and sizes)
		// TODO: add Span<byte> overloads
		// TODO: throw if platform not supported
		// TODO: add IsSupported property
		// TODO: zero out all intermediate keys in Encrypt/Decrypt methods
		// TODO: make all private methods private
		// TODO: test max plaintext size
		// TODO: test both polyval and encrypt methods on all input sizes
		// TODO: try to pipeline CLMUL instructions and to load powers as needed
		// TODO: move unsafe implementations to separate file

		public AesGcmSiv(byte[] key)
		{
			ThrowIfNull(key, nameof(key));

			if (key.Length != KeySizeInBytes)
			{
				throw new CryptographicException("Specified key is not a valid size for this algorithm.");
			}

			roundKeys = new byte[15 * 16];
			KeySchedule(key, roundKeys);
		}

		public void Encrypt(
			byte[] nonce,
			byte[] plaintext,
			byte[] ciphertext,
			byte[] tag,
			byte[] associatedData = null)
		{
			ThrowIfDisposed();

			ThrowIfNull(nonce, nameof(nonce));
			ThrowIfNull(plaintext, nameof(plaintext));
			ThrowIfNull(ciphertext, nameof(ciphertext));
			ThrowIfNull(tag, nameof(tag));

			Encrypt((ReadOnlySpan<byte>)nonce, plaintext, ciphertext, tag, associatedData);
		}

		public void Encrypt(
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> plaintext,
			Span<byte> ciphertext,
			Span<byte> tag,
			ReadOnlySpan<byte> associatedData)
		{
			ThrowIfDisposed();
			CheckParameters(plaintext, ciphertext, nonce, tag);

			int plaintextLength = plaintext.Length;
			int associatedDataLength = associatedData.Length;

			byte* hashKey = stackalloc byte[16];
			byte* encryptionKey = stackalloc byte[32];
			byte* encryptionRoundKeys = stackalloc byte[15 * 16];

			fixed (byte* roundKeysPtr = roundKeys)
			fixed (byte* noncePtr = nonce)
			fixed (byte* plaintextPtr = plaintext)
			fixed (byte* ciphertextPtr = ciphertext)
			fixed (byte* tagPtr = tag)
			fixed (byte* associatedDataPtr = associatedData)
			{
				if (plaintextLength + associatedDataLength <= 128)
				{
					DeriveKeys(noncePtr, hashKey, encryptionKey, roundKeysPtr);

					CalculateTagHorner(
						noncePtr,
						plaintextPtr,
						plaintextLength,
						associatedDataPtr,
						associatedDataLength,
						hashKey,
						encryptionKey,
						tagPtr,
						encryptionRoundKeys
					);

					Encrypt4(plaintextPtr, ciphertextPtr, plaintextLength, tagPtr, encryptionRoundKeys);
				}
				else
				{
					DeriveKeys(noncePtr, hashKey, encryptionKey, roundKeysPtr);

					CalculateTagPowersTable(
						noncePtr,
						plaintextPtr,
						plaintextLength,
						associatedDataPtr,
						associatedDataLength,
						hashKey,
						encryptionKey,
						tagPtr,
						encryptionRoundKeys
					);

					Encrypt8(plaintextPtr, ciphertextPtr, plaintextLength, tagPtr, encryptionRoundKeys);
				}
			}
		}

		public void Decrypt(
			byte[] nonce,
			byte[] ciphertext,
			byte[] tag,
			byte[] plaintext,
			byte[] associatedData = null)
		{
			ThrowIfDisposed();

			ThrowIfNull(nonce, nameof(nonce));
			ThrowIfNull(plaintext, nameof(plaintext));
			ThrowIfNull(ciphertext, nameof(ciphertext));
			ThrowIfNull(tag, nameof(tag));

			Decrypt((ReadOnlySpan<byte>)nonce, ciphertext, tag, plaintext, associatedData);
		}

		public void Decrypt(
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> tag,
			Span<byte> plaintext,
			ReadOnlySpan<byte> associatedData)
		{
			ThrowIfDisposed();
			CheckParameters(plaintext, ciphertext, nonce, tag);
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
			Vector128<byte> xmm1, xmm2, xmm3, xmm4, xmm14, con1, con3, mask;

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

				for (int i = 0; i < 6; ++i)
				{
					xmm2 = Ssse3.Shuffle(xmm3, mask);
					xmm2 = Aes.EncryptLast(xmm2, con1);
					con1 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(con1), 1));
					xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm1), 32));
					xmm1 = Sse2.Xor(xmm1, xmm4);
					xmm4 = Ssse3.Shuffle(xmm1, con3);
					xmm1 = Sse2.Xor(xmm1, xmm4);
					xmm1 = Sse2.Xor(xmm1, xmm2);
					Sse2.Store(&roundKeysPtr[(i + 1) * 2 * 16], xmm1);

					xmm2 = Sse.StaticCast<uint, byte>(Sse2.Shuffle(Sse.StaticCast<byte, uint>(xmm1), 0xff));
					xmm2 = Aes.EncryptLast(xmm2, xmm14);
					xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm3), 32));
					xmm3 = Sse2.Xor(xmm4, xmm3);
					xmm4 = Ssse3.Shuffle(xmm3, con3);
					xmm3 = Sse2.Xor(xmm4, xmm3);
					xmm3 = Sse2.Xor(xmm2, xmm3);
					Sse2.Store(&roundKeysPtr[((i + 1) * 2 + 1) * 16], xmm3);
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

		public static void DeriveKeys(byte* nonce, byte* hashKey, byte* encryptionKey, byte* roundKeys)
		{
			Vector128<byte> xmm1, xmm3, b1, b2, b3, b4, b5, b6;
			Vector128<int> one = Sse2.SetVector128(0, 0, 0, 1);

			var n = (int*)nonce;

			b1 = Sse.StaticCast<int, byte>(Sse2.SetVector128(n[2], n[1], n[0], 0));
			b2 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b1), one));
			b3 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b2), one));
			b4 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b3), one));
			b5 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b4), one));
			b6 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b5), one));

			xmm1 = Sse2.LoadVector128(&roundKeys[0]);
			xmm3 = Sse2.LoadVector128(&roundKeys[16]);

			b1 = Sse2.Xor(b1, xmm1);
			b2 = Sse2.Xor(b2, xmm1);
			b3 = Sse2.Xor(b3, xmm1);
			b4 = Sse2.Xor(b4, xmm1);
			b5 = Sse2.Xor(b5, xmm1);
			b6 = Sse2.Xor(b6, xmm1);

			b1 = Aes.Encrypt(b1, xmm3);
			b2 = Aes.Encrypt(b2, xmm3);
			b3 = Aes.Encrypt(b3, xmm3);
			b4 = Aes.Encrypt(b4, xmm3);
			b5 = Aes.Encrypt(b5, xmm3);
			b6 = Aes.Encrypt(b6, xmm3);

			for (int i = 1; i <= 6; ++i)
			{
				xmm1 = Sse2.LoadVector128(&roundKeys[2 * 16 * i]);
				xmm3 = Sse2.LoadVector128(&roundKeys[2 * 16 * i + 16]);

				b1 = Aes.Encrypt(b1, xmm1);
				b2 = Aes.Encrypt(b2, xmm1);
				b3 = Aes.Encrypt(b3, xmm1);
				b4 = Aes.Encrypt(b4, xmm1);
				b5 = Aes.Encrypt(b5, xmm1);
				b6 = Aes.Encrypt(b6, xmm1);

				b1 = Aes.Encrypt(b1, xmm3);
				b2 = Aes.Encrypt(b2, xmm3);
				b3 = Aes.Encrypt(b3, xmm3);
				b4 = Aes.Encrypt(b4, xmm3);
				b5 = Aes.Encrypt(b5, xmm3);
				b6 = Aes.Encrypt(b6, xmm3);
			}

			xmm1 = Sse2.LoadVector128(&roundKeys[14 * 16]);

			b1 = Aes.EncryptLast(b1, xmm1);
			b2 = Aes.EncryptLast(b2, xmm1);
			b3 = Aes.EncryptLast(b3, xmm1);
			b4 = Aes.EncryptLast(b4, xmm1);
			b5 = Aes.EncryptLast(b5, xmm1);
			b6 = Aes.EncryptLast(b6, xmm1);

			Sse2.StoreLow((long*)hashKey + 0, Sse.StaticCast<byte, long>(b1));
			Sse2.StoreLow((long*)hashKey + 1, Sse.StaticCast<byte, long>(b2));

			Sse2.StoreLow((long*)encryptionKey + 0, Sse.StaticCast<byte, long>(b3));
			Sse2.StoreLow((long*)encryptionKey + 1, Sse.StaticCast<byte, long>(b4));
			Sse2.StoreLow((long*)encryptionKey + 2, Sse.StaticCast<byte, long>(b5));
			Sse2.StoreLow((long*)encryptionKey + 3, Sse.StaticCast<byte, long>(b6));
		}

		public static void InitPowersTable(byte* powersTable, int size, byte* hashKey)
		{
			Vector128<ulong> tmp0, tmp1, tmp2, tmp3, tmp4, poly, t;

			poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));
			t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(hashKey));
			tmp0 = t;
			Sse2.Store(powersTable, Sse.StaticCast<ulong, byte>(t));

			for (int i = 1; i < size; ++i)
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
				Sse2.Store(&powersTable[i * 16], Sse.StaticCast<ulong, byte>(t));
			}
		}

		public static void PolyvalHorner(byte* polyval, byte* hashKey, byte* input, int length)
		{
			if (length == 0)
			{
				return;
			}

			int blocks = Math.DivRem(length, 16, out int remainder);
			Vector128<ulong> tmp1, tmp2, tmp3, tmp4, poly, t, h;

			poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));
			t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(polyval));
			h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(hashKey));

			for (int i = 0; i < blocks; ++i)
			{
				t = Sse2.Xor(t, Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&input[i * 16])));
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

			if (remainder != 0)
			{
				byte* b = stackalloc byte[16];
				new Span<byte>(input + length - remainder, remainder).CopyTo(new Span<byte>(b, 16));

				t = Sse2.Xor(t, Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(b)));
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

			Sse2.Store(polyval, Sse.StaticCast<ulong, byte>(t));
		}

		public static void PolyvalPowersTable(byte* polyval, byte* powersTable, byte* input, int length)
		{
			if (length == 0)
			{
				return;
			}

			int blocks = Math.DivRem(length, 16, out int remainder16);
			int remainder128 = length % 128 - remainder16;

			Vector128<ulong> data, h, tmp0, tmp1, tmp2, tmp3, tmp4;
			Vector128<sbyte> tb;

			var xhi = Sse2.SetZeroVector128<ulong>();
			var poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));
			var t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(polyval));

			var h0 = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[0 * 16]));
			var h1 = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[1 * 16]));
			var h2 = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[2 * 16]));
			var h3 = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[3 * 16]));
			var h4 = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[4 * 16]));
			var h5 = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[5 * 16]));
			var h6 = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[6 * 16]));
			var h7 = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[7 * 16]));

			if (remainder128 != 0)
			{
				int remainder128Blocks = remainder128 / 16;
				blocks -= remainder128Blocks;

				data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(input));
				data = Sse2.Xor(t, data);
				h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[(remainder128Blocks - 1) * 16]));
				tmp2 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
				tmp0 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
				tmp1 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
				tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
				tmp2 = Sse2.Xor(tmp2, tmp3);

				for (int i = 1; i < remainder128Blocks; ++i)
				{
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&input[i * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&powersTable[(remainder128Blocks - i - 1) * 16]));
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);
				}

				tmp3 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
				tmp2 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
				xhi = Sse2.Xor(tmp3, tmp1);
				t = Sse2.Xor(tmp0, tmp2);
			}

			if (blocks != 0)
			{
				var fixedInputPtr = input + remainder128;

				if (remainder128 == 0)
				{
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[7 * 16]));
					tmp2 = Pclmulqdq.CarrylessMultiply(data, h0, 0x01);
					tmp0 = Pclmulqdq.CarrylessMultiply(data, h0, 0x00);
					tmp1 = Pclmulqdq.CarrylessMultiply(data, h0, 0x11);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h0, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[6 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[5 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[4 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[3 * 16]));
					tmp4 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[2 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[1 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(fixedInputPtr));
					data = Sse2.Xor(t, data);

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h7, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h7, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h7, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h7, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					tmp3 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
					tmp2 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
					xhi = Sse2.Xor(tmp3, tmp1);
					t = Sse2.Xor(tmp0, tmp2);
				}

				for (int i = remainder128 == 0 ? 8 : 0; i < blocks; i += 8)
				{
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[(i + 7) * 16]));
					tmp2 = Pclmulqdq.CarrylessMultiply(data, h0, 0x01);
					tmp0 = Pclmulqdq.CarrylessMultiply(data, h0, 0x00);
					tmp1 = Pclmulqdq.CarrylessMultiply(data, h0, 0x11);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h0, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[(i + 6) * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[(i + 5) * 16]));
					tmp4 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
					tb = Sse.StaticCast<ulong, sbyte>(t);
					t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(tb, tb, 8));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					t = Sse2.Xor(t, tmp4);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[(i + 4) * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[(i + 3) * 16]));
					tmp4 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
					tb = Sse.StaticCast<ulong, sbyte>(t);
					t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(tb, tb, 8));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					t = Sse2.Xor(t, tmp4);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[(i + 2) * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					t = Sse2.Xor(t, xhi);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[(i + 1) * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInputPtr[i * 16]));
					data = Sse2.Xor(t, data);

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h7, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h7, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h7, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h7, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					tmp3 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
					tmp2 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
					xhi = Sse2.Xor(tmp3, tmp1);
					t = Sse2.Xor(tmp0, tmp2);
				}
			}

			if (blocks != 0 || remainder128 != 0)
			{
				tmp3 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				tb = Sse.StaticCast<ulong, sbyte>(t);
				t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(tb, tb, 8));
				t = Sse2.Xor(tmp3, t);
				tmp3 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				tb = Sse.StaticCast<ulong, sbyte>(t);
				t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(tb, tb, 8));
				t = Sse2.Xor(tmp3, t);
				t = Sse2.Xor(xhi, t);
			}

			if (remainder16 != 0)
			{
				byte* b = stackalloc byte[16];
				new Span<byte>(&input[length - remainder16], remainder16).CopyTo(new Span<byte>(b, 16));

				data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(b));
				data = Sse2.Xor(t, data);
				tmp2 = Pclmulqdq.CarrylessMultiply(data, h0, 0x01);
				tmp0 = Pclmulqdq.CarrylessMultiply(data, h0, 0x00);
				tmp1 = Pclmulqdq.CarrylessMultiply(data, h0, 0x11);
				tmp3 = Pclmulqdq.CarrylessMultiply(data, h0, 0x10);
				tmp2 = Sse2.Xor(tmp2, tmp3);
				tmp3 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
				tmp2 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
				xhi = Sse2.Xor(tmp3, tmp1);
				t = Sse2.Xor(tmp0, tmp2);

				tmp3 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				tb = Sse.StaticCast<ulong, sbyte>(t);
				t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(tb, tb, 8));
				t = Sse2.Xor(tmp3, t);
				tmp3 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				tb = Sse.StaticCast<ulong, sbyte>(t);
				t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(tb, tb, 8));
				t = Sse2.Xor(tmp3, t);
				t = Sse2.Xor(xhi, t);
			}

			Sse2.Store(polyval, Sse.StaticCast<ulong, byte>(t));
		}

		public static void EncryptTag(byte* plaintext, byte* ciphertext, byte* key, byte* roundKeys)
		{
			Vector128<byte> xmm1, xmm2, xmm3, xmm4, xmm14, b1, con1, con3, mask;

			mask = Sse.StaticCast<int, byte>(Sse2.SetVector128(0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d));
			con1 = Sse.StaticCast<int, byte>(Sse2.SetVector128(1, 1, 1, 1));
			con3 = Sse.StaticCast<sbyte, byte>(Sse2.SetVector128(7, 6, 5, 4, 7, 6, 5, 4, -1, -1, -1, -1, -1, -1, -1, -1));
			xmm4 = Sse2.SetZeroVector128<byte>();
			xmm14 = Sse2.SetZeroVector128<byte>();
			xmm1 = Sse2.LoadVector128(&key[0]);
			xmm3 = Sse2.LoadVector128(&key[16]);
			Sse2.Store(&roundKeys[0], xmm1);
			b1 = Sse2.LoadVector128(&plaintext[0]);
			b1 = Sse2.Xor(b1, xmm1);
			b1 = Aes.Encrypt(b1, xmm3);
			Sse2.Store(&roundKeys[16], xmm3);

			for (int i = 0; i < 6; ++i)
			{
				xmm2 = Ssse3.Shuffle(xmm3, mask);
				xmm2 = Aes.EncryptLast(xmm2, con1);
				con1 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(con1), 1));
				xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm1), 32));
				xmm1 = Sse2.Xor(xmm1, xmm4);
				xmm4 = Ssse3.Shuffle(xmm1, con3);
				xmm1 = Sse2.Xor(xmm1, xmm4);
				xmm1 = Sse2.Xor(xmm1, xmm2);
				Sse2.Store(&roundKeys[(i + 1) * 2 * 16], xmm1);
				b1 = Aes.Encrypt(b1, xmm1);

				xmm2 = Sse.StaticCast<uint, byte>(Sse2.Shuffle(Sse.StaticCast<byte, uint>(xmm1), 0xff));
				xmm2 = Aes.EncryptLast(xmm2, xmm14);
				xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm3), 32));
				xmm3 = Sse2.Xor(xmm4, xmm3);
				xmm4 = Ssse3.Shuffle(xmm3, con3);
				xmm3 = Sse2.Xor(xmm4, xmm3);
				xmm3 = Sse2.Xor(xmm2, xmm3);
				Sse2.Store(&roundKeys[((i + 1) * 2 + 1) * 16], xmm3);
				b1 = Aes.Encrypt(b1, xmm3);
			}

			xmm2 = Ssse3.Shuffle(xmm3, mask);
			xmm2 = Aes.EncryptLast(xmm2, con1);
			xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm1), 32));
			xmm1 = Sse2.Xor(xmm1, xmm4);
			xmm4 = Ssse3.Shuffle(xmm1, con3);
			xmm1 = Sse2.Xor(xmm1, xmm4);
			xmm1 = Sse2.Xor(xmm1, xmm2);
			Sse2.Store(&roundKeys[14 * 16], xmm1);

			b1 = Aes.EncryptLast(b1, xmm1);
			Sse2.Store(ciphertext, b1);
		}

		public static void CalculateTagHorner(
			byte* nonce,
			byte* plaintext,
			int plaintextLength,
			byte* associatedData,
			int associatedDataLength,
			byte* hashKey,
			byte* encryptionKey,
			byte* tag,
			byte* roundKeys)
		{
			byte* lengthBlock = stackalloc byte[16];

			((long*)lengthBlock)[0] = associatedDataLength * 8;
			((long*)lengthBlock)[1] = plaintextLength * 8;

			byte* polyval = stackalloc byte[16];

			PolyvalHorner(polyval, hashKey, associatedData, associatedDataLength);
			PolyvalHorner(polyval, hashKey, plaintext, plaintextLength);
			PolyvalHorner(polyval, hashKey, lengthBlock, 16);

			var n = (int*)nonce;
			var t = Sse2.LoadVector128(polyval);
			t = Sse2.Xor(t, Sse.StaticCast<int, byte>(Sse2.SetVector128(0, n[2], n[1], n[0])));

			var andMask = Sse2.SetVector128(0x7fffffffffffffff, 0xffffffffffffffff);
			t = Sse2.And(t, Sse.StaticCast<ulong, byte>(andMask));

			Sse2.Store(polyval, t);
			EncryptTag(polyval, tag, encryptionKey, roundKeys);
		}

		public static void CalculateTagPowersTable(
			byte* nonce,
			byte* plaintext,
			int plaintextLength,
			byte* associatedData,
			int associatedDataLength,
			byte* hashKey,
			byte* encryptionKey,
			byte* tag,
			byte* roundKeys)
		{
			byte* powersTable = stackalloc byte[8 * 16];
			InitPowersTable(powersTable, 8, hashKey);

			byte* lengthBlock = stackalloc byte[16];

			((long*)lengthBlock)[0] = associatedDataLength * 8;
			((long*)lengthBlock)[1] = plaintextLength * 8;

			byte* polyval = stackalloc byte[16];

			PolyvalPowersTable(polyval, powersTable, associatedData, associatedDataLength);
			PolyvalPowersTable(polyval, powersTable, plaintext, plaintextLength);
			PolyvalPowersTable(polyval, powersTable, lengthBlock, 16);

			var n = (int*)nonce;
			var t = Sse2.LoadVector128(polyval);
			t = Sse2.Xor(t, Sse.StaticCast<int, byte>(Sse2.SetVector128(0, n[2], n[1], n[0])));

			var andMask = Sse2.SetVector128(0x7fffffffffffffff, 0xffffffffffffffff);
			t = Sse2.And(t, Sse.StaticCast<ulong, byte>(andMask));

			Sse2.Store(polyval, t);
			EncryptTag(polyval, tag, encryptionKey, roundKeys);
		}

		public static void Encrypt4(byte* plaintext, byte* ciphertext, int length, byte* tag, byte* roundKeys)
		{
			if (length == 0)
			{
				return;
			}

			int blocks = Math.DivRem(length, 16, out int remainder16);
			int remainder16Pos = length - remainder16;
			int remainder4 = blocks % 4;
			int remainder4Pos = blocks - remainder4;

			Vector128<byte> key;
			Vector128<byte> orMask = Sse.StaticCast<uint, byte>(Sse2.SetVector128(0x80000000, 0, 0, 0));
			Vector128<byte> ctr = Sse2.Or(Sse2.LoadVector128(tag), orMask);

			var one = Sse2.SetVector128(0, 0, 0, 1);
			var two = Sse2.SetVector128(0, 0, 0, 2);

			for (int i = 0; i < remainder4Pos; i += 4)
			{
				var tmp0 = ctr;
				var tmp1 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), one));
				var tmp2 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), two));
				var tmp3 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(tmp2), one));
				ctr = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(tmp2), two));

				key = Sse2.LoadVector128(roundKeys);
				tmp0 = Sse2.Xor(tmp0, key);
				tmp1 = Sse2.Xor(tmp1, key);
				tmp2 = Sse2.Xor(tmp2, key);
				tmp3 = Sse2.Xor(tmp3, key);

				for (int j = 1; j < 14; ++j)
				{
					key = Sse2.LoadVector128(&roundKeys[j * 16]);
					tmp0 = Aes.Encrypt(tmp0, key);
					tmp1 = Aes.Encrypt(tmp1, key);
					tmp2 = Aes.Encrypt(tmp2, key);
					tmp3 = Aes.Encrypt(tmp3, key);
				}

				key = Sse2.LoadVector128(&roundKeys[14 * 16]);
				tmp0 = Aes.EncryptLast(tmp0, key);
				tmp1 = Aes.EncryptLast(tmp1, key);
				tmp2 = Aes.EncryptLast(tmp2, key);
				tmp3 = Aes.EncryptLast(tmp3, key);

				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(&plaintext[(i + 0) * 16]));
				tmp1 = Sse2.Xor(tmp1, Sse2.LoadVector128(&plaintext[(i + 1) * 16]));
				tmp2 = Sse2.Xor(tmp2, Sse2.LoadVector128(&plaintext[(i + 2) * 16]));
				tmp3 = Sse2.Xor(tmp3, Sse2.LoadVector128(&plaintext[(i + 3) * 16]));

				Sse2.Store(&ciphertext[(i + 0) * 16], tmp0);
				Sse2.Store(&ciphertext[(i + 1) * 16], tmp1);
				Sse2.Store(&ciphertext[(i + 2) * 16], tmp2);
				Sse2.Store(&ciphertext[(i + 3) * 16], tmp3);
			}

			for (int i = 0; i < remainder4; ++i)
			{
				var tmp0 = ctr;
				ctr = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), one));
				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(roundKeys));

				for (int j = 1; j < 14; ++j)
				{
					tmp0 = Aes.Encrypt(tmp0, Sse2.LoadVector128(&roundKeys[j * 16]));
				}

				tmp0 = Aes.EncryptLast(tmp0, Sse2.LoadVector128(&roundKeys[14 * 16]));
				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(&plaintext[(remainder4Pos + i) * 16]));
				Sse2.Store(&ciphertext[(remainder4Pos + i) * 16], tmp0);
			}

			if (remainder16 != 0)
			{
				byte* b = stackalloc byte[16];

				var source = new Span<byte>(plaintext + remainder16Pos, remainder16);
				var destination = new Span<byte>(b, 16);

				source.CopyTo(destination);

				var tmp0 = ctr;
				ctr = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), one));
				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(roundKeys));

				for (int j = 1; j < 14; ++j)
				{
					tmp0 = Aes.Encrypt(tmp0, Sse2.LoadVector128(&roundKeys[j * 16]));
				}

				tmp0 = Aes.EncryptLast(tmp0, Sse2.LoadVector128(&roundKeys[14 * 16]));
				Sse2.Store(b, Sse2.Xor(tmp0, Sse2.LoadVector128(b)));

				source = new Span<byte>(b, remainder16);
				destination = new Span<byte>(ciphertext + remainder16Pos, remainder16);

				source.CopyTo(destination);
			}
		}

		public static void Encrypt8(byte* plaintext, byte* ciphertext, int length, byte* tag, byte* roundKeys)
		{
			if (length == 0)
			{
				return;
			}

			int blocks = Math.DivRem(length, 16, out int remainder16);
			int remainder16Pos = length - remainder16;
			int remainder8 = blocks % 8;
			int remainder8Pos = blocks - remainder8;

			Vector128<byte> key;
			Vector128<byte> orMask = Sse.StaticCast<uint, byte>(Sse2.SetVector128(0x80000000, 0, 0, 0));
			Vector128<byte> ctr = Sse2.Or(Sse2.LoadVector128(tag), orMask);

			var one = Sse2.SetVector128(0, 0, 0, 1);
			var two = Sse2.SetVector128(0, 0, 0, 2);

			for (int i = 0; i < remainder8Pos; i += 8)
			{
				var tmp0 = ctr;
				var tmp1 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), one));
				var tmp2 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), two));
				var tmp3 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(tmp2), one));
				var tmp4 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(tmp2), two));
				var tmp5 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(tmp4), one));
				var tmp6 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(tmp4), two));
				var tmp7 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(tmp6), one));
				ctr = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(tmp6), two));

				key = Sse2.LoadVector128(roundKeys);
				tmp0 = Sse2.Xor(tmp0, key);
				tmp1 = Sse2.Xor(tmp1, key);
				tmp2 = Sse2.Xor(tmp2, key);
				tmp3 = Sse2.Xor(tmp3, key);
				tmp4 = Sse2.Xor(tmp4, key);
				tmp5 = Sse2.Xor(tmp5, key);
				tmp6 = Sse2.Xor(tmp6, key);
				tmp7 = Sse2.Xor(tmp7, key);

				for (int j = 1; j < 14; ++j)
				{
					key = Sse2.LoadVector128(&roundKeys[j * 16]);
					tmp0 = Aes.Encrypt(tmp0, key);
					tmp1 = Aes.Encrypt(tmp1, key);
					tmp2 = Aes.Encrypt(tmp2, key);
					tmp3 = Aes.Encrypt(tmp3, key);
					tmp4 = Aes.Encrypt(tmp4, key);
					tmp5 = Aes.Encrypt(tmp5, key);
					tmp6 = Aes.Encrypt(tmp6, key);
					tmp7 = Aes.Encrypt(tmp7, key);
				}

				key = Sse2.LoadVector128(&roundKeys[14 * 16]);
				tmp0 = Aes.EncryptLast(tmp0, key);
				tmp1 = Aes.EncryptLast(tmp1, key);
				tmp2 = Aes.EncryptLast(tmp2, key);
				tmp3 = Aes.EncryptLast(tmp3, key);
				tmp4 = Aes.EncryptLast(tmp4, key);
				tmp5 = Aes.EncryptLast(tmp5, key);
				tmp6 = Aes.EncryptLast(tmp6, key);
				tmp7 = Aes.EncryptLast(tmp7, key);

				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(&plaintext[(i + 0) * 16]));
				tmp1 = Sse2.Xor(tmp1, Sse2.LoadVector128(&plaintext[(i + 1) * 16]));
				tmp2 = Sse2.Xor(tmp2, Sse2.LoadVector128(&plaintext[(i + 2) * 16]));
				tmp3 = Sse2.Xor(tmp3, Sse2.LoadVector128(&plaintext[(i + 3) * 16]));
				tmp4 = Sse2.Xor(tmp4, Sse2.LoadVector128(&plaintext[(i + 4) * 16]));
				tmp5 = Sse2.Xor(tmp5, Sse2.LoadVector128(&plaintext[(i + 5) * 16]));
				tmp6 = Sse2.Xor(tmp6, Sse2.LoadVector128(&plaintext[(i + 6) * 16]));
				tmp7 = Sse2.Xor(tmp7, Sse2.LoadVector128(&plaintext[(i + 7) * 16]));

				Sse2.Store(&ciphertext[(i + 0) * 16], tmp0);
				Sse2.Store(&ciphertext[(i + 1) * 16], tmp1);
				Sse2.Store(&ciphertext[(i + 2) * 16], tmp2);
				Sse2.Store(&ciphertext[(i + 3) * 16], tmp3);
				Sse2.Store(&ciphertext[(i + 4) * 16], tmp4);
				Sse2.Store(&ciphertext[(i + 5) * 16], tmp5);
				Sse2.Store(&ciphertext[(i + 6) * 16], tmp6);
				Sse2.Store(&ciphertext[(i + 7) * 16], tmp7);
			}

			for (int i = 0; i < remainder8; ++i)
			{
				var tmp0 = ctr;
				ctr = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), one));
				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(roundKeys));

				for (int j = 1; j < 14; ++j)
				{
					tmp0 = Aes.Encrypt(tmp0, Sse2.LoadVector128(&roundKeys[j * 16]));
				}

				tmp0 = Aes.EncryptLast(tmp0, Sse2.LoadVector128(&roundKeys[14 * 16]));
				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(&plaintext[(remainder8Pos + i) * 16]));
				Sse2.Store(&ciphertext[(remainder8Pos + i) * 16], tmp0);
			}

			if (remainder16 != 0)
			{
				byte* b = stackalloc byte[16];

				var source = new Span<byte>(plaintext + remainder16Pos, remainder16);
				var destination = new Span<byte>(b, 16);

				source.CopyTo(destination);

				var tmp0 = ctr;
				ctr = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), one));
				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(roundKeys));

				for (int j = 1; j < 14; ++j)
				{
					tmp0 = Aes.Encrypt(tmp0, Sse2.LoadVector128(&roundKeys[j * 16]));
				}

				tmp0 = Aes.EncryptLast(tmp0, Sse2.LoadVector128(&roundKeys[14 * 16]));
				Sse2.Store(b, Sse2.Xor(tmp0, Sse2.LoadVector128(b)));

				source = new Span<byte>(b, remainder16);
				destination = new Span<byte>(ciphertext + remainder16Pos, remainder16);

				source.CopyTo(destination);
			}
		}

		public void Dispose()
		{
			if (!disposed)
			{
				CryptographicOperations.ZeroMemory(roundKeys);
				disposed = true;
			}
		}

		private static void ThrowIfNull(object value, string name)
		{
			if (value == null)
			{
				throw new ArgumentNullException(name);
			}
		}

		private void ThrowIfDisposed()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(AesGcmSiv));
			}
		}
	}
}
