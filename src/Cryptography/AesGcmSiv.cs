using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.X86.Aes;

namespace Cryptography
{
	/// <summary>
	/// AES-256-GCM-SIV nonce misuse-resistant authenticated encryption mode, defined in
	/// <see href="https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-08">draft-irtf-cfrg-gcmsiv-08</see>.
	/// </summary>
	public unsafe sealed partial class AesGcmSiv : IDisposable
	{
		private static readonly byte[] Empty = new byte[0];

		private const int KeySizeInBytes = 32;
		private const int NonceSizeInBytes = 12;
		private const int TagSizeInBytes = 16;
		private const int RoundKeysSizeInBytes = 15 * 16;

		private const int Align16Overhead = 15;
		private const ulong Align16Mask = ~15ul;

		private readonly IntPtr ptr;
		private readonly byte* ks;

		private readonly int threshold = 128;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="AesGcmSiv"/> class.
		/// </summary>
		/// <param name="key">The secret key for AES-256-GCM-SIV encryption.</param>
		/// <returns>An AES-256-GCM-SIV instance.</returns>
		/// <exception cref="ArgumentNullException">
		/// Thrown if the <paramref name="key"/> is null.
		/// </exception>
		/// <exception cref="PlatformNotSupportedException">
		/// Thrown if the CPU doesn't implement AES and CLMUL instruction sets.
		/// </exception>
		/// <exception cref="CryptographicException">
		/// Thrown if the <paramref name="key"/> is not 32 bytes in length.
		/// </exception>
		public AesGcmSiv(byte[] key) : this((ReadOnlySpan<byte>)(key ?? throw new ArgumentNullException()))
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="AesGcmSiv"/> class.
		/// </summary>
		/// <param name="key">The secret key for AES-256-GCM-SIV encryption.</param>
		/// <returns>An AES-256-GCM-SIV instance.</returns>
		/// <exception cref="PlatformNotSupportedException">
		/// Thrown if the CPU doesn't support AES and CLMUL instruction sets.
		/// </exception>
		/// <exception cref="CryptographicException">
		/// Thrown if the <paramref name="key"/> is not 32 bytes in length.
		/// </exception>
		public AesGcmSiv(ReadOnlySpan<byte> key)
		{
			if (!IsSupported)
			{
				throw new PlatformNotSupportedException();
			}

			if (key.Length != KeySizeInBytes)
			{
				throw new CryptographicException("Specified key is not a valid size for this algorithm.");
			}

			ptr = Marshal.AllocHGlobal(RoundKeysSizeInBytes + Align16Overhead);
			ks = Align16((byte*)ptr.ToPointer());

			fixed (byte* keyPtr = key)
			{
				KeySchedule(keyPtr, ks);
			}
		}

		/// <summary>
		/// Returns true if the CPU supports AES and CLMUL instruction sets, false otherwise.
		/// </summary>
		public static bool IsSupported => Aes.IsSupported && Pclmulqdq.IsSupported;

		/// <summary>
		/// Encrypt encrypts and authenticates the plaintext,
		/// and authenticates the optional associated data.
		/// </summary>
		/// <param name="nonce">The 12-byte nonce. It is recommended to use randomnly chosen nonces.</param>
		/// <param name="plaintext">The plaintext to encrypt.</param>
		/// <param name="ciphertext">The buffer for the ciphertext. It must be the same length as the plaintext.</param>
		/// <param name="tag">The 16-byte buffer for the authentication tag.</param>
		/// <param name="associatedData">Associated data to authenticate. Can be null.</param>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="nonce"/>, <paramref name="plaintext"/>,
		/// <paramref name="ciphertext"/>, or <paramref name="tag"/> is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if any of the following conditions is satisfied:
		/// <para>- <paramref name="plaintext"/> and <paramref name="ciphertext"/> are not the same length.</para>
		/// <para>- <paramref name="nonce"/> is not 12 bytes in length.</para>
		/// <para>- <paramref name="tag"/> is not 16 bytes in length.</para>
		/// </exception>
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

			CheckParameters(plaintext, ciphertext, nonce, tag);

			if (associatedData is null)
			{
				associatedData = Empty;
			}

			fixed (byte* noncePtr = nonce)
			fixed (byte* pt = plaintext)
			fixed (byte* ct = ciphertext)
			fixed (byte* tagPtr = tag)
			fixed (byte* ad = associatedData)
			{
				Encrypt(noncePtr, pt, plaintext.Length, ct, tagPtr, ad, associatedData.Length);
			}
		}

		/// <summary>
		/// Encrypt encrypts and authenticates the plaintext,
		/// and authenticates the optional associated data.
		/// </summary>
		/// <param name="nonce">The 12-byte nonce. It is recommended to use randomnly chosen nonces.</param>
		/// <param name="plaintext">The plaintext to encrypt.</param>
		/// <param name="ciphertext">The buffer for the ciphertext. It must be the same length as the plaintext.</param>
		/// <param name="tag">The 16-byte buffer for the authentication tag.</param>
		/// <param name="associatedData">Associated data to authenticate. Can be null.</param>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if any of the following conditions is satisfied:
		/// <para>- <paramref name="plaintext"/> and <paramref name="ciphertext"/> are not the same length.</para>
		/// <para>- <paramref name="nonce"/> is not 12 bytes in length.</para>
		/// <para>- <paramref name="tag"/> is not 16 bytes in length.</para>
		/// </exception>
		public void Encrypt(
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> plaintext,
			Span<byte> ciphertext,
			Span<byte> tag,
			ReadOnlySpan<byte> associatedData)
		{
			ThrowIfDisposed();
			CheckParameters(plaintext, ciphertext, nonce, tag);

			fixed (byte* noncePtr = nonce)
			fixed (byte* pt = plaintext)
			fixed (byte* ct = ciphertext)
			fixed (byte* tagPtr = tag)
			fixed (byte* ad = associatedData)
			{
				Encrypt(noncePtr, pt, plaintext.Length, ct, tagPtr, ad, associatedData.Length);
			}
		}

		private void Encrypt(byte* nonce, byte* pt, int ptLen, byte* ct, byte* tag, byte* ad, int adLen)
		{
			byte* hashKey = stackalloc byte[16];
			byte* encKey = stackalloc byte[32];

			byte* encRoundKeys = stackalloc byte[RoundKeysSizeInBytes + Align16Overhead];
			encRoundKeys = Align16(encRoundKeys);

			int* n = (int*)nonce;
			byte* polyval = stackalloc byte[16];
			long* lengthBlock = stackalloc long[2] { (long)adLen * 8, (long)ptLen * 8 };

			var xorMask = Sse.StaticCast<int, byte>(Sse2.SetVector128(0, n[2], n[1], n[0]));
			var andMask = Sse.StaticCast<ulong, byte>(Sse2.SetVector128(0x7fffffffffffffff, 0xffffffffffffffff));

			DeriveKeys(nonce, ks, hashKey, encKey);

			if (ptLen + adLen <= threshold)
			{
				PolyvalHorner(polyval, hashKey, ad, adLen);
				PolyvalHorner(polyval, hashKey, pt, ptLen);
				PolyvalHorner(polyval, hashKey, (byte*)lengthBlock, 16);

				var t = Sse2.LoadVector128(polyval);
				Sse2.Store(polyval, Sse2.And(Sse2.Xor(t, xorMask), andMask));

				EncryptTag(polyval, tag, encKey, encRoundKeys);
				Encrypt4(pt, ptLen, ct, tag, encRoundKeys);
			}
			else
			{
				byte* powersTable = stackalloc byte[8 * 16];
				InitPowersTable(powersTable, 8, hashKey);

				PolyvalPowersTable(polyval, powersTable, ad, adLen);
				PolyvalPowersTable(polyval, powersTable, pt, ptLen);
				PolyvalPowersTable(polyval, powersTable, (byte*)lengthBlock, 16);

				var t = Sse2.LoadVector128(polyval);
				Sse2.Store(polyval, Sse2.And(Sse2.Xor(t, xorMask), andMask));

				EncryptTag(polyval, tag, encKey, encRoundKeys);
				Encrypt8(pt, ptLen, ct, tag, encRoundKeys);
			}
		}

		/// <summary>
		/// Decrypt decrypts the ciphertext, and authenticates the
		/// decrypted plaintext and the optional associated data.
		/// </summary>
		/// <param name="nonce">The 12-byte nonce that was previously used for encryption.</param>
		/// <param name="ciphertext">The ciphertext to decrypt.</param>
		/// <param name="tag">The 16-byte authentication tag.</param>
		/// <param name="plaintext">The buffer for the plaintext. It must be the same length as the ciphertext.</param>
		/// <param name="associatedData">Associated data to authenticate. Can be null.</param>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		/// <exception cref="ArgumentNullException">
		/// Thrown if either <paramref name="nonce"/>, <paramref name="plaintext"/>,
		/// <paramref name="ciphertext"/>, or <paramref name="tag"/> is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if any of the following conditions is satisfied:
		/// <para>- <paramref name="plaintext"/> and <paramref name="ciphertext"/> are not the same length.</para>
		/// <para>- <paramref name="nonce"/> is not 12 bytes in length.</para>
		/// <para>- <paramref name="tag"/> is not 16 bytes in length.</para>
		/// </exception>
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

			CheckParameters(plaintext, ciphertext, nonce, tag);

			if (associatedData is null)
			{
				associatedData = Empty;
			}

			fixed (byte* noncePtr = nonce)
			fixed (byte* ct = ciphertext)
			fixed (byte* tagPtr = tag)
			fixed (byte* pt = plaintext)
			fixed (byte* ad = associatedData)
			{
				Decrypt(noncePtr, ks, ct, ciphertext.Length, tagPtr, pt, ad, associatedData.Length);
			}
		}

		/// <summary>
		/// Decrypt decrypts the ciphertext, and authenticates the
		/// decrypted plaintext and the optional associated data.
		/// </summary>
		/// <param name="nonce">The 12-byte nonce that was previously used for encryption.</param>
		/// <param name="ciphertext">The ciphertext to decrypt.</param>
		/// <param name="tag">The 16-byte authentication tag.</param>
		/// <param name="plaintext">The buffer for the plaintext. It must be the same length as the ciphertext.</param>
		/// <param name="associatedData">Associated data to authenticate. Can be null.</param>
		/// <exception cref="ObjectDisposedException">
		/// Thrown if the current instance has already been disposed.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// Thrown if any of the following conditions is satisfied:
		/// <para>- <paramref name="plaintext"/> and <paramref name="ciphertext"/> are not the same length.</para>
		/// <para>- <paramref name="nonce"/> is not 12 bytes in length.</para>
		/// <para>- <paramref name="tag"/> is not 16 bytes in length.</para>
		/// </exception>
		public void Decrypt(
			ReadOnlySpan<byte> nonce,
			ReadOnlySpan<byte> ciphertext,
			ReadOnlySpan<byte> tag,
			Span<byte> plaintext,
			ReadOnlySpan<byte> associatedData)
		{
			ThrowIfDisposed();
			CheckParameters(plaintext, ciphertext, nonce, tag);

			fixed (byte* noncePtr = nonce)
			fixed (byte* ct = ciphertext)
			fixed (byte* tagPtr = tag)
			fixed (byte* pt = plaintext)
			fixed (byte* ad = associatedData)
			{
				Decrypt(noncePtr, ks, ct, ciphertext.Length, tagPtr, pt, ad, associatedData.Length);
			}
		}

		private void Decrypt(byte* nonce, byte* ks, byte* ct, int ctLen, byte* tag, byte* pt, byte* ad, int adLen)
		{
			byte* hashKey = stackalloc byte[16];
			byte* encKey = stackalloc byte[32];
			byte* decTag = stackalloc byte[16];

			byte* encRoundKeys = stackalloc byte[RoundKeysSizeInBytes + Align16Overhead];
			encRoundKeys = Align16(encRoundKeys);

			int* n = (int*)nonce;
			byte* polyval = stackalloc byte[16];
			long* lengthBlock = stackalloc long[2] { (long)adLen * 8, (long)ctLen * 8 };

			var xorMask = Sse.StaticCast<int, byte>(Sse2.SetVector128(0, n[2], n[1], n[0]));
			var andMask = Sse.StaticCast<ulong, byte>(Sse2.SetVector128(0x7fffffffffffffff, 0xffffffffffffffff));

			DeriveKeys(nonce, ks, hashKey, encKey);
			KeySchedule(encKey, encRoundKeys);

			if (ctLen + adLen <= threshold)
			{
				Encrypt4(ct, ctLen, pt, tag, encRoundKeys);

				PolyvalHorner(polyval, hashKey, ad, adLen);
				PolyvalHorner(polyval, hashKey, pt, ctLen);
				PolyvalHorner(polyval, hashKey, (byte*)lengthBlock, 16);
			}
			else
			{
				byte* powersTable = stackalloc byte[6 * 16];
				InitPowersTable(powersTable, 6, hashKey);

				PolyvalHorner(polyval, hashKey, ad, adLen);
				DecryptPowersTable(ct, ctLen, pt, polyval, powersTable, tag, encRoundKeys);
				PolyvalHorner(polyval, hashKey, (byte*)lengthBlock, 16);
			}

			var t = Sse2.LoadVector128(polyval);
			Sse2.Store(polyval, Sse2.And(Sse2.Xor(t, xorMask), andMask));

			EncryptBlock(polyval, decTag, encRoundKeys);

			if (!ConstantTimeEquals16(tag, decTag))
			{
				CryptographicOperations.ZeroMemory(new Span<byte>(pt, ctLen));
				throw new CryptographicException("The computed authentication tag did not match the input authentication tag.");
			}
		}

		// KeySchedule performs a key expansion of the AES-256
		// key in key, and writes the expanded key to ks.
		private static void KeySchedule(byte* key, byte* ks)
		{
			Vector128<byte> xmm1, xmm2, xmm3, xmm4, xmm14;

			var mask = Sse.StaticCast<int, byte>(Sse2.SetVector128(0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d));
			var con1 = Sse.StaticCast<int, byte>(Sse2.SetVector128(1, 1, 1, 1));
			var con3 = Sse.StaticCast<sbyte, byte>(Sse2.SetVector128(7, 6, 5, 4, 7, 6, 5, 4, -1, -1, -1, -1, -1, -1, -1, -1));

			xmm4 = Sse2.SetZeroVector128<byte>();
			xmm14 = Sse2.SetZeroVector128<byte>();
			xmm1 = Sse2.LoadVector128(&key[0]);
			xmm3 = Sse2.LoadVector128(&key[16]);
			Sse2.Store(&ks[0], xmm1);
			Sse2.Store(&ks[16], xmm3);

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
				Sse2.Store(&ks[(i + 1) * 2 * 16], xmm1);

				xmm2 = Sse.StaticCast<uint, byte>(Sse2.Shuffle(Sse.StaticCast<byte, uint>(xmm1), 0xff));
				xmm2 = Aes.EncryptLast(xmm2, xmm14);
				xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm3), 32));
				xmm3 = Sse2.Xor(xmm4, xmm3);
				xmm4 = Ssse3.Shuffle(xmm3, con3);
				xmm3 = Sse2.Xor(xmm4, xmm3);
				xmm3 = Sse2.Xor(xmm2, xmm3);
				Sse2.Store(&ks[((i + 1) * 2 + 1) * 16], xmm3);
			}

			xmm2 = Ssse3.Shuffle(xmm3, mask);
			xmm2 = Aes.EncryptLast(xmm2, con1);
			xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm1), 32));
			xmm1 = Sse2.Xor(xmm1, xmm4);
			xmm4 = Ssse3.Shuffle(xmm1, con3);
			xmm1 = Sse2.Xor(xmm1, xmm4);
			xmm1 = Sse2.Xor(xmm1, xmm2);
			Sse2.Store(&ks[14 * 16], xmm1);
		}

		// DeriveKeys performs the AES-GCM-SIV KDF given the expanded key from ks and
		// the nonce in nonce. The resulting keys are placed in hashKey and encKey.
		private static void DeriveKeys(byte* nonce, byte* ks, byte* hashKey, byte* encKey)
		{
			var n = (int*)nonce;
			var one = Sse2.SetVector128(0, 0, 0, 1);

			var b1 = Sse.StaticCast<int, byte>(Sse2.SetVector128(n[2], n[1], n[0], 0));
			var b2 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b1), one));
			var b3 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b2), one));
			var b4 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b3), one));
			var b5 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b4), one));
			var b6 = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(b5), one));

			var xmm1 = Sse2.LoadVector128(&ks[0]);
			var xmm3 = Sse2.LoadVector128(&ks[16]);

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
				xmm1 = Sse2.LoadVector128(&ks[2 * 16 * i]);
				xmm3 = Sse2.LoadVector128(&ks[2 * 16 * i + 16]);

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

			xmm1 = Sse2.LoadVector128(&ks[14 * 16]);

			b1 = Aes.EncryptLast(b1, xmm1);
			b2 = Aes.EncryptLast(b2, xmm1);
			b3 = Aes.EncryptLast(b3, xmm1);
			b4 = Aes.EncryptLast(b4, xmm1);
			b5 = Aes.EncryptLast(b5, xmm1);
			b6 = Aes.EncryptLast(b6, xmm1);

			Sse2.StoreLow((long*)hashKey + 0, Sse.StaticCast<byte, long>(b1));
			Sse2.StoreLow((long*)hashKey + 1, Sse.StaticCast<byte, long>(b2));

			Sse2.StoreLow((long*)encKey + 0, Sse.StaticCast<byte, long>(b3));
			Sse2.StoreLow((long*)encKey + 1, Sse.StaticCast<byte, long>(b4));
			Sse2.StoreLow((long*)encKey + 2, Sse.StaticCast<byte, long>(b5));
			Sse2.StoreLow((long*)encKey + 3, Sse.StaticCast<byte, long>(b6));
		}

		// InitPowersTable writes powers 1..size of hashKey to htbl.
		private static void InitPowersTable(byte* htbl, int size, byte* hashKey)
		{
			Vector128<ulong> tmp1, tmp2, tmp3, tmp4;

			var poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));
			var t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(hashKey));
			var h = t;

			Sse2.Store(htbl, Sse.StaticCast<ulong, byte>(t));

			for (int i = 1; i < size; ++i)
			{
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
				Sse2.Store(&htbl[i * 16], Sse.StaticCast<ulong, byte>(t));
			}
		}

		// EncryptTag performs a key expansion of the AES-256 key in key, writes
		// the expanded key to ks, and encrypts a single block from pt to ct.
		private static void EncryptTag(byte* pt, byte* ct, byte* key, byte* ks)
		{
			Vector128<byte> xmm1, xmm2, xmm3, xmm4, xmm14, b1;

			var mask = Sse.StaticCast<int, byte>(Sse2.SetVector128(0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d, 0x0c0f0e0d));
			var con1 = Sse.StaticCast<int, byte>(Sse2.SetVector128(1, 1, 1, 1));
			var con3 = Sse.StaticCast<sbyte, byte>(Sse2.SetVector128(7, 6, 5, 4, 7, 6, 5, 4, -1, -1, -1, -1, -1, -1, -1, -1));

			xmm4 = Sse2.SetZeroVector128<byte>();
			xmm14 = Sse2.SetZeroVector128<byte>();
			xmm1 = Sse2.LoadVector128(&key[0]);
			xmm3 = Sse2.LoadVector128(&key[16]);
			Sse2.Store(&ks[0], xmm1);
			b1 = Sse2.LoadVector128(&pt[0]);
			b1 = Sse2.Xor(b1, xmm1);
			b1 = Aes.Encrypt(b1, xmm3);
			Sse2.Store(&ks[16], xmm3);

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
				Sse2.Store(&ks[(i + 1) * 2 * 16], xmm1);
				b1 = Aes.Encrypt(b1, xmm1);

				xmm2 = Sse.StaticCast<uint, byte>(Sse2.Shuffle(Sse.StaticCast<byte, uint>(xmm1), 0xff));
				xmm2 = Aes.EncryptLast(xmm2, xmm14);
				xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm3), 32));
				xmm3 = Sse2.Xor(xmm4, xmm3);
				xmm4 = Ssse3.Shuffle(xmm3, con3);
				xmm3 = Sse2.Xor(xmm4, xmm3);
				xmm3 = Sse2.Xor(xmm2, xmm3);
				Sse2.Store(&ks[((i + 1) * 2 + 1) * 16], xmm3);
				b1 = Aes.Encrypt(b1, xmm3);
			}

			xmm2 = Ssse3.Shuffle(xmm3, mask);
			xmm2 = Aes.EncryptLast(xmm2, con1);
			xmm4 = Sse.StaticCast<ulong, byte>(Sse2.ShiftLeftLogical(Sse.StaticCast<byte, ulong>(xmm1), 32));
			xmm1 = Sse2.Xor(xmm1, xmm4);
			xmm4 = Ssse3.Shuffle(xmm1, con3);
			xmm1 = Sse2.Xor(xmm1, xmm4);
			xmm1 = Sse2.Xor(xmm1, xmm2);
			Sse2.Store(&ks[14 * 16], xmm1);
			b1 = Aes.EncryptLast(b1, xmm1);
			Sse2.Store(ct, b1);
		}

		// EncryptBlock encrypts a single block from pt to ct using the expanded key in ks.
		private static void EncryptBlock(byte* pt, byte* ct, byte* ks)
		{
			var block = Sse2.LoadVector128(pt);
			block = Sse2.Xor(block, Sse2.LoadVector128(ks));

			for (int i = 1; i < 14; ++i)
			{
				block = Aes.Encrypt(block, Sse2.LoadVector128(&ks[i * 16]));
			}

			block = Aes.EncryptLast(block, Sse2.LoadVector128(&ks[14 * 16]));
			Sse2.Store(ct, block);
		}

		/// <summary>
		/// Disposes this object.
		/// </summary>
		public void Dispose()
		{
			if (!disposed)
			{
				var key = new Span<byte>(ks, RoundKeysSizeInBytes);

				CryptographicOperations.ZeroMemory(key);
				Marshal.FreeHGlobal(ptr);

				disposed = true;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static byte* Align16(byte* ptr)
		{
			return (byte*)(((ulong)ptr + Align16Overhead) & Align16Mask);
		}

		[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
		private static bool ConstantTimeEquals16(byte* x, byte* y)
		{
			int acc = 0;

			acc |= x[0] ^ y[0];
			acc |= x[1] ^ y[1];
			acc |= x[2] ^ y[2];
			acc |= x[3] ^ y[3];
			acc |= x[4] ^ y[4];
			acc |= x[5] ^ y[5];
			acc |= x[6] ^ y[6];
			acc |= x[7] ^ y[7];
			acc |= x[8] ^ y[8];
			acc |= x[9] ^ y[9];
			acc |= x[10] ^ y[10];
			acc |= x[11] ^ y[11];
			acc |= x[12] ^ y[12];
			acc |= x[13] ^ y[13];
			acc |= x[14] ^ y[14];
			acc |= x[15] ^ y[15];

			return acc == 0;
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
	}
}
