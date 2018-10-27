using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using Aes = System.Runtime.Intrinsics.X86.Aes;

namespace Cryptography
{
	public unsafe partial class AesGcmSiv
	{
		// Encrypt4 encrypts ptLen bytes from pt to ct using the expanded key from ks.
		// It processes 4 blocks of data in parallel (if the size of the input is not
		// divisible by 64, the remainder blocks are handled separately). The initial
		// counter is constructed from the given tag as required by AES-GCM-SIV.
		private static void Encrypt4(byte* pt, int ptLen, byte* ct, byte* tag, byte* ks)
		{
			if (ptLen == 0)
			{
				return;
			}

			int blocks = Math.DivRem(ptLen, 16, out int remainder16);
			int remainder16Pos = ptLen - remainder16;
			int remainder4 = blocks % 4;
			int remainder4Pos = blocks - remainder4;

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

				var key = Sse2.LoadVector128(ks);
				tmp0 = Sse2.Xor(tmp0, key);
				tmp1 = Sse2.Xor(tmp1, key);
				tmp2 = Sse2.Xor(tmp2, key);
				tmp3 = Sse2.Xor(tmp3, key);

				for (int j = 1; j < 14; ++j)
				{
					key = Sse2.LoadVector128(&ks[j * 16]);
					tmp0 = Aes.Encrypt(tmp0, key);
					tmp1 = Aes.Encrypt(tmp1, key);
					tmp2 = Aes.Encrypt(tmp2, key);
					tmp3 = Aes.Encrypt(tmp3, key);
				}

				key = Sse2.LoadVector128(&ks[14 * 16]);
				tmp0 = Aes.EncryptLast(tmp0, key);
				tmp1 = Aes.EncryptLast(tmp1, key);
				tmp2 = Aes.EncryptLast(tmp2, key);
				tmp3 = Aes.EncryptLast(tmp3, key);

				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(&pt[(i + 0) * 16]));
				tmp1 = Sse2.Xor(tmp1, Sse2.LoadVector128(&pt[(i + 1) * 16]));
				tmp2 = Sse2.Xor(tmp2, Sse2.LoadVector128(&pt[(i + 2) * 16]));
				tmp3 = Sse2.Xor(tmp3, Sse2.LoadVector128(&pt[(i + 3) * 16]));

				Sse2.Store(&ct[(i + 0) * 16], tmp0);
				Sse2.Store(&ct[(i + 1) * 16], tmp1);
				Sse2.Store(&ct[(i + 2) * 16], tmp2);
				Sse2.Store(&ct[(i + 3) * 16], tmp3);
			}

			for (int i = 0; i < remainder4; ++i)
			{
				var tmp = ctr;
				ctr = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), one));
				tmp = Sse2.Xor(tmp, Sse2.LoadVector128(ks));

				for (int j = 1; j < 14; ++j)
				{
					tmp = Aes.Encrypt(tmp, Sse2.LoadVector128(&ks[j * 16]));
				}

				tmp = Aes.EncryptLast(tmp, Sse2.LoadVector128(&ks[14 * 16]));
				tmp = Sse2.Xor(tmp, Sse2.LoadVector128(&pt[(remainder4Pos + i) * 16]));
				Sse2.Store(&ct[(remainder4Pos + i) * 16], tmp);
			}

			if (remainder16 != 0)
			{
				byte* b = stackalloc byte[16];
				new Span<byte>(pt + remainder16Pos, remainder16).CopyTo(new Span<byte>(b, 16));
				var tmp = Sse2.Xor(ctr, Sse2.LoadVector128(ks));

				for (int j = 1; j < 14; ++j)
				{
					tmp = Aes.Encrypt(tmp, Sse2.LoadVector128(&ks[j * 16]));
				}

				tmp = Aes.EncryptLast(tmp, Sse2.LoadVector128(&ks[14 * 16]));
				Sse2.Store(b, Sse2.Xor(tmp, Sse2.LoadVector128(b)));

				new Span<byte>(b, remainder16).CopyTo(new Span<byte>(ct + remainder16Pos, remainder16));
			}
		}

		// Encrypt8 encrypts ptLen bytes from pt to ct using the expanded key from ks.
		// It processes 8 blocks of data in parallel (if the size of the input is not
		// divisible by 128, the remainder blocks are handled separately). The initial
		// counter is constructed from the given tag as required by AES-GCM-SIV.
		private static void Encrypt8(byte* pt, int ptLen, byte* ct, byte* tag, byte* ks)
		{
			if (ptLen == 0)
			{
				return;
			}

			int blocks = Math.DivRem(ptLen, 16, out int remainder16);
			int remainder16Pos = ptLen - remainder16;
			int remainder8 = blocks % 8;
			int remainder8Pos = blocks - remainder8;

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

				var key = Sse2.LoadVector128(ks);
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
					key = Sse2.LoadVector128(&ks[j * 16]);
					tmp0 = Aes.Encrypt(tmp0, key);
					tmp1 = Aes.Encrypt(tmp1, key);
					tmp2 = Aes.Encrypt(tmp2, key);
					tmp3 = Aes.Encrypt(tmp3, key);
					tmp4 = Aes.Encrypt(tmp4, key);
					tmp5 = Aes.Encrypt(tmp5, key);
					tmp6 = Aes.Encrypt(tmp6, key);
					tmp7 = Aes.Encrypt(tmp7, key);
				}

				key = Sse2.LoadVector128(&ks[14 * 16]);
				tmp0 = Aes.EncryptLast(tmp0, key);
				tmp1 = Aes.EncryptLast(tmp1, key);
				tmp2 = Aes.EncryptLast(tmp2, key);
				tmp3 = Aes.EncryptLast(tmp3, key);
				tmp4 = Aes.EncryptLast(tmp4, key);
				tmp5 = Aes.EncryptLast(tmp5, key);
				tmp6 = Aes.EncryptLast(tmp6, key);
				tmp7 = Aes.EncryptLast(tmp7, key);

				tmp0 = Sse2.Xor(tmp0, Sse2.LoadVector128(&pt[(i + 0) * 16]));
				tmp1 = Sse2.Xor(tmp1, Sse2.LoadVector128(&pt[(i + 1) * 16]));
				tmp2 = Sse2.Xor(tmp2, Sse2.LoadVector128(&pt[(i + 2) * 16]));
				tmp3 = Sse2.Xor(tmp3, Sse2.LoadVector128(&pt[(i + 3) * 16]));
				tmp4 = Sse2.Xor(tmp4, Sse2.LoadVector128(&pt[(i + 4) * 16]));
				tmp5 = Sse2.Xor(tmp5, Sse2.LoadVector128(&pt[(i + 5) * 16]));
				tmp6 = Sse2.Xor(tmp6, Sse2.LoadVector128(&pt[(i + 6) * 16]));
				tmp7 = Sse2.Xor(tmp7, Sse2.LoadVector128(&pt[(i + 7) * 16]));

				Sse2.Store(&ct[(i + 0) * 16], tmp0);
				Sse2.Store(&ct[(i + 1) * 16], tmp1);
				Sse2.Store(&ct[(i + 2) * 16], tmp2);
				Sse2.Store(&ct[(i + 3) * 16], tmp3);
				Sse2.Store(&ct[(i + 4) * 16], tmp4);
				Sse2.Store(&ct[(i + 5) * 16], tmp5);
				Sse2.Store(&ct[(i + 6) * 16], tmp6);
				Sse2.Store(&ct[(i + 7) * 16], tmp7);
			}

			for (int i = 0; i < remainder8; ++i)
			{
				var tmp = ctr;
				ctr = Sse.StaticCast<int, byte>(Sse2.Add(Sse.StaticCast<byte, int>(ctr), one));
				tmp = Sse2.Xor(tmp, Sse2.LoadVector128(ks));

				for (int j = 1; j < 14; ++j)
				{
					tmp = Aes.Encrypt(tmp, Sse2.LoadVector128(&ks[j * 16]));
				}

				tmp = Aes.EncryptLast(tmp, Sse2.LoadVector128(&ks[14 * 16]));
				tmp = Sse2.Xor(tmp, Sse2.LoadVector128(&pt[(remainder8Pos + i) * 16]));
				Sse2.Store(&ct[(remainder8Pos + i) * 16], tmp);
			}

			if (remainder16 != 0)
			{
				byte* b = stackalloc byte[16];
				new Span<byte>(pt + remainder16Pos, remainder16).CopyTo(new Span<byte>(b, 16));
				var tmp = Sse2.Xor(ctr, Sse2.LoadVector128(ks));

				for (int j = 1; j < 14; ++j)
				{
					tmp = Aes.Encrypt(tmp, Sse2.LoadVector128(&ks[j * 16]));
				}

				tmp = Aes.EncryptLast(tmp, Sse2.LoadVector128(&ks[14 * 16]));
				Sse2.Store(b, Sse2.Xor(tmp, Sse2.LoadVector128(b)));

				new Span<byte>(b, remainder16).CopyTo(new Span<byte>(ct + remainder16Pos, remainder16));
			}
		}
	}
}
