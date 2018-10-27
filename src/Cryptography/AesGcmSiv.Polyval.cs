using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Cryptography
{
	public unsafe partial class AesGcmSiv
	{
		// PolyvalHorner updates the POLYVAL value in polyval to include length bytes
		// of data from input, given the POLYVAL key in hashKey. If the length is not
		// divisible by 16, input is padded with zeros until it's a multiple of 16 bytes.
		private static void PolyvalHorner(byte* polyval, byte* hashKey, byte* input, int length)
		{
			if (length == 0)
			{
				return;
			}

			int blocks = Math.DivRem(length, 16, out int remainder);
			Vector128<ulong> tmp1, tmp2, tmp3, tmp4;

			var poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));
			var t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(polyval));
			var h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(hashKey));

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

		// PolyvalPowersTable updates the POLYVAL value in polyval to include length bytes
		// of data from input, given the POLYVAL key in hashKey. It uses the precomputed
		// powers of the key given in htbl. If the length is not divisible by 16, input
		// is padded with zeros until it's a multiple of 16 bytes.
		private static void PolyvalPowersTable(byte* polyval, byte* htbl, byte* input, int length)
		{
			if (length == 0)
			{
				return;
			}

			int blocks = Math.DivRem(length, 16, out int remainder16);
			int remainder128 = length % 128 - remainder16;
			Vector128<ulong> tmp0, tmp1, tmp2, tmp3, tmp4;

			var xhi = Sse2.SetZeroVector128<ulong>();
			var poly = Sse.StaticCast<uint, ulong>(Sse2.SetVector128(0xc2000000, 0, 0, 1));
			var t = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(polyval));

			if (remainder128 != 0)
			{
				int remainder128Blocks = remainder128 / 16;
				blocks -= remainder128Blocks;

				var data = Sse2.Xor(t, Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(input)));
				var h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[(remainder128Blocks - 1) * 16]));

				tmp2 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
				tmp0 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
				tmp1 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
				tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
				tmp2 = Sse2.Xor(tmp2, tmp3);

				for (int i = 1; i < remainder128Blocks; ++i)
				{
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&input[i * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[(remainder128Blocks - i - 1) * 16]));

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
				var fixedInput = input + remainder128;

				if (remainder128 == 0)
				{
					var data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[7 * 16]));
					var h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[0 * 16]));

					tmp2 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp0 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp1 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[6 * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[1 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[5 * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[2 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[4 * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[3 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[3 * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[4 * 16]));
					tmp4 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[2 * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[5 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[1 * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[6 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse2.Xor(t, Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[0 * 16])));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[7 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					tmp3 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
					tmp2 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
					xhi = Sse2.Xor(tmp3, tmp1);
					t = Sse2.Xor(tmp0, tmp2);
				}

				for (int i = remainder128 == 0 ? 8 : 0; i < blocks; i += 8)
				{
					var data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 7) * 16]));
					var h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[0 * 16]));

					tmp2 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp0 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp1 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 6) * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[1 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 5) * 16]));
					tmp4 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
					t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(Sse.StaticCast<ulong, sbyte>(t), Sse.StaticCast<ulong, sbyte>(t), 8));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[2 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					t = Sse2.Xor(t, tmp4);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 4) * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[3 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 3) * 16]));
					tmp4 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
					t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(Sse.StaticCast<ulong, sbyte>(t), Sse.StaticCast<ulong, sbyte>(t), 8));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[4 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					t = Sse2.Xor(t, tmp4);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 2) * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[5 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					t = Sse2.Xor(t, xhi);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 1) * 16]));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[6 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse2.Xor(t, Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[i * 16])));
					h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&htbl[7 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
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
				t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(Sse.StaticCast<ulong, sbyte>(t), Sse.StaticCast<ulong, sbyte>(t), 8));
				t = Sse2.Xor(tmp3, t);
				tmp3 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(Sse.StaticCast<ulong, sbyte>(t), Sse.StaticCast<ulong, sbyte>(t), 8));
				t = Sse2.Xor(tmp3, t);
				t = Sse2.Xor(xhi, t);
			}

			if (remainder16 != 0)
			{
				byte* b = stackalloc byte[16];
				new Span<byte>(&input[length - remainder16], remainder16).CopyTo(new Span<byte>(b, 16));

				var data = Sse2.Xor(t, Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(b)));
				var h = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(htbl));

				tmp2 = Pclmulqdq.CarrylessMultiply(data, h, 0x01);
				tmp0 = Pclmulqdq.CarrylessMultiply(data, h, 0x00);
				tmp1 = Pclmulqdq.CarrylessMultiply(data, h, 0x11);
				tmp3 = Pclmulqdq.CarrylessMultiply(data, h, 0x10);
				tmp2 = Sse2.Xor(tmp2, tmp3);
				tmp3 = Sse2.ShiftRightLogical128BitLane(tmp2, 8);
				tmp2 = Sse2.ShiftLeftLogical128BitLane(tmp2, 8);
				xhi = Sse2.Xor(tmp3, tmp1);
				t = Sse2.Xor(tmp0, tmp2);

				tmp3 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(Sse.StaticCast<ulong, sbyte>(t), Sse.StaticCast<ulong, sbyte>(t), 8));
				t = Sse2.Xor(tmp3, t);
				tmp3 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);
				t = Sse.StaticCast<sbyte, ulong>(Ssse3.AlignRight(Sse.StaticCast<ulong, sbyte>(t), Sse.StaticCast<ulong, sbyte>(t), 8));
				t = Sse2.Xor(tmp3, t);
				t = Sse2.Xor(xhi, t);
			}

			Sse2.Store(polyval, Sse.StaticCast<ulong, byte>(t));
		}
	}
}
