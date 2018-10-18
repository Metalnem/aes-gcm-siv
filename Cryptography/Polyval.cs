using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Cryptography
{
	public unsafe partial class AesGcmSiv
	{
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

		private static void PolyvalPowersTable(byte* polyval, byte* powersTable, byte* input, int length)
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
				var fixedInput = input + remainder128;

				if (remainder128 == 0)
				{
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[7 * 16]));
					tmp2 = Pclmulqdq.CarrylessMultiply(data, h0, 0x01);
					tmp0 = Pclmulqdq.CarrylessMultiply(data, h0, 0x00);
					tmp1 = Pclmulqdq.CarrylessMultiply(data, h0, 0x11);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h0, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[6 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[5 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h2, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[4 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[3 * 16]));
					tmp4 = Pclmulqdq.CarrylessMultiply(t, poly, 0x10);

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h4, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[2 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[1 * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(fixedInput));
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
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 7) * 16]));
					tmp2 = Pclmulqdq.CarrylessMultiply(data, h0, 0x01);
					tmp0 = Pclmulqdq.CarrylessMultiply(data, h0, 0x00);
					tmp1 = Pclmulqdq.CarrylessMultiply(data, h0, 0x11);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h0, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 6) * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h1, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 5) * 16]));
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
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 4) * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h3, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 3) * 16]));
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
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 2) * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h5, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					t = Sse2.Xor(t, xhi);
					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[(i + 1) * 16]));

					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x01);
					tmp2 = Sse2.Xor(tmp2, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x00);
					tmp0 = Sse2.Xor(tmp0, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x11);
					tmp1 = Sse2.Xor(tmp1, tmp3);
					tmp3 = Pclmulqdq.CarrylessMultiply(data, h6, 0x10);
					tmp2 = Sse2.Xor(tmp2, tmp3);

					data = Sse.StaticCast<byte, ulong>(Sse2.LoadVector128(&fixedInput[i * 16]));
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
	}
}
