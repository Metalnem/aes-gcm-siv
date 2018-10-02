using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace Cryptography
{
	public unsafe sealed class AesGcmSiv
	{
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
	}
}
