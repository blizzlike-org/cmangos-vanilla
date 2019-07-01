/*
 * This file is part of the CMaNGOS Project. See AUTHORS file for Copyright information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "Common.h"
#include "Auth/HMACSHA1.h"
#include "Auth/base32.h"
#include "SRP6.h"

SRP6::SRP6()
{
    N.SetHexStr("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7");
    g.SetDword(7);
    v_hex = NULL;
    s_hex = NULL;
}

SRP6::~SRP6()
{
    if (v_hex != NULL)
        OPENSSL_free((void*)v_hex);
    if (s_hex != NULL)
        OPENSSL_free((void*)s_hex);
}

void SRP6::CalculateBField(void)
{
    b.SetRand(19 * 8);
    BigNumber gmod = g.ModExp(b, N);
    B = ((v * 3) + gmod) % N;

    MANGOS_ASSERT(gmod.GetNumBytes() <= 32);
}

/// Make the SRP6 calculation
void SRP6::CalculatevsFields(const std::string& rI)
{
    BigNumber salt;
    salt.SetRand(s_BYTE_SIZE * 8);
    const char* _salt = salt.AsHexStr();
    CalculatevsFields(rI, _salt);
    OPENSSL_free((void*)_salt);
}

void SRP6::CalculatevsFields(const std::string& rI, const char* salt)
{
    s.SetHexStr(salt);

    BigNumber I;
    I.SetHexStr(rI.c_str());

    // In case of leading zeros in the rI hash, restore them
    uint8 mDigest[SHA_DIGEST_LENGTH];
    memset(mDigest, 0, SHA_DIGEST_LENGTH);
    if (I.GetNumBytes() <= SHA_DIGEST_LENGTH)
        memcpy(mDigest, I.AsByteArray(), I.GetNumBytes());

    std::reverse(mDigest, mDigest + SHA_DIGEST_LENGTH);

    Sha1Hash sha;
    sha.UpdateData(s.AsByteArray(), s.GetNumBytes());
    sha.UpdateData(mDigest, SHA_DIGEST_LENGTH);
    sha.Finalize();
    BigNumber x;
    x.SetBinary(sha.GetDigest(), Sha1Hash::GetLength());
    v = g.ModExp(x, N);
    v_hex = v.AsHexStr();
    s_hex = s.AsHexStr();
}

bool SRP6::CalculateSField(uint8* lp_A, int l)
{
    A.SetBinary(lp_A, l);

    // SRP safeguard: abort if A==0
    if (A.isZero())
        return false;

    if ((A % N).isZero())
        return false;

    Sha1Hash sha;
    sha.UpdateBigNumbers(&A, &B, nullptr);
    sha.Finalize();
    u.SetBinary(sha.GetDigest(), 20);
    S = (A * (v.ModExp(u, N))).ModExp(b, N);

    return true;
}

void SRP6::CalculateKField(void)
{
    uint8 t[32];
    uint8 t1[16];
    uint8 vK[40];
    memcpy(t, S.AsByteArray(32), 32);
    for (int i = 0; i < 16; ++i)
    {
        t1[i] = t[i * 2];
    }
    Sha1Hash sha;
    sha.Initialize();
    sha.UpdateData(t1, 16);
    sha.Finalize();
    for (int i = 0; i < 20; ++i)
    {
        vK[i * 2] = sha.GetDigest()[i];
    }
    for (int i = 0; i < 16; ++i)
    {
        t1[i] = t[i * 2 + 1];
    }
    sha.Initialize();
    sha.UpdateData(t1, 16);
    sha.Finalize();
    for (int i = 0; i < 20; ++i)
    {
        vK[i * 2 + 1] = sha.GetDigest()[i];
    }
    K.SetBinary(vK, 40);
}

void SRP6::CalculateMField(std::string username)
{
    uint8 hash[20];

    Sha1Hash sha;
    sha.Initialize();
    sha.UpdateBigNumbers(&N, nullptr);
    sha.Finalize();
    memcpy(hash, sha.GetDigest(), 20);
    sha.Initialize();
    sha.UpdateBigNumbers(&g, nullptr);
    sha.Finalize();
    for (int i = 0; i < 20; ++i)
    {
        hash[i] ^= sha.GetDigest()[i];
    }
    BigNumber t3;
    t3.SetBinary(hash, 20);

    sha.Initialize();
    sha.UpdateData(username);
    sha.Finalize();
    uint8 t4[SHA_DIGEST_LENGTH];
    memcpy(t4, sha.GetDigest(), SHA_DIGEST_LENGTH);

    sha.Initialize();
    sha.UpdateBigNumbers(&t3, nullptr);
    sha.UpdateData(t4, SHA_DIGEST_LENGTH);
    sha.UpdateBigNumbers(&s, &A, &B, &K, nullptr);
    sha.Finalize();
    M.SetBinary(sha.GetDigest(), 20);
}

bool SRP6::CompareM(uint8* lp_M, int l)
{
    if (!memcmp(M.AsByteArray(), lp_M, l))
        return false;

    return true;
}

bool SRP6::Comparev(std::string vC)
{
    const char* vC_hex = vC.c_str();

    if (memcmp(vC_hex, v_hex, strlen(vC_hex)) == 0)
        return true;

    return false;
}

void SRP6::FinishSRP(Sha1Hash& sha)
{
    sha.Initialize();
    sha.UpdateBigNumbers(&A, &M, &K, nullptr);
    sha.Finalize();
}
