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

#ifndef _SRP6_H
#define _SRP6_H

#include "Common.h"
#include "Auth/BigNumber.h"
#include "Auth/Sha1.h"
#include "ByteBuffer.h"

#define HMAC_RES_SIZE 20

class SRP6
{
    public:
        const static int s_BYTE_SIZE = 32;

        SRP6(void);
        ~SRP6(void);

        void CalculateBField(void);
        void CalculateKField(void);
        void CalculateMField(std::string username);
        bool CalculateSField(uint8* lp_A, int l);
        void CalculatevsFields(const std::string& rI);

        bool CompareM(uint8* lp_M, int l);

        void FinishSRP(Sha1Hash& sha);

        const char* GetsAsHexStr(void) { return s_hex; };
        const char* GetvAsHexStr(void) { return v_hex; };
        const char* GetKAsHexStr(void) { return K.AsHexStr(); };
        BigNumber GetK(void) { return K; };
        uint8* GetMAsByteArray(void) { return M.AsByteArray(); };
        uint8* GetBAsByteArray(int minSize = 0) { return B.AsByteArray(minSize); };
        uint8* GetgAsByteArray(void) { return g.AsByteArray(); };
        uint8* GetNAsByteArray(int minSize = 0) { return N.AsByteArray(minSize); };

        void SetKAsHexStr(const char* new_K) { K.SetHexStr(new_K); };
        void SetsAsHexStr(const char* new_s) { s.SetHexStr(new_s); };
        void SetvAsHexStr(const char* new_v) { v.SetHexStr(new_v); };

    private:
        BigNumber A, u, S;
        BigNumber N, s, g, v;
        BigNumber b, B;
        BigNumber K;
        BigNumber M;

        const char* v_hex;
        const char* s_hex;
};
#endif
