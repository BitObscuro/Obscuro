// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK
#define BITCOIN_BLOCK

#include "block.h"
#include <stdio.h>

const int64_t nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
const int64_t nPowTargetSpacing = 10 * 60;
const bool fPowNoRetargeting = true;
const bool fPowAllowMinDifficultyBlocks = true;
const uint256 powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
const int64_t DifficultyAdjustmentInterval = nPowTargetTimespan / nPowTargetSpacing;

const int32_t genesis_nVersion = 1;
const char* genesis_hashMerkleRoot = "0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
const char* genesis_hashPrevBlock = "0000000000000000000000000000000000000000000000000000000000000000";
const uint32_t genesis_nTime = 1296688602;
const uint32_t genesis_nBits = 0x207fffff;
const uint32_t genesis_nNonce = 2;

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CCBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    if (height > nHeight || height < 0)
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != NULL &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    unsigned int nProofOfWorkLimit = UintToArith256(powLimit).GetCompact();
    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;
    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % DifficultyAdjustmentInterval != 0) //ignore
    {
        // if (fPowAllowMinDifficultyBlocks)// ignore while using regtest mode
        // {
        //     // Special difficulty rule for testnet:
        //     // If the new block's timestamp is more than 2* 10 minutes
        //     // then allow mining of a min-difficulty block.
        //     if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + nPowTargetSpacing*2)
        //         return nProofOfWorkLimit;
        //     else
        //     {
        //         // Return the last non-special-min-difficulty-rules-block
        //         const CBlockIndex* pindex = pindexLast;
        //         while (pindex->pprev && pindex->nHeight % DifficultyAdjustmentInterval != 0 && pindex->nBits == nProofOfWorkLimit)
        //             pindex = pindex->pprev;
        //         return pindex->nBits;
        //     }
        //     const CBlockIndex* pindex = pindexLast;
        //     while (pindex->pprev && pindex->nHeight % DifficultyAdjustmentInterval != 0 && pindex->nBits == nProofOfWorkLimit)
        //         pindex = pindex->pprev;
        //     return pindex->nBits;
        // }
        return pindexLast->nBits;
    }
     
    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (DifficultyAdjustmentInterval-1);
    //assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    //assert(pindexFirst);
    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime());
    
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime)
{   
    if (fPowNoRetargeting)
        return pindexLast->nBits;
    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < nPowTargetTimespan/4)
        nActualTimespan = nPowTargetTimespan/4;
    if (nActualTimespan > nPowTargetTimespan*4)
        nActualTimespan = nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

CBlockHeader GetGenesisBlock(){
	CBlockHeader genesis;
    genesis.SetNull();
	genesis.nVersion = genesis_nVersion;
	genesis.hashPrevBlock = uint256S(genesis_hashPrevBlock);
	genesis.hashMerkleRoot = uint256S(genesis_hashMerkleRoot);
	genesis.nTime = genesis_nTime;
	genesis.nBits = genesis_nBits;
	genesis.nNonce = genesis_nNonce;
	return genesis;
}

#endif