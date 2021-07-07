// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <https://unlicense.org>

package verkle

import (
	"crypto/sha256"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

func calcR(cs []*bls.G1Point, indices []*bls.Fr, ys []*bls.Fr, modulus *big.Int) bls.Fr {
	digest := sha256.New()
	for _, c := range cs {
		h := sha256.Sum256(bls.ToCompressedG1(c))
		digest.Write(h[:])
	}
	for _, idx := range indices {
		tmp := bls.FrTo32(idx)
		digest.Write(tmp[:])
	}
	for _, y := range ys {
		tmp := bls.FrTo32(y)
		digest.Write(tmp[:])
	}

	var tmp bls.Fr
	hashToFr(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp

}

func calcT(r *bls.Fr, d *bls.G1Point, modulus *big.Int) bls.Fr {
	digest := sha256.New()

	tmpBytes := bls.FrTo32(r)
	digest.Write(tmpBytes[:])
	tmpBytes = sha256.Sum256(bls.ToCompressedG1(d))
	digest.Write(tmpBytes[:])

	var tmp bls.Fr
	hashToFr(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp
}

func calcQ(e, d *bls.G1Point, y, w *bls.Fr, modulus *big.Int) bls.Fr {
	digest := sha256.New()
	hE := sha256.Sum256(bls.ToCompressedG1(e))
	hD := sha256.Sum256(bls.ToCompressedG1(d))

	digest.Write(hE[:])
	digest.Write(hD[:])
	tmpBytes := bls.FrTo32(y)
	digest.Write(tmpBytes[:])
	tmpBytes = bls.FrTo32(w)
	digest.Write(tmpBytes[:])

	var tmp bls.Fr
	hashToFr(&tmp, common.BytesToHash(digest.Sum(nil)))
	return tmp
}

func ComputeKZGProof(tc *TreeConfig, poly []bls.Fr, z, y *bls.Fr) *bls.G1Point {
	oq := tc.outerQuotients(poly, z, y)
	return kzg.CommitToEvalPoly(tc.lg1, oq)
}

func MakeVerkleProofOneLeaf(root VerkleNode, key []byte) (d *bls.G1Point, y *bls.Fr, sigma *bls.G1Point) {
	var tc *TreeConfig
	if root, ok := root.(*InternalNode); !ok {
		panic("no tree config")
	} else {
		tc = root.treeConfig
	}

	var fis [][]bls.Fr
	commitments, zis, yis, fis := root.GetCommitmentsAlongPath(key)

	// Construct g(x)
	r := calcR(commitments, zis, yis, tc.modulus)

	g := make([]bls.Fr, tc.nodeWidth)
	var powR bls.Fr
	bls.CopyFr(&powR, &bls.ONE)
	for index, f := range fis {
		quotients := tc.innerQuotients(f, index)
		var tmp bls.Fr
		for i := 0; i < tc.nodeWidth; i++ {
			bls.MulModFr(&tmp, &powR, &quotients[i])
			bls.AddModFr(&g[i], &g[i], &tmp)
		}

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	d = bls.LinCombG1(tc.lg1, g[:])

	// Compute h(x)
	t := calcT(&r, d, tc.modulus)

	h := make([]bls.Fr, tc.nodeWidth)
	bls.CopyFr(&powR, &bls.ONE)
	for index, f := range fis {
		var denom bls.Fr
		bls.SubModFr(&denom, &t, &tc.omegaIs[index])
		bls.DivModFr(&denom, &powR, &denom)

		for i := 0; i < tc.nodeWidth; i++ {
			var tmp bls.Fr
			bls.MulModFr(&tmp, &denom, &f[i])
			bls.AddModFr(&h[i], &h[i], &tmp)
		}

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}

	// compute y and w
	y = new(bls.Fr)
	w := new(bls.Fr)
	for i := range g {
		var factor, tmp bls.Fr
		bls.SubModFr(&factor, &t, &tc.omegaIs[i])
		bls.DivModFr(&factor, &tc.omegaIs[i], &factor)

		bls.MulModFr(&tmp, &h[i], &factor)
		bls.AddModFr(y, y, &tmp)
		bls.MulModFr(&tmp, &g[i], &factor)
		bls.AddModFr(w, w, &tmp)
	}
	// Compute t^width - 1
	var tPowWidth bls.Fr
	bls.CopyFr(&tPowWidth, &t)
	for i := 0; i < tc.width; i++ {
		bls.MulModFr(&tPowWidth, &tPowWidth, &tPowWidth)
	}
	bls.SubModFr(&tPowWidth, &tPowWidth, &bls.ONE)
	bls.MulModFr(&tPowWidth, &tPowWidth, &tc.nodeWidthInversed)
	bls.MulModFr(w, w, &tPowWidth)
	bls.MulModFr(y, y, &tPowWidth)

	// compute π and ρ
	pi := ComputeKZGProof(tc, h, &t, y)
	rho := ComputeKZGProof(tc, g, &t, w)

	// Compute E
	e := kzg.CommitToEvalPoly(tc.lg1, h[:])

	// compute σ
	sigma = new(bls.G1Point)
	q := calcQ(e, d, y, w, tc.modulus)
	bls.MulG1(sigma, rho, &q)
	bls.AddG1(sigma, sigma, pi)

	return
}

func VerifyVerkleProof(ks *kzg.KZGSettings, d, sigma *bls.G1Point, y *bls.Fr, commitments []*bls.G1Point, zis, yis []*bls.Fr, tc *TreeConfig) bool {
	r := calcR(commitments, zis, yis, tc.modulus)
	t := calcT(&r, d, tc.modulus)

	// Evaluate w = g₂(t) and E
	g2 := make([]bls.Fr, len(commitments))
	var powR bls.Fr
	var e bls.G1Point
	bls.CopyFr(&powR, &bls.ONE)
	for i := range g2 {
		var tMinusZi, rDivZi bls.Fr
		bls.SubModFr(&tMinusZi, &t, &tc.omegaIs[i])
		bls.DivModFr(&rDivZi, &powR, &tMinusZi)

		// g₂(t)
		bls.MulModFr(&g2[i], &rDivZi, yis[i])

		// E
		var eTmp bls.G1Point
		bls.MulG1(&eTmp, commitments[i], &rDivZi)
		bls.AddG1(&e, &e, &eTmp)

		// rⁱ⁺¹ = r ⨯ rⁱ
		bls.MulModFr(&powR, &powR, &r)
	}
	var g2t bls.Fr
	bls.EvalPolyAt(&g2t, g2, &t)

	// w = y - g₂(t)
	var w bls.Fr
	bls.SubModFr(&w, y, &g2t)

	// Calculate q
	q := calcQ(&e, d, y, &w, tc.modulus)

	// final=E+qD
	var final bls.G1Point
	bls.MulG1(&final, d, &q)
	bls.AddG1(&final, &final, &e)

	// finalAt=y+w*q
	var finalAt bls.Fr
	bls.MulModFr(&finalAt, &q, &w)
	bls.AddModFr(&finalAt, &finalAt, y)

	return ks.CheckProofSingle(&final, sigma, &t, &finalAt)
}
