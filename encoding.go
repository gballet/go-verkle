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
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/protolambda/go-kzg/bls"
)

const ErrInvalidNodeEncoding = "invalid node encoding"

func ParseNode(serialized []byte, depth, width int) (VerkleNode, error) {
	elems, _, err := rlp.SplitList(serialized)
	if err != nil {
		return nil, err
	}
	c, err := rlp.CountValues(elems)
	if err != nil {
		return nil, err
	}

	if c != 3 {
		// hashed node decoding not supported
		return nil, errors.New(ErrInvalidNodeEncoding)
	}

	// either leaf or internal
	kind, typ, rest, err := rlp.Split(elems)
	if err != nil {
		return nil, err
	}
	if kind != rlp.Byte || len(typ) != 1 {
		return nil, errors.New(ErrInvalidNodeEncoding)
	}

	switch typ[0] {
	case leafRLPType:
		key, rest, err := rlp.SplitString(rest)
		if err != nil {
			return nil, err
		}
		var values [][]byte
		if err := rlp.DecodeBytes(rest, &values); err != nil {
			return nil, err
		}
		tc := GetTreeConfig(width)
		if tc.nodeWidth != len(values) {
			return nil, fmt.Errorf("invalid number of nodes in decoded child expected %d, got %d", tc.nodeWidth, len(values))
		}
		ln := &LeafNode{
			key:        key,
			values:     values,
			treeConfig: tc,
		}
		return ln, nil
	case internalRLPType:
		bitlist, rest, err := rlp.SplitString(rest)
		if err != nil {
			return nil, err
		}
		children, _, err := rlp.SplitString(rest)
		if err != nil {
			return nil, err
		}
		return createInternalNode(bitlist, children, depth, width)
	default:
		return nil, errors.New(ErrInvalidNodeEncoding)
	}
}

func createInternalNode(bitlist []byte, raw []byte, depth, width int) (*InternalNode, error) {
	// GetTreeConfig caches computation result, hence
	// this op has low overhead
	tc := GetTreeConfig(width)
	n := (newInternalNode(depth, tc)).(*InternalNode)
	indices := indicesFromBitlist(bitlist)
	if len(raw)/32 != len(indices) {
		return nil, errors.New(ErrInvalidNodeEncoding)
	}
	for i, index := range indices {
		hashed := &HashedNode{hash: new(bls.Fr)}
		bls.FrFrom32(hashed.hash, common.BytesToHash(raw[i*32:(i+1)*32]))
		n.children[index] = hashed
		n.count++
	}
	return n, nil
}

func indicesFromBitlist(bitlist []byte) []int {
	indices := make([]int, 0)
	for i, b := range bitlist {
		if b == 0 {
			continue
		}
		// the bitmap is little-endian, inside a big-endian byte list
		for j := 0; j < 8; j++ {
			mask := byte(1 << j)
			if b&mask == mask {
				index := i*8 + j
				indices = append(indices, index)
			}
		}
	}
	return indices
}
