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
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/protolambda/go-kzg/bls"
)

// FlushableNode is a tuple of a node and its hash, to be passed
// to a consumer (e.g. the routine responsible for saving it to
// the db) once the node is no longer used by the tree.
type FlushableNode struct {
	Hash [32]byte
	Node VerkleNode
}

type NodeResolverFn func([]byte) ([]byte, error)

type VerkleNode interface {
	// Insert or Update value `v` at key `k`
	Insert(k []byte, v []byte) error

	// Insert "à la" Stacktrie. Same thing as insert, except that
	// values are expected to be ordered, and the commitments and
	// hashes for each subtrie are computed online, as soon as it
	// is clear that no more values will be inserted in there.
	InsertOrdered([]byte, []byte, chan FlushableNode) error

	// Delete a leaf with the given key
	Delete([]byte) error

	// Get value at a given key
	Get([]byte, NodeResolverFn) ([]byte, error)

	// Hash of the current node
	Hash() common.Hash

	// ComputeCommitment computes the commitment of the node
	ComputeCommitment() *bls.G1Point

	// GetCommitment retrieves the (previously computed)
	// commitment of a node.
	GetCommitment() *bls.G1Point

	// GetCommitmentAlongPath follows the path that one key
	// traces through the tree, and collects the various
	// elements needed to build a proof. The order of elements
	// is from the bottom of the tree, up to the root.
	GetCommitmentsAlongPath([]byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr)

	// Serialize encodes the node to RLP.
	Serialize() ([]byte, error)

	// Copy a node and its children
	Copy() VerkleNode
}

const (
	// These types will distinguish internal
	// and leaf nodes when decoding from RLP.
	internalRLPType byte = 1
	leafRLPType     byte = 2
)

var (
	errInsertIntoHash    = errors.New("trying to insert into hashed node")
	errValueNotPresent   = errors.New("value not present in tree")
	errDeleteNonExistent = errors.New("trying to delete non-existent leaf")
	errReadFromInvalid   = errors.New("trying to read from an invalid child")

	zeroHash = common.HexToHash("0000000000000000000000000000000000000000000000000000000000000000")
)

type (
	// Represents an internal node at any level
	InternalNode struct {
		// List of child nodes of this internal node.
		children []VerkleNode

		// node depth in the tree, in bits
		depth int

		// Cache the hash of the current node
		hash common.Hash

		// Cache the commitment value
		commitment *bls.G1Point

		treeConfig *TreeConfig
	}

	HashedNode struct {
		hash       common.Hash
		commitment *bls.G1Point
	}

	LeafNode struct {
		key   []byte
		value []byte
	}

	Empty struct{}
)

func newInternalNode(depth int, tc *TreeConfig) VerkleNode {
	node := new(InternalNode)
	node.children = make([]VerkleNode, tc.nodeWidth)
	for idx := range node.children {
		node.children[idx] = Empty(struct{}{})
	}
	node.depth = depth
	node.treeConfig = tc
	return node
}

// New creates a new tree root
func New(width int) VerkleNode {
	return newInternalNode(0, GetTreeConfig(width))
}

// Offset2Key extracts the n bits of a key that correspond to the
// index of a child node.
func Offset2Key(key []byte, offset, width int) uint {
	switch width {
	case 10:
		return Offset2KeyTenBits(key, offset)
	case 8:
		return uint(key[offset/8])
	default:
		// no need to bother with other width
		// until this is required.
		panic("node width not supported")
	}
}

func Offset2KeyTenBits(key []byte, offset int) uint {
	// The node has 1024 children, i.e. 10 bits. Extract it
	// from the key to figure out which child to recurse into.
	// The number is necessarily spread across 2 bytes because
	// the pitch is 10 and therefore a multiple of 2. Hence, no
	// 3 byte scenario is possible.
	nFirstByte := offset / 8
	nBitsInSecondByte := (offset + 10) % 8
	firstBitShift := (8 - (offset % 8))
	lastBitShift := (8 - nBitsInSecondByte) % 8
	leftMask := (key[nFirstByte] >> firstBitShift) << firstBitShift
	ret := (uint(key[nFirstByte]^leftMask) << ((uint(nBitsInSecondByte)-1)%8 + 1))
	if int(nFirstByte)+1 < len(key) {
		// Note that, at the last level, the last 4 bits are
		// zeroed-out so children are 16 bits apart.
		ret |= uint(key[nFirstByte+1] >> lastBitShift)
	}
	return ret
}

func (n *InternalNode) Depth() int {
	return n.depth
}

func (n *InternalNode) SetDepth(depth int) {
	n.depth = depth
}

func (n *InternalNode) Width() int {
	return n.treeConfig.width
}

func (n *InternalNode) Children() []VerkleNode {
	return n.children
}

func (n *InternalNode) SetChild(i int, c VerkleNode) error {
	if i >= n.treeConfig.nodeWidth-1 {
		return errors.New("child index higher than node width")
	}
	n.children[i] = c
	return nil
}

func (n *InternalNode) Insert(key []byte, value []byte) error {
	// Clear cached commitment on modification
	if n.commitment != nil {
		n.commitment = nil
	}

	nChild := Offset2Key(key, n.depth, n.treeConfig.width)

	switch child := n.children[nChild].(type) {
	case Empty:
		n.children[nChild] = &LeafNode{key: key, value: value}
	case *HashedNode:
		return errInsertIntoHash
	case *LeafNode:
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if bytes.Equal(child.key, key) {
			child.value = value
		} else {
			width := n.treeConfig.width

			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := Offset2Key(child.key, n.depth+width, width)
			newBranch := newInternalNode(n.depth+width, n.treeConfig).(*InternalNode)
			n.children[nChild] = newBranch
			newBranch.children[nextWordInExistingKey] = child

			nextWordInInsertedKey := Offset2Key(key, n.depth+width, width)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				newBranch.children[nextWordInInsertedKey] = &LeafNode{key: key, value: value}
			} else {
				newBranch.Insert(key, value)
			}
		}
	default: // InternalNode
		return child.Insert(key, value)
	}
	return nil
}

func (n *InternalNode) InsertOrdered(key []byte, value []byte, flush chan FlushableNode) error {
	// Clear cached commitment on modification
	if n.commitment != nil {
		n.commitment = nil
	}

	nChild := Offset2Key(key, n.depth, n.treeConfig.width)

	switch child := n.children[nChild].(type) {
	case Empty:
		// Insert into a new subtrie, which means that the
		// subtree directly preceding this new one, can
		// safely be calculated.
		for i := int(nChild) - 1; i >= 0; i-- {
			switch n.children[i].(type) {
			case Empty:
				continue
			case *LeafNode:
				childHash := n.children[i].Hash()
				if flush != nil {
					flush <- FlushableNode{childHash, n.children[i]}
				}
				n.children[i] = &HashedNode{hash: childHash}
				break
			case *HashedNode:
				break
			default:
				comm := n.children[i].ComputeCommitment()
				// Doesn't re-compute commitment as it's cached
				h := n.children[i].Hash()
				if flush != nil {
					n.children[i].(*InternalNode).Flush(flush)
				}
				n.children[i] = &HashedNode{hash: h, commitment: comm}
				break
			}
		}

		n.children[nChild] = &LeafNode{key: key, value: value}
	case *HashedNode:
		return errInsertIntoHash
	case *LeafNode:
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if bytes.Equal(child.key, key) {
			child.value = value
		} else {
			width := n.treeConfig.width

			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := Offset2Key(child.key, n.depth+width, width)
			newBranch := newInternalNode(n.depth+width, n.treeConfig).(*InternalNode)
			n.children[nChild] = newBranch

			nextWordInInsertedKey := Offset2Key(key, n.depth+width, width)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Directly hash the (left) node that was already
				// inserted.
				h := child.Hash()
				comm := new(bls.G1Point)
				var tmp bls.Fr
				hashToFr(&tmp, h, n.treeConfig.modulus)
				bls.MulG1(comm, &bls.GenG1, &tmp)
				if flush != nil {
					flush <- FlushableNode{h, child}
				}
				newBranch.children[nextWordInExistingKey] = &HashedNode{hash: h, commitment: comm}
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				newBranch.children[nextWordInInsertedKey] = &LeafNode{key: key, value: value}
			} else {
				// Reinsert the leaf in order to recurse
				newBranch.children[nextWordInExistingKey] = child
				newBranch.InsertOrdered(key, value, flush)
			}
		}
	default: // InternalNode
		return child.InsertOrdered(key, value, flush)
	}
	return nil
}

func (n *InternalNode) Delete(key []byte) error {
	// Clear cached commitment on modification
	if n.commitment != nil {
		n.commitment = nil
	}

	nChild := Offset2Key(key, n.depth, n.treeConfig.width)
	switch child := n.children[nChild].(type) {
	case Empty:
		return errDeleteNonExistent
	case *HashedNode:
		return errors.New("trying to delete from a hashed subtree")
	case *LeafNode:
		if !bytes.Equal(child.key, key) {
			return errDeleteNonExistent
		}
		n.children[nChild] = Empty{}
		return nil
	default:
		if err := child.Delete(key); err != nil {
			return err
		}
		// Prune child if necessary
		emptyCount := 0
		lastNonEmpty := -1
		for i, c := range child.(*InternalNode).children {
			if _, ok := c.(Empty); !ok {
				emptyCount++
				lastNonEmpty = i
				if emptyCount >= 2 {
					return nil
				}
			}
		}
		switch emptyCount {
		case 0:
			n.children[nChild] = Empty{}
		case 1:
			n.children[nChild] = child.(*InternalNode).children[lastNonEmpty]
		default:
		}
	}
	return nil
}

// Flush hashes the children of an internal node and replaces them
// with HashedNode. It also sends the current node on the flush channel.
func (n *InternalNode) Flush(flush chan FlushableNode) {
	for i, child := range n.children {
		if c, ok := child.(*InternalNode); ok {
			c.Flush(flush)
			n.children[i] = &HashedNode{c.Hash(), c.commitment}
		} else if c, ok := child.(*LeafNode); ok {
			childHash := c.Hash()
			flush <- FlushableNode{childHash, c}
			n.children[i] = &HashedNode{hash: childHash}
		}
	}
	flush <- FlushableNode{n.Hash(), n}
}

func (n *InternalNode) Get(k []byte, getter NodeResolverFn) ([]byte, error) {
	nChild := Offset2Key(k, n.depth, n.treeConfig.width)

	switch child := n.children[nChild].(type) {
	case Empty, nil:
		// Return nil as a signal that the value isn't
		// present in the tree. This matches the behavior
		// of SecureTrie in Geth.
		return nil, nil
	case *HashedNode:
		// if a resolution function is set, resolve the
		// current hash node.
		if getter == nil {
			return nil, errReadFromInvalid
		}

		payload, err := getter(child.hash[:])
		if err != nil {
			return nil, err
		}

		// deserialize the payload and set it as the child
		c, err := ParseNode(payload, n.depth+n.Width(), n.Width())
		if err != nil {
			return nil, err
		}
		n.children[nChild] = c

		return c.Get(k, getter)
	default: // InternalNode
		return child.Get(k, getter)
	}
}

func (n *InternalNode) Hash() common.Hash {
	comm := n.ComputeCommitment()
	h := sha256.Sum256(bls.ToCompressedG1(comm))
	return common.BytesToHash(h[:])
}

// This function takes a hash and turns it into a bls.Fr integer, making
// sure that this doesn't overflow the modulus.
// This piece of code is really ugly, and probably a performance hog, it
// needs to be rewritten more efficiently.
func hashToFr(out *bls.Fr, h [32]byte, modulus *big.Int) {
	// set first byte to 0 so as not to have to calculate the modulus



	h[31] = 0

	if !bls.FrFrom32(out, h) {
		panic(fmt.Sprintf("invalid Fr number %x", h))
	}
}

func (n *InternalNode) ComputeCommitment() *bls.G1Point {
	if n.commitment != nil {
		return n.commitment
	}

	emptyChildren := 0
	poly := make([]bls.Fr, n.treeConfig.nodeWidth)
	for idx, childC := range n.children {
		switch child := childC.(type) {
		case Empty:
			emptyChildren++
		case *LeafNode, *HashedNode:
			hashToFr(&poly[idx], child.Hash(), n.treeConfig.modulus)
		default:
			compressed := bls.ToCompressedG1(childC.ComputeCommitment())
			hashToFr(&poly[idx], sha256.Sum256(compressed), n.treeConfig.modulus)
		}
	}

	var commP *bls.G1Point
	if n.treeConfig.nodeWidth-emptyChildren >= n.treeConfig.multiExpThreshold {
		commP = bls.LinCombG1(n.treeConfig.lg1, poly[:])
	} else {
		var comm bls.G1Point
		bls.CopyG1(&comm, &bls.ZERO_G1)
		for i := range poly {
			if !bls.EqualZero(&poly[i]) {
				var tmpG1, eval bls.G1Point
				bls.MulG1(&eval, &n.treeConfig.lg1[i], &poly[i])
				bls.CopyG1(&tmpG1, &comm)
				bls.AddG1(&comm, &tmpG1, &eval)
			}
		}
		commP = &comm
	}
	n.commitment = commP
	return n.commitment
}

func (n *InternalNode) GetCommitment() *bls.G1Point {
	return n.commitment
}

func (n *InternalNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	childIdx := Offset2Key(key, n.depth, n.treeConfig.width)
	comms, zis, yis, fis := n.children[childIdx].GetCommitmentsAlongPath(key)
	var zi, yi bls.Fr
	bls.AsFr(&zi, uint64(childIdx))
	fi := make([]bls.Fr, n.treeConfig.nodeWidth)
	for i, child := range n.children {
		hashToFr(&fi[i], child.Hash(), n.treeConfig.modulus)
		if i == int(childIdx) {
			bls.CopyFr(&yi, &fi[i])
		}
	}
	return append(comms, n.GetCommitment()), append(zis, &zi), append(yis, &yi), append(fis, fi[:])
}

func (n *InternalNode) Serialize() ([]byte, error) {
	var bitlist [128]uint8
	children := make([]byte, 0, n.treeConfig.nodeWidth*32)
	for i, c := range n.children {
		if _, ok := c.(Empty); !ok {
			setBit(bitlist[:], i)
			children = append(children, c.Hash().Bytes()...)
		}
	}
	return rlp.EncodeToBytes([]interface{}{internalRLPType, bitlist, children})
}

func (n *InternalNode) Copy() VerkleNode {
	ret := &InternalNode{
		children:   make([]VerkleNode, len(n.children)),
		commitment: new(bls.G1Point),
		depth:      n.depth,
		treeConfig: n.treeConfig,
	}

	for i, child := range n.children {
		ret.children[i] = child.Copy()
	}

	copy(ret.hash[:], n.hash[:])
	if n.commitment != nil {
		bls.CopyG1(ret.commitment, n.commitment)
	}

	return ret
}

// clearCache sets the commitment field of node
// and all of its children (recursively) to nil.
func (n *InternalNode) clearCache() {
	for _, c := range n.children {
		in, ok := c.(*InternalNode)
		if !ok {
			continue
		}
		in.clearCache()
	}
	n.commitment = nil
}

func (n *LeafNode) Insert(k []byte, value []byte) error {
	n.key = k
	n.value = value
	return nil
}

func (n *LeafNode) InsertOrdered(key []byte, value []byte, flush chan FlushableNode) error {
	err := n.Insert(key, value)
	if err != nil && flush != nil {
		flush <- FlushableNode{n.Hash(), n}
	}
	return err
}

func (n *LeafNode) Delete(k []byte) error {
	return errors.New("cant delete a leaf in-place")
}

func (n *LeafNode) Get(k []byte, _ NodeResolverFn) ([]byte, error) {
	if !bytes.Equal(k, n.key) {
		// If keys differ, return nil in order to
		// signal that the key isn't present in the
		// tree. Do not return an error, thus matching
		// the behavior of Geth's SecureTrie.
		return nil, nil
	}
	return n.value, nil
}

func (n *LeafNode) ComputeCommitment() *bls.G1Point {
	panic("can't compute the commitment directly")
}

func (n *LeafNode) GetCommitment() *bls.G1Point {
	panic("can't get the commitment directly")
}

func (n *LeafNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	return nil, nil, nil, nil
}

func (n *LeafNode) Hash() common.Hash {
	digest := sha256.New()
	digest.Write(n.key)
	digest.Write(n.value)
	return common.BytesToHash(digest.Sum(nil))
}

func (n *LeafNode) Serialize() ([]byte, error) {
	return rlp.EncodeToBytes([]interface{}{leafRLPType, n.key, n.value})
}

func (n *LeafNode) Copy() VerkleNode {
	l := &LeafNode{}
	l.key = make([]byte, len(n.key))
	l.value = make([]byte, len(n.value))
	copy(l.key, n.key)
	copy(l.value, n.value)

	return l
}

func (n *LeafNode) Key() []byte {
	return n.key
}

func (n *LeafNode) Value() []byte {
	return n.value
}

func (n *HashedNode) Insert(k []byte, value []byte) error {
	return errInsertIntoHash
}

func (n *HashedNode) InsertOrdered(key []byte, value []byte, _ chan FlushableNode) error {
	return errInsertIntoHash
}

func (n *HashedNode) Delete(k []byte) error {
	return errors.New("cant delete a hashed node in-place")
}

func (n *HashedNode) Get(k []byte, _ NodeResolverFn) ([]byte, error) {
	return nil, errors.New("can not read from a hash node")
}

func (n *HashedNode) Hash() common.Hash {
	return n.hash
}

func (n *HashedNode) ComputeCommitment() *bls.G1Point {
	if n.commitment == nil {
		var hashAsFr bls.Fr
		hashToFr(&hashAsFr, n.hash, big.NewInt(0))
		n.commitment = new(bls.G1Point)
		bls.MulG1(n.commitment, &bls.GenG1, &hashAsFr)
	}
	return n.commitment
}

func (n *HashedNode) GetCommitment() *bls.G1Point {
	return n.commitment
}

func (n *HashedNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	panic("can not get the full path, and there is no proof of absence")
}

func (n *HashedNode) Serialize() ([]byte, error) {
	return rlp.EncodeToBytes([][]byte{n.hash[:]})
}

func (n *HashedNode) Copy() VerkleNode {
	h := &HashedNode{
		commitment: new(bls.G1Point),
	}
	copy(h.hash[:], n.hash[:])
	if n.commitment != nil {
		bls.CopyG1(h.commitment, n.commitment)
	}

	return h
}

func (e Empty) Insert(k []byte, value []byte) error {
	return errors.New("an empty node should not be inserted directly into")
}

func (e Empty) InsertOrdered(key []byte, value []byte, _ chan FlushableNode) error {
	return e.Insert(key, value)
}

func (e Empty) Delete(k []byte) error {
	return errors.New("cant delete an empty node")
}

func (e Empty) Get(k []byte, _ NodeResolverFn) ([]byte, error) {
	return nil, nil
}

func (e Empty) Hash() common.Hash {
	return zeroHash
}

func (e Empty) ComputeCommitment() *bls.G1Point {
	return &bls.ZeroG1
}

func (e Empty) GetCommitment() *bls.G1Point {
	return &bls.ZeroG1
}

func (e Empty) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	panic("trying to produce a commitment for an empty subtree")
}

func (e Empty) Serialize() ([]byte, error) {
	return nil, errors.New("can't encode empty node to RLP")
}

func (e Empty) Copy() VerkleNode {
	return Empty(struct{}{})
}

func setBit(bitlist []uint8, index int) {
	byt := index / 8
	bit := index % 8
	bitlist[byt] |= (uint8(1) << bit)
}
