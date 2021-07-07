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
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/protolambda/go-kzg/bls"
)

type NodeFlushFn func(VerkleNode)
type NodeResolverFn func([]byte) ([]byte, error)

type VerkleNode interface {
	// Insert or Update value `v` at key `k`
	Insert(k []byte, v []byte) error

	// Insert "à la" Stacktrie. Same thing as insert, except that
	// values are expected to be ordered, and the commitments and
	// hashes for each subtrie are computed online, as soon as it
	// is clear that no more values will be inserted in there.
	InsertOrdered([]byte, []byte, NodeFlushFn) error

	// Adds an account to the tree
	CreateAccount([]byte, uint64, uint64, uint64, *big.Int, common.Hash) error

	// Delete a leaf with the given key
	Delete([]byte) error

	// Get value at a given key
	Get([]byte, NodeResolverFn) ([]byte, error)

	// Hash of the current node
	Hash() common.Hash

	// ComputeCommitment computes the commitment of the node
	// The result is cached.
	ComputeCommitment() *bls.G1Point

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

	AccountLeaf struct {
		LeafNode

		Version  uint64
		Balance  *big.Int
		Nonce    uint64
		CodeSize uint64
		CodeHash common.Hash

		commitment *bls.G1Point

		treeConfig *TreeConfig
	}

	LeafNode struct {
		key    []byte
		values [][]byte

		commitment *bls.G1Point
		treeConfig *TreeConfig
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

	nChild := n.treeConfig.offset2key(key, n.depth)

	switch child := n.children[nChild].(type) {
	case Empty:
		lastNode := &LeafNode{
			key:        key,
			values:     make([][]byte, n.treeConfig.nodeWidth),
			treeConfig: n.treeConfig,
		}
		lastNode.values[lastSlot(n.treeConfig.width, key)] = value
		n.children[nChild] = lastNode
	case *HashedNode:
		return errInsertIntoHash
	case *LeafNode:
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if n.treeConfig.equalPaths(child.key, key) {
			child.Insert(key, value)
		} else {
			width := n.treeConfig.width

			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := n.treeConfig.offset2key(child.key, n.depth+width)
			newBranch := newInternalNode(n.depth+width, n.treeConfig).(*InternalNode)
			n.children[nChild] = newBranch
			newBranch.children[nextWordInExistingKey] = child

			nextWordInInsertedKey := n.treeConfig.offset2key(key, n.depth+width)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				lastNode := &LeafNode{
					key:        key,
					values:     make([][]byte, n.treeConfig.nodeWidth),
					treeConfig: n.treeConfig,
				}
				lastNode.values[lastSlot(n.treeConfig.width, key)] = value
				newBranch.children[nextWordInInsertedKey] = lastNode
			} else {
				newBranch.Insert(key, value)
			}
		}
	default: // InternalNode
		return child.Insert(key, value)
	}
	return nil
}

func (n *InternalNode) InsertOrdered(key []byte, value []byte, flush NodeFlushFn) error {
	// Clear cached commitment on modification
	if n.commitment != nil {
		n.commitment = nil
	}

	nChild := n.treeConfig.offset2key(key, n.depth)

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
					flush(n.children[i])
				}
				n.children[i] = &HashedNode{hash: childHash}
				break
			case *HashedNode:
				break
			default:
				comm := n.children[i].ComputeCommitment()
				// Don't re-compute commitment as it's cached
				h := n.children[i].Hash()
				if flush != nil {
					n.children[i].(*InternalNode).Flush(flush)
				}
				n.children[i] = &HashedNode{hash: h, commitment: comm}
				break
			}
		}

		// NOTE: these allocations are inducing a noticeable slowdown
		lastNode := &LeafNode{
			key:        key,
			values:     make([][]byte, n.treeConfig.nodeWidth),
			treeConfig: n.treeConfig,
		}
		lastNode.values[lastSlot(n.treeConfig.width, key)] = value
		n.children[nChild] = lastNode
	case *HashedNode:
		return errInsertIntoHash
	case *LeafNode:
		// Need to add a new branch node to differentiate
		// between two keys, if the keys are different.
		// Otherwise, just update the key.
		if n.treeConfig.equalPaths(child.key, key) {
			child.values[lastSlot(n.treeConfig.width, key)] = value
		} else {
			width := n.treeConfig.width

			// A new branch node has to be inserted. Depending
			// on the next word in both keys, a recursion into
			// the moved leaf node can occur.
			nextWordInExistingKey := n.treeConfig.offset2key(child.key, n.depth+width)
			newBranch := newInternalNode(n.depth+width, n.treeConfig).(*InternalNode)
			n.children[nChild] = newBranch

			nextWordInInsertedKey := n.treeConfig.offset2key(key, n.depth+width)
			if nextWordInInsertedKey != nextWordInExistingKey {
				// Directly hash the (left) node that was already
				// inserted.
				h := child.Hash()
				comm := new(bls.G1Point)
				var tmp bls.Fr
				hashToFr(&tmp, h, n.treeConfig.modulus)
				bls.MulG1(comm, &bls.GenG1, &tmp)
				if flush != nil {
					flush(child)
				}
				newBranch.children[nextWordInExistingKey] = &HashedNode{hash: h, commitment: comm}
				// Next word differs, so this was the last level.
				// Insert it directly into its final slot.
				lastNode := &LeafNode{
					key:        key,
					values:     make([][]byte, n.treeConfig.nodeWidth),
					treeConfig: n.treeConfig,
				}
				lastNode.values[lastSlot(n.treeConfig.width, key)] = value
				newBranch.children[nextWordInInsertedKey] = lastNode
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

	nChild := n.treeConfig.offset2key(key, n.depth)
	switch child := n.children[nChild].(type) {
	case Empty:
		return errDeleteNonExistent
	case *HashedNode:
		return errors.New("trying to delete from a hashed subtree")
	case *LeafNode:
		if !n.treeConfig.equalPaths(child.key, key) {
			return errDeleteNonExistent
		}
		n.commitment = nil
		if err := child.Delete(key); err != nil {
			return err
		}
		// Prune child if necessary
		usedCount := 0
		for _, v := range child.values {
			if v != nil {
				usedCount++
				if usedCount >= 1 {
					return nil
				}
			}
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
func (n *InternalNode) Flush(flush NodeFlushFn) {
	for i, child := range n.children {
		if c, ok := child.(*InternalNode); ok {
			c.Flush(flush)
			n.children[i] = &HashedNode{c.Hash(), c.commitment}
		} else if c, ok := child.(*LeafNode); ok {
			childHash := c.Hash()
			flush(c)
			n.children[i] = &HashedNode{hash: childHash}
		}
	}
	flush(n)
}

func (n *InternalNode) Get(k []byte, getter NodeResolverFn) ([]byte, error) {
	nChild := n.treeConfig.offset2key(k, n.depth)

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
	default: // InternalNode, [Account]Leaf
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
	h[31] &= 0x7F // mod 2^255

	// reverse endianness (little -> big)
	for i := 0; i < len(h)/2; i++ {
		t := h[i]
		h[i] = h[len(h)-i-1]
		h[len(h)-i-1] = t
	}

	// Apply modulus
	x := big.NewInt(0).SetBytes(h[:])
	x.Mod(x, modulus)

	// clear the buffer in case the trailing bytes were 0
	for i := 0; i < 32; i++ {
		h[i] = 0
	}

	// back to original endianness
	converted := x.Bytes()
	for i := 0; i < len(converted); i++ {
		h[i] = converted[len(converted)-i-1]
	}

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

	n.commitment = n.treeConfig.evalPoly(poly, emptyChildren)
	return n.commitment
}

func (n *InternalNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	childIdx := n.treeConfig.offset2key(key, n.depth)
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
	return append(comms, n.ComputeCommitment()), append(zis, &zi), append(yis, &yi), append(fis, fi[:])
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

func (n *InternalNode) CreateAccount(key []byte, version, nonce, codeSize uint64, balance *big.Int, codeHash common.Hash) error {
	nChild := Offset2Key(key, n.depth, n.treeConfig.width)

	switch child := n.children[nChild].(type) {
	case *LeafNode, *HashedNode, nil:
		return errors.New("trying to create an account in an invalid subtree")
	case Empty:
		n.children[nChild] = &AccountLeaf{
			LeafNode: LeafNode{key: key},
			Version:  version,
			Balance:  balance,
			Nonce:    nonce,
			CodeSize: codeSize,
			CodeHash: codeHash,
		}
		return nil
	case *AccountLeaf:
		// Insert an intermediate node
		newBranch := newInternalNode(n.depth+n.treeConfig.width, n.treeConfig).(*InternalNode)

		nExisting := Offset2Key(child.key, n.depth+1, n.treeConfig.width)
		nNew := Offset2Key(key, n.depth+1, n.treeConfig.width)

		newBranch.children[nExisting] = child

		if nExisting != nNew {
			// Both the current account node and the inserted
			// one share the same key segment. Introduce an
			// intermediate node and recurse.
			n.children[nChild] = newBranch
			return newBranch.CreateAccount(key, version, nonce, codeSize, balance, codeHash)
		}

		// The new branch is the first differing branch, set both of them
		// in their own slot.
		n.children[nNew] = new(AccountLeaf)
		return n.children[nNew].CreateAccount(key, version, nonce, codeSize, balance, codeHash)
	default:
		return child.CreateAccount(key, version, nonce, codeSize, balance, codeHash)
	}
}

const (
	accountLeafVersion = iota
	accountLeafBalance
	accountLeafNonce
	accountLeafCodeHash
	accountLeafCodeSize
)

func (n *AccountLeaf) Insert(k []byte, value []byte) error {
	// The parent insert is expected to ensure that this
	// situation doesn't occur. This check will catch an
	// invalid situation while the library stabilizes.
	if !bytes.Equal(k[:31], n.key[:31]) {
		return errors.New("inserting invalid key into key")
	}

	switch k[31] {
	case accountLeafBalance:
		n.Balance.SetBytes(value)
		n.commitment = nil // invalidate commitment
	case accountLeafNonce:
		n.Nonce = binary.BigEndian.Uint64(value)
		n.commitment = nil // invalidate commitment
	default:
		return errors.New("writing to read-only location")
	}
	return nil
}

func (n *AccountLeaf) CreateAccount(k []byte, version, nonce, codeSize uint64, balance *big.Int, codeHash common.Hash) error {
	return errors.New("creating over an already exisiting account")
}

func (n *AccountLeaf) InsertOrdered(key []byte, value []byte, flush chan FlushableNode) error {
	err := n.Insert(key, value)
	if err != nil && flush != nil {
		flush <- FlushableNode{n.Hash(), n}
	}
	return err
}

func (n *AccountLeaf) Get(k []byte, resolver NodeResolverFn) ([]byte, error) {
	if !bytes.Equal(k[:31], n.key[:31]) {
		return nil, errValueNotPresent
	}

	switch k[31] {
	case accountLeafVersion:
		var ret [8]byte
		binary.BigEndian.PutUint64(ret[:], n.Version)
		return ret[:], nil
	case accountLeafBalance:
		return n.Balance.Bytes(), nil
	case accountLeafNonce:
		var ret [8]byte
		binary.BigEndian.PutUint64(ret[:], n.Nonce)
		return ret[:], nil
	case accountLeafCodeHash:
		return n.CodeHash[:], nil
	case accountLeafCodeSize:
		var ret [8]byte
		binary.BigEndian.PutUint64(ret[:], n.CodeSize)
		return ret[:], nil
	default:
		return nil, errValueNotPresent
	}
}

func (n *AccountLeaf) ComputeCommitment() *bls.G1Point {
	// TODO only allocate if the thing isn't already
	// allocated. Otherwise, just overwrite it.
	n.commitment = new(bls.G1Point)
	bls.CopyG1(n.commitment, &bls.ZERO_G1)

	// Build the polynomial based on the account information
	var poly [5]bls.Fr
	bls.AsFr(&poly[0], n.Version)
	var data [32]byte
	n.Balance.FillBytes(data[:])
	hashToFr(&poly[1], data, n.treeConfig.modulus)
	bls.AsFr(&poly[2], n.Nonce)
	hashToFr(&poly[3], n.CodeHash, n.treeConfig.modulus)
	bls.AsFr(&poly[4], n.CodeSize)

	for i := range poly {
		if !bls.EqualZero(&poly[i]) {
			var eval bls.G1Point
			bls.MulG1(&eval, &n.treeConfig.lg1[i], &poly[i])
			bls.AddG1(n.commitment, n.commitment, &eval)
		}
	}

	return n.commitment
}

func (n *AccountLeaf) GetCommitment() *bls.G1Point {
	return n.commitment
}

func (n *AccountLeaf) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	return nil, nil, nil, nil
}

func (n *AccountLeaf) Hash() common.Hash {
	h := sha256.Sum256(bls.ToCompressedG1(n.ComputeCommitment()))
	return common.BytesToHash(h[:])
}

func (n *AccountLeaf) Serialize() ([]byte, error) {
	return rlp.EncodeToBytes(struct {
		k []byte
		v uint64
		b *big.Int
		m uint64
		h []byte
		s uint64
	}{n.key, n.Version, n.Balance, n.Nonce, n.CodeHash[:], n.CodeSize})
}

func (n *LeafNode) Insert(k []byte, value []byte) error {
	// Sanity check: ensure the key header is the same:
	if !n.treeConfig.equalPaths(k, n.key) {
		return errors.New("split should not happen here")
	}
	n.values[lastSlot(n.treeConfig.width, k)] = value
	n.commitment = nil
	return nil
}

func (n *LeafNode) InsertOrdered(key []byte, value []byte, flush NodeFlushFn) error {
	// In the previous version, this value used to be flushed on insert.
	// This is no longer the case, as all values at the last level get
	// flushed at the same time.
	return n.Insert(key, value)
}

func (n *LeafNode) Delete(k []byte) error {
	// Sanity check: ensure the key header is the same:
	if !n.treeConfig.equalPaths(k, n.key) {
		return errors.New("trying to delete a non-existing key")
	}

	n.values[lastSlot(n.treeConfig.width, k)] = nil
	return nil
}

func lastSlot(width int, key []byte) int {
	switch width {
	case 8:
		return int(key[31])
	case 10:
		return int(key[31]&0x3F) << 4
	default:
		panic("invalid width")
	}
}

func (n *LeafNode) CreateAccount(key []byte, version, nonce, codeSize uint64, balance *big.Int, codeHash common.Hash) error {
	return errors.New("inserting an account node in a storage leaf")
}

func (n *LeafNode) Get(k []byte, _ NodeResolverFn) ([]byte, error) {
	if !n.treeConfig.equalPaths(k, n.key) {
		// If keys differ, return nil in order to
		// signal that the key isn't present in the
		// tree. Do not return an error, thus matching
		// the behavior of Geth's SecureTrie.
		return nil, nil
	}
	// value can be nil, as expected by geth
	return n.values[lastSlot(n.treeConfig.width, k)], nil
}

func (n *LeafNode) ComputeCommitment() *bls.G1Point {
	if n.commitment != nil {
		return n.commitment
	}

	emptyChildren := 0
	poly := make([]bls.Fr, n.treeConfig.nodeWidth)
	for idx, val := range n.values {
		if val == nil {
			emptyChildren++
			continue
		}
		h := sha256.Sum256(val)
		hashToFr(&poly[idx], h, n.treeConfig.modulus)
	}

	n.commitment = n.treeConfig.evalPoly(poly, emptyChildren)
	return n.commitment
}

func (n *LeafNode) GetCommitmentsAlongPath(key []byte) ([]*bls.G1Point, []*bls.Fr, []*bls.Fr, [][]bls.Fr) {
	return nil, nil, nil, nil
}

func (n *LeafNode) Hash() common.Hash {
	comm := n.ComputeCommitment()
	h := sha256.Sum256(bls.ToCompressedG1(comm))
	return common.BytesToHash(h[:])
}

func (n *LeafNode) Serialize() ([]byte, error) {
	return rlp.EncodeToBytes([]interface{}{leafRLPType, n.key, n.values})
}

func (n *LeafNode) Copy() VerkleNode {
	l := &LeafNode{}
	l.key = make([]byte, len(n.key))
	l.values = make([][]byte, len(n.values))
	l.treeConfig = n.treeConfig
	copy(l.key, n.key)
	for i, v := range n.values {
		l.values[i] = make([]byte, len(v))
		copy(l.values[i], v)
	}
	if n.commitment != nil {
		l.commitment = n.commitment
	}

	return l
}

func (n *HashedNode) Insert(k []byte, value []byte) error {
	return errInsertIntoHash
}

func (n *HashedNode) InsertOrdered(key []byte, value []byte, _ NodeFlushFn) error {
	return errInsertIntoHash
}

func (n *HashedNode) Delete(k []byte) error {
	return errors.New("cant delete a hashed node in-place")
}

func (n *HashedNode) CreateAccount(key []byte, version, nonce, codeSize uint64, balance *big.Int, codeHash common.Hash) error {
	return errors.New("inserting an account node in a hash node")
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

func (e Empty) InsertOrdered(key []byte, value []byte, _ NodeFlushFn) error {
	return e.Insert(key, value)
}

func (e Empty) Delete(k []byte) error {
	return errors.New("cant delete an empty node")
}

func (e Empty) CreateAccount(key []byte, version, nonce, codeSize uint64, balance *big.Int, codeHash common.Hash) error {
	return errors.New("inserting an account node directly into an empty node")
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
