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
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg/bls"
)

var testValue = []byte("hello")

var (
	zeroKeyTest   = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000")
	oneKeyTest    = common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001")
	fourtyKeyTest = common.Hex2Bytes("4000000000000000000000000000000000000000000000000000000000000000")
	ffx32KeyTest  = common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
)

var s1, lg1 []bls.G1Point
var s2 []bls.G2Point

func TestInsertIntoRoot(t *testing.T) {
	root := New(10)
	err := root.Insert(zeroKeyTest, testValue)
	if err != nil {
		t.Fatalf("error inserting: %v", err)
	}

	leaf, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[0])
	}

	if !bytes.Equal(leaf.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf.value[:])
	}
}

func TestInsertTwoLeaves(t *testing.T) {
	root := New(10)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	leaf0, ok := root.(*InternalNode).children[0].(*LeafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[0])
	}

	leaff, ok := root.(*InternalNode).children[1023].(*LeafNode)
	if !ok {
		t.Fatalf("invalid leaf node type %v", root.(*InternalNode).children[1023])
	}

	if !bytes.Equal(leaf0.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf0.value[:])
	}

	if !bytes.Equal(leaff.value[:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaff.value[:])
	}
}

func TestGetTwoLeaves(t *testing.T) {
	root := New(10)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	val, err := root.Get(zeroKeyTest)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(val, testValue) {
		t.Fatalf("got a different value from the tree than expected %x != %x", val, testValue)
	}

	val, err = root.Get(oneKeyTest)
	if err != nil {
		t.Fatalf("wrong error type, expected %v, got %v", nil, err)
	}
	if val != nil {
		t.Fatalf("Get returned value %x for a non-existing key", val)
	}

	if val != nil {
		t.Fatalf("got a different value from the tree than expected %x != nil", val)
	}
}

func TestTreeHashing(t *testing.T) {
	root := New(10)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	root.Hash()
}

func TestComputeRootCommitmentThreeLeaves(t *testing.T) {
	root := New(10)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(fourtyKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	expected := []byte{137, 46, 141, 157, 55, 243, 191, 123, 197, 83, 9, 229, 155, 145, 185, 155, 171, 133, 195, 118, 100, 193, 107, 202, 170, 6, 51, 189, 99, 62, 244, 70, 199, 253, 80, 218, 171, 68, 89, 136, 222, 166, 5, 209, 92, 255, 140, 164}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentOnlineThreeLeaves(t *testing.T) {
	root := New(10)
	root.InsertOrdered(zeroKeyTest, testValue, nil)
	root.InsertOrdered(fourtyKeyTest, testValue, nil)
	root.InsertOrdered(ffx32KeyTest, testValue, nil)

	// This still needs to be called, so that the root
	// commitment is calculated.
	comm := root.ComputeCommitment()

	expected := []byte{137, 46, 141, 157, 55, 243, 191, 123, 197, 83, 9, 229, 155, 145, 185, 155, 171, 133, 195, 118, 100, 193, 107, 202, 170, 6, 51, 189, 99, 62, 244, 70, 199, 253, 80, 218, 171, 68, 89, 136, 222, 166, 5, 209, 92, 255, 140, 164}

	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentThreeLeavesDeep(t *testing.T) {
	root := New(10)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(oneKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	expected := []byte{180, 224, 116, 69, 8, 16, 10, 46, 12, 87, 199, 139, 17, 157, 123, 95, 113, 9, 180, 227, 72, 13, 125, 20, 35, 52, 98, 119, 121, 181, 253, 151, 253, 0, 62, 206, 64, 49, 8, 93, 140, 128, 232, 208, 102, 248, 81, 206}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentOnlineThreeLeavesDeep(t *testing.T) {
	root := New(10)
	root.InsertOrdered(zeroKeyTest, testValue, nil)
	root.InsertOrdered(oneKeyTest, testValue, nil)
	root.InsertOrdered(ffx32KeyTest, testValue, nil)

	expected := []byte{180, 224, 116, 69, 8, 16, 10, 46, 12, 87, 199, 139, 17, 157, 123, 95, 113, 9, 180, 227, 72, 13, 125, 20, 35, 52, 98, 119, 121, 181, 253, 151, 253, 0, 62, 206, 64, 49, 8, 93, 140, 128, 232, 208, 102, 248, 81, 206}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentOnlineThreeLeavesFlush(t *testing.T) {
	flush := make(chan FlushableNode)
	go func() {
		root := New(10)
		root.InsertOrdered(zeroKeyTest, testValue, flush)
		root.InsertOrdered(fourtyKeyTest, testValue, flush)
		root.InsertOrdered(ffx32KeyTest, testValue, flush)
		root.(*InternalNode).Flush(flush)
		close(flush)
	}()

	count := 0
	for f := range flush {
		_, isLeaf := f.Node.(*LeafNode)
		_, isInternal := f.Node.(*InternalNode)
		if !isLeaf && !isInternal {
			t.Fatal("invalid node type received, expected leaf")
		}
		count++
	}

	if count != 4 {
		t.Fatalf("incorrect number of flushed leaves 4 != %d", count)
	}
}

func TestComputeRootCommitmentTwoLeaves(t *testing.T) {
	root := New(10)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)
	expected := []byte{178, 195, 197, 132, 158, 141, 115, 80, 222, 187, 37, 145, 15, 184, 242, 86, 101, 164, 144, 51, 239, 90, 232, 100, 78, 178, 253, 145, 36, 168, 30, 75, 100, 185, 100, 14, 198, 48, 14, 95, 3, 252, 185, 73, 183, 195, 153, 44}

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestHashToFrTrailingZeroBytes(t *testing.T) {
	modulus, ok := big.NewInt(0).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	if !ok {
		panic("could not get modulus")
	}

	h := common.HexToHash("c79e576e0f534a5bbed66b32e5022a9d624b4415779b369a62b2e7a6c3d8e000")
	var out bls.Fr
	hashToFr(&out, h, modulus)

	h2 := common.HexToHash("c79e576e0f534a5bbed66b32e5022a9d624b4415779b369a62b2e7a6c3d8e000")
	var expected bls.Fr
	bls.FrFrom32(&expected, h2)

	if !bls.EqualFr(&out, &expected) {
		t.Fatalf("incorrect value received, got %x != %x", out, expected)
	}
}

func TestOffset2Key8BitsWide(t *testing.T) {
	key := common.Hex2Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	for i := 0; i < 32; i++ {
		childId := Offset2Key(key, i*8, 8)
		if childId != uint(i) {
			t.Fatalf("error getting child number in key %d != %d", childId, i)
		}
	}
}

func TestOffset2Key10BitsWide(t *testing.T) {
	key := common.Hex2Bytes("00001008030100501807020090280b0300d0380f040110481305015058170601")
	for i := 0; i < 25; i++ {
		childId := Offset2Key(key, i*10, 10)
		if childId != uint(i) {
			t.Fatalf("error getting child number in key %d != %d", childId, i)
		}
	}

	if childIdx := Offset2Key(key, 250, 10); childIdx != 16 {
		t.Fatalf("error getting last child number in key %d != %d", childIdx, 16)
	}
}

func TestComputeRootCommitmentTwoLeaves256(t *testing.T) {
	root := New(8)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)
	expected := common.Hex2Bytes("84c699b01f33e5af95d4dd3a09257c442606a0d812600bdfcc06f45be6eba3cc767fa837e47e5c1ac51956424c9258dd")

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestInsertVsOrdered(t *testing.T) {
	n := 10000
	rand.Seed(time.Now().UnixNano())
	value := []byte("value")
	keys := randomKeys(n)
	sortedKeys := make([][]byte, n)
	copy(sortedKeys[:], keys[:])
	sort.Slice(sortedKeys, func(i, j int) bool { return bytes.Compare(sortedKeys[i], sortedKeys[j]) < 0 })

	root1 := New(10)
	for _, k := range keys {
		root1.Insert(k, value)
	}
	root2 := New(10)
	for _, k := range sortedKeys {
		root2.InsertOrdered(k, value, nil)
	}

	h1 := root1.Hash().Bytes()
	h2 := root2.Hash().Bytes()

	if !bytes.Equal(h1, h2) {
		t.Error("Insert and InsertOrdered produce different trees")
	}
}

func TestFlush1kLeaves(t *testing.T) {
	n := 1000
	rand.Seed(time.Now().UnixNano())
	keys := randomKeysSorted(n)
	value := []byte("value")

	flush := make(chan FlushableNode)
	go func() {
		root := New(10)
		for _, k := range keys {
			root.InsertOrdered(k, value, flush)
		}
		root.(*InternalNode).Flush(flush)
		close(flush)
	}()

	count := 0
	leaves := 0
	for f := range flush {
		_, isLeaf := f.Node.(*LeafNode)
		_, isInternal := f.Node.(*InternalNode)
		if !isLeaf && !isInternal {
			t.Fatal("invalid node type received, expected leaf")
		}
		if isLeaf {
			leaves++
		}
		count++
	}

	if leaves != n {
		t.Errorf("number of flushed leaves incorrect. Expected %d got %d\n", n, leaves)
	}
	if count <= n {
		t.Errorf("number of flushed nodes incorrect. Expected %d got %d\n", n, leaves)
	}
}

func TestCopy(t *testing.T) {
	value := []byte("value")
	key1 := common.Hex2Bytes("0105000000000000000000000000000000000000000000000000000000000000")
	key2 := common.Hex2Bytes("0107000000000000000000000000000000000000000000000000000000000000")
	key3 := common.Hex2Bytes("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New(8)
	tree.Insert(key1, value)
	tree.Insert(key2, value)
	tree.Insert(key3, value)
	tree.ComputeCommitment()

	copied := tree.Copy()
	copied.(*InternalNode).clearCache()

	if !bytes.Equal(bls.ToCompressedG1(copied.ComputeCommitment()), bls.ToCompressedG1(tree.ComputeCommitment())) {
		t.Fatal("error copying commitments")
	}
	if copied.Hash() != tree.Hash() {
		t.Fatal("error copying commitments")
	}
	tree.Insert(key2, []byte("changed"))
	tree.ComputeCommitment()
	if bytes.Equal(bls.ToCompressedG1(copied.GetCommitment()), bls.ToCompressedG1(tree.GetCommitment())) {
		t.Fatal("error tree and its copy should have a different commitment after the update")
	}
}

func TestCachedCommitment(t *testing.T) {
	value := []byte("value")
	key1 := common.Hex2Bytes("0105000000000000000000000000000000000000000000000000000000000000")
	key2 := common.Hex2Bytes("0107000000000000000000000000000000000000000000000000000000000000")
	key3 := common.Hex2Bytes("0405000000000000000000000000000000000000000000000000000000000000")
	key4 := common.Hex2Bytes("0407000000000000000000000000000000000000000000000000000000000000")
	tree := New(8)
	tree.Insert(key1, value)
	tree.Insert(key2, value)
	tree.Insert(key3, value)
	tree.ComputeCommitment()

	if tree.(*InternalNode).commitment == nil {
		t.Error("root has not cached commitment")
	}

	tree.Insert(key4, value)

	if tree.(*InternalNode).commitment != nil {
		t.Error("root has stale commitment")
	}
	if tree.(*InternalNode).children[4].(*InternalNode).commitment != nil {
		t.Error("internal node has stale commitment")
	}
	if tree.(*InternalNode).children[1].(*InternalNode).commitment == nil {
		t.Error("internal node has mistakenly cleared cached commitment")
	}
}

func TestClearCache(t *testing.T) {
	value := []byte("value")
	key1 := common.Hex2Bytes("0105000000000000000000000000000000000000000000000000000000000000")
	key2 := common.Hex2Bytes("0107000000000000000000000000000000000000000000000000000000000000")
	key3 := common.Hex2Bytes("0405000000000000000000000000000000000000000000000000000000000000")

	tree := New(8)
	tree.Insert(key1, value)
	tree.Insert(key2, value)
	tree.Insert(key3, value)
	tree.ComputeCommitment()

	root := tree.(*InternalNode)
	root.clearCache()

	if root.commitment != nil {
		t.Error("root cached commitment should have been cleared")
	}

	if root.children[1].(*InternalNode).commitment != nil {
		t.Error("internal child's cached commitment should have been cleared")
	}
}

func TestGetCommitmentAlongPathS(t *testing.T) {
	value := []byte("value")
	key1 := common.Hex2Bytes("0105000000000000000000000000000000000000000000000000000000000000")
	key2 := common.Hex2Bytes("0107000000000000000000000000000000000000000000000000000000000000")
	key3 := common.Hex2Bytes("0405000000000000000000000000000000000000000000000000000000000000")
	key4 := common.Hex2Bytes("0407000000000000000000000000000000000000000000000000000000000000")
	tree := New(8)
	tree.Insert(key1, value)
	tree.Insert(key2, value)
	tree.Insert(key3, value)
	tree.Insert(key4, value)
	tree.ComputeCommitment()

	cs, zs, ys, fs := tree.GetCommitmentsAlongPaths([][]byte{key3, key4})
	if len(cs) != 4 {
		t.Fatalf("invalid number of commitments 4 != %d", len(cs))
	}
	if len(zs) != 4 {
		t.Fatalf("invalid number of zis 4 != %d", len(zs))
	}
	if len(ys) != 4 {
		t.Fatalf("invalid number of yis 4 != %d", len(ys))
	}
	if len(fs) != 4 {
		t.Fatalf("invalid number of fis 4 != %d", len(fs))
	}
}

func BenchmarkCommitLeaves(b *testing.B) {
	benchmarkCommitNLeaves(b, 1000, 10)
	benchmarkCommitNLeaves(b, 10000, 10)
	benchmarkCommitNLeaves(b, 1000, 8)
	benchmarkCommitNLeaves(b, 10000, 8)
}

func BenchmarkCommitFullNode(b *testing.B) {
	benchmarkCommitFullNode(b, 10)
	benchmarkCommitFullNode(b, 8)
}
func benchmarkCommitFullNode(b *testing.B, width int) {
	b.Run(fmt.Sprintf("width/%d", width), func(b *testing.B) {
		nChildren := 1 << width
		value := []byte("value")
		keys := make([][]byte, nChildren)
		for i := 0; i < nChildren; i++ {
			key := make([]byte, 32)
			if width == 10 {
				binary.BigEndian.PutUint16(key[:2], uint16(i)<<6)
			} else {
				key[0] = uint8(i)
			}
			keys[i] = key
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			root := New(width)
			for _, k := range keys {
				if err := root.Insert(k, value); err != nil {
					b.Fatal(err)
				}
			}
			root.ComputeCommitment()
		}
	})
}

func benchmarkCommitNLeaves(b *testing.B, n, width int) {
	type kv struct {
		k []byte
		v []byte
	}
	kvs := make([]kv, n)
	sortedKVs := make([]kv, n)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		val := make([]byte, 32)
		rand.Read(key)
		rand.Read(val)
		kvs[i] = kv{k: key, v: val}
		sortedKVs[i] = kv{k: key, v: val}
	}

	// InsertOrder assumes keys are sorted
	sortKVs := func(src []kv) {
		sort.Slice(src, func(i, j int) bool { return bytes.Compare(src[i].k, src[j].k) < 0 })
	}
	sortKVs(sortedKVs)

	b.Run(fmt.Sprintf("insert/leaves/%d/width/%d", n, width), func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			root := New(width)
			for _, el := range kvs {
				if err := root.Insert(el.k, el.v); err != nil {
					b.Error(err)
				}
			}
			root.ComputeCommitment()
		}
	})

	b.Run(fmt.Sprintf("insertOrdered/leaves/%d/width/%d", n, width), func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			root := New(width)
			for _, el := range sortedKVs {
				if err := root.InsertOrdered(el.k, el.v, nil); err != nil {
					b.Fatal(err)
				}
			}
			root.ComputeCommitment()
		}
	})
}

func BenchmarkModifyLeaves(b *testing.B) {
	rand.Seed(time.Now().UnixNano())

	n := 200000
	toEdit := 10000
	val := []byte{0}
	keys := make([][]byte, n)
	root := New(10)
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
		root.Insert(key, val)
	}
	root.ComputeCommitment()

	b.ResetTimer()
	b.ReportAllocs()

	val = make([]byte, 4)
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint32(val, uint32(i))
		for j := 0; j < toEdit; j++ {
			k := keys[rand.Intn(n)]
			if err := root.Insert(k, val); err != nil {
				b.Error(err)
			}
		}
		root.ComputeCommitment()
	}
}

func randomKeys(n int) [][]byte {
	keys := make([][]byte, n)
	for i := 0; i < n; i++ {
		key := make([]byte, 32)
		rand.Read(key)
		keys[i] = key
	}
	return keys
}

func randomKeysSorted(n int) [][]byte {
	keys := randomKeys(n)
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	return keys
}

func TestNodeSerde(t *testing.T) {
	tree := New(10)
	tree.Insert(zeroKeyTest, testValue)
	tree.Insert(fourtyKeyTest, testValue)
	root := tree.(*InternalNode)
	tc := root.treeConfig

	// Serialize all the nodes
	leaf0 := (root.children[0]).(*LeafNode)
	ls0, err := leaf0.Serialize()
	if err != nil {
		t.Error(err)
	}

	leaf256 := (root.children[256]).(*LeafNode)
	ls256, err := leaf256.Serialize()
	if err != nil {
		t.Error(err)
	}

	rs, err := root.Serialize()
	if err != nil {
		t.Error(err)
	}

	// Now deserialize and re-construct tree
	res, err := ParseNode(ls0, 1, tc)
	if err != nil {
		t.Error(err)
	}
	resLeaf0 := res.(*LeafNode)

	res, err = ParseNode(ls256, 1, tc)
	if err != nil {
		t.Error(err)
	}
	resLeaf256 := res.(*LeafNode)

	res, err = ParseNode(rs, 0, tc)
	if err != nil {
		t.Error(err)
	}
	resRoot := res.(*InternalNode)

	resRoot.children[0] = resLeaf0
	resRoot.children[256] = resLeaf256

	if !isInternalEqual(root, resRoot) {
		t.Error("parsed node not equal")
	}
}

func isInternalEqual(a, b *InternalNode) bool {
	if a.treeConfig.nodeWidth != b.treeConfig.nodeWidth {
		return false
	}

	for i := 0; i < a.treeConfig.nodeWidth; i++ {
		c := a.children[i]
		switch c.(type) {
		case Empty:
			if _, ok := b.children[i].(Empty); !ok {
				return false
			}
		case *HashedNode:
			hn, ok := b.children[i].(*HashedNode)
			if !ok {
				return false
			}
			if !bytes.Equal(c.(*HashedNode).hash.Bytes(), hn.hash.Bytes()) {
				return false
			}
		case *LeafNode:
			ln, ok := b.children[i].(*LeafNode)
			if !ok {
				return false
			}
			if !isLeafEqual(c.(*LeafNode), ln) {
				return false
			}
		case *InternalNode:
			in, ok := b.children[i].(*InternalNode)
			if !ok {
				return false
			}
			if !isInternalEqual(c.(*InternalNode), in) {
				return false
			}
		}
	}

	return true
}

func isLeafEqual(a, b *LeafNode) bool {
	return bytes.Equal(a.key, b.key) && bytes.Equal(a.value, b.value)
}
