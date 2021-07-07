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
	"github.com/ethereum/go-ethereum/rlp"
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

	if !bytes.Equal(leaf.values[zeroKeyTest[31]][:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf.values[zeroKeyTest[31]][:])
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

	if !bytes.Equal(leaf0.values[zeroKeyTest[31]][:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaf0.values[zeroKeyTest[31]][:])
	}

	if !bytes.Equal(leaff.values[1008][:], testValue) {
		t.Fatalf("did not find correct value in trie %x != %x", testValue, leaff.values[ffx32KeyTest[31]][:])
	}
}

func TestGetTwoLeaves(t *testing.T) {
	root := New(10)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)

	val, err := root.Get(zeroKeyTest, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(val, testValue) {
		t.Fatalf("got a different value from the tree than expected %x != %x", val, testValue)
	}

	val, err = root.Get(oneKeyTest, nil)
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

	expected := common.Hex2Bytes("951dcba37a55b6ca65717e36a8ba9fc9974c1e4959861ee50d6b935da0ecc869fe278b605108d1c346295c4bdefca3df")

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

	expected := common.Hex2Bytes("951dcba37a55b6ca65717e36a8ba9fc9974c1e4959861ee50d6b935da0ecc869fe278b605108d1c346295c4bdefca3df")

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

	expected := common.Hex2Bytes("84651cc7122fcf0e0c6cba8e4f5c0212fc9d257f9fb43ab855c19a2e03396eb0b73720abf0c6d1324dd132f9340bc691")

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

	expected := common.Hex2Bytes("84651cc7122fcf0e0c6cba8e4f5c0212fc9d257f9fb43ab855c19a2e03396eb0b73720abf0c6d1324dd132f9340bc691")

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestComputeRootCommitmentOnlineThreeLeavesFlush(t *testing.T) {
	flushCh := make(chan VerkleNode)
	flush := func(node VerkleNode) {
		flushCh <- node
	}
	go func() {
		root := New(10)
		root.InsertOrdered(zeroKeyTest, testValue, flush)
		root.InsertOrdered(fourtyKeyTest, testValue, flush)
		root.InsertOrdered(ffx32KeyTest, testValue, flush)
		root.(*InternalNode).Flush(flush)
		close(flushCh)
	}()

	count := 0
	for n := range flushCh {
		_, isLeaf := n.(*LeafNode)
		_, isInternal := n.(*InternalNode)
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
	expected := common.Hex2Bytes("a64ec9519659972fdb9d31c4abad5bed33135c0c27eff5d365809d30183785d6813767f2a651ae8642cb699d27bb450d")

	comm := root.ComputeCommitment()
	got := bls.ToCompressedG1(comm)

	if !bytes.Equal(got, expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}

func TestHashToFrTrailingZeroBytes(t *testing.T) {
	h := common.HexToHash("c79e576e0f534a5bbed66b32e5022a9d624b4415779b369a62b2e7a6c3d8e000")
	var out bls.Fr
	hashToFr(&out, h)

	h2 := common.HexToHash("c79e576e0f534a5bbed66b32e5022a9d624b4415779b369a62b2e7a6c3d8e000")
	var expected bls.Fr
	bls.FrFrom32(&expected, h2)

	if !bls.EqualFr(&out, &expected) {
		t.Fatalf("incorrect value received, got %x != %x", out, expected)
	}
}

func TestOffset2key8BitsWide(t *testing.T) {
	key := common.Hex2Bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	for i := 0; i < 32; i++ {
		childId := GetTreeConfig(8).offset2key(key, i*8)
		if childId != uint(i) {
			t.Fatalf("error getting child number in key %d != %d", childId, i)
		}
	}
}

func TestOffset2key10BitsWide(t *testing.T) {
	key := common.Hex2Bytes("00001008030100501807020090280b0300d0380f040110481305015058170601")
	for i := 0; i < 25; i++ {
		childId := GetTreeConfig(10).offset2key(key, i*10)
		if childId != uint(i) {
			t.Fatalf("error getting child number in key %d != %d", childId, i)
		}
	}

	if childIdx := GetTreeConfig(10).offset2key(key, 250); childIdx != 16 {
		t.Fatalf("error getting last child number in key %d != %d", childIdx, 16)
	}
}

func TestComputeRootCommitmentTwoLeaves256(t *testing.T) {
	root := New(8)
	root.Insert(zeroKeyTest, testValue)
	root.Insert(ffx32KeyTest, testValue)
	expected := common.Hex2Bytes("844b3cdb8312b0126b80746477c2b78014f3c9be90bf4b8830d544a4bd4095144993506559a76182e105704eb899e561")

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

	flushCh := make(chan VerkleNode)
	flush := func(node VerkleNode) {
		flushCh <- node
	}
	go func() {
		root := New(10)
		for _, k := range keys {
			root.InsertOrdered(k, value, flush)
		}
		root.(*InternalNode).Flush(flush)
		close(flushCh)
	}()

	count := 0
	leaves := 0
	for n := range flushCh {
		_, isLeaf := n.(*LeafNode)
		_, isInternal := n.(*InternalNode)
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
	if bytes.Equal(bls.ToCompressedG1(copied.ComputeCommitment()), bls.ToCompressedG1(tree.ComputeCommitment())) {
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

func TestDelLeaf(t *testing.T) {
	value := []byte("value")
	key1 := common.Hex2Bytes("0105000000000000000000000000000000000000000000000000000000000000")
	key2 := common.Hex2Bytes("0107000000000000000000000000000000000000000000000000000000000000")
	key3 := common.Hex2Bytes("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New(8)
	tree.Insert(key1, value)
	tree.Insert(key2, value)
	hash := tree.Hash()

	tree.Insert(key3, value)
	if err := tree.Delete(key3); err != nil {
		t.Error(err)
	}

	postHash := tree.Hash()
	if !bytes.Equal(hash.Bytes(), postHash.Bytes()) {
		t.Error("deleting leaf resulted in unexpected tree")
	}

	res, err := tree.Get(key3, nil)
	if err != nil {
		t.Error(err)
	}
	if res != nil {
		t.Error("leaf hasnt been deleted")
	}
}

func TestDeleteNonExistent(t *testing.T) {
	value := []byte("value")
	key1 := common.Hex2Bytes("0105000000000000000000000000000000000000000000000000000000000000")
	key2 := common.Hex2Bytes("0107000000000000000000000000000000000000000000000000000000000000")
	key3 := common.Hex2Bytes("0405000000000000000000000000000000000000000000000000000000000000")
	tree := New(8)
	tree.Insert(key1, value)
	tree.Insert(key2, value)
	if err := tree.Delete(key3); err != errDeleteNonExistent {
		t.Error("should fail to delete non-existent key")
	}
}

func TestDeletePrune(t *testing.T) {
	value := []byte("value")
	key1 := common.Hex2Bytes("0105000000000000000000000000000000000000000000000000000000000000")
	key2 := common.Hex2Bytes("0107000000000000000000000000000000000000000000000000000000000000")
	key3 := common.Hex2Bytes("0405000000000000000000000000000000000000000000000000000000000000")
	key4 := common.Hex2Bytes("0407000000000000000000000000000000000000000000000000000000000000")
	tree := New(8)
	tree.Insert(key1, value)
	tree.Insert(key2, value)

	hash1 := tree.Hash()
	tree.Insert(key3, value)
	hash2 := tree.Hash()
	tree.Insert(key4, value)

	if err := tree.Delete(key4); err != nil {
		t.Error(err)
	}
	postHash := tree.Hash()
	if !bytes.Equal(hash2.Bytes(), postHash.Bytes()) {
		t.Error("deleting leaf resulted in unexpected tree")
	}

	if err := tree.Delete(key3); err != nil {
		t.Error(err)
	}
	postHash = tree.Hash()
	if !bytes.Equal(hash1.Bytes(), postHash.Bytes()) {
		t.Error("deleting leaf resulted in unexpected tree")
	}
}

var (
	emptyCodeHash = common.Hex2Bytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
	emptyRootHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // merkle root of the storage trie
	CodeHash []byte
}

func TestDevnet0PostMortem(t *testing.T) {
	t.Skip()
	addr1 := common.Hex2Bytes("3e47cd08ea12b4dfcf5210e3ef3827471994d49b")
	addr2 := common.Hex2Bytes("617661d148a52bef51a268c728b3a21b58f94306")
	balance1, _ := big.NewInt(0).SetString("100000000000000000000", 10)
	balance2, _ := big.NewInt(0).SetString("1000003506000000000000000000", 10)
	account1 := Account{
		Nonce:    0,
		Balance:  balance1,
		Root:     emptyRootHash,
		CodeHash: emptyCodeHash,
	}
	account2 := Account{
		Nonce:    1,
		Balance:  balance2,
		Root:     emptyRootHash,
		CodeHash: emptyCodeHash,
	}

	var buf1, buf2 bytes.Buffer
	tree := New(8)
	rlp.Encode(&buf1, &account1)
	tree.Insert(addr1, buf1.Bytes())
	rlp.Encode(&buf2, &account2)
	tree.Insert(addr2, buf2.Bytes())

	tree.ComputeCommitment()

	block1803Hash := tree.Hash()
	if !bytes.Equal(block1803Hash[:], common.Hex2Bytes("74eb37a063c4c8806716d59816487c32315861d32f5f7697a9aaef5cfe964b9c")) {
		t.Fatalf("error, got %x != 74eb37a063c4c8806716d59816487c32315861d32f5f7697a9aaef5cfe964b9c", block1803Hash)
	}

	buf1.Reset()
	account1.Balance.SetString("199000000000000000000", 10)
	rlp.Encode(&buf1, &account1)
	tree.Insert(addr1, buf1.Bytes())
	buf2.Reset()
	account2.Nonce = 4
	account2.Balance.SetString("1000003587000000000000000000", 10)
	rlp.Encode(&buf2, &account2)
	tree.Insert(addr2, buf2.Bytes())

	tree.ComputeCommitment()

	block1893Hash := tree.Hash()
	if !bytes.Equal(block1893Hash[:], common.Hex2Bytes("55938f57d4211b306eb3a1404d4784b2e0a8fdb254f284834b3ccf74791e54ee")) {
		t.Fatalf("error, got %x != 55938f57d4211b306eb3a1404d4784b2e0a8fdb254f284834b3ccf74791e54ee", block1803Hash)
	}
}

func TestConcurrentTrees(t *testing.T) {
	value := []byte("value")
	tree := New(10)
	tree.Insert(zeroKeyTest, value)
	expected := tree.Hash()

	threads := 2
	ch := make(chan common.Hash)
	builder := func() {
		tree := New(10)
		tree.Insert(zeroKeyTest, value)
		ch <- tree.Hash()
	}

	for i := 0; i < threads; i++ {
		go builder()
	}

	for i := 0; i < threads; i++ {
		root := <-ch
		if !bytes.Equal(root.Bytes(), expected.Bytes()) {
			t.Error("Incorrect root")
		}
	}
}

func TestConcurrentMulG1(t *testing.T) {
	var fr bls.Fr
	bls.AsFr(&fr, 2)
	expected := new(bls.G1Point)
	bls.MulG1(expected, &bls.GenG1, &fr)

	threads := 10
	ch := make(chan *bls.G1Point)
	builder := func() {
		var fr bls.Fr
		bls.AsFr(&fr, 2)
		dst := new(bls.G1Point)
		bls.MulG1(dst, &bls.GenG1, &fr)
		ch <- dst
	}

	for i := 0; i < threads; i++ {
		go builder()
	}

	for i := 0; i < threads; i++ {
		res := <-ch
		if res.String() != expected.String() {
			t.Error("Incorrect fr")
		}
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

func TestMainnetStart(t *testing.T) {
	tree := New(10)
	type KV struct {
		key   string
		value string
	}

	kvs := []KV{
		{
			"00000013653234c2d78dcdc645c5141e358ef2e590fe5278778ba729ff5ffd95",
			"f84b01871c2decb3cd3400a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			"0000008c38d769d75c1ad1de6660da51edc10394c11c50ff9a0ca9e8b8b35dc2",
			"f84a0986825807966613a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			"000000a55a3faa6b402bf3ac46a382c003ca1f9d21177dc31008bab92bdf1529",
			"f8440180a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a01d93f60f105899172f7255c030301c3af4564edd4a48577dbdc448aec7ddb0ac",
		},
		{
			"000000cd919b672081922775cc5884e4e1cd795a2bbbd9473f16c7a44ad98b40",
			"f84c808802069e3c5b1d6800a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			"000000d88546b028daa8674473bb11f665ee45f3962d4887bbce611f5d9f2edf", "f84b0387023a8ff9da7800a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
	}

	for _, kv := range kvs {
		key := common.Hex2Bytes(kv.key)
		value := common.Hex2Bytes(kv.value)
		tree.InsertOrdered(key, value, nil)
	}

	h := tree.Hash()

	if !bytes.Equal(h[:], common.Hex2Bytes("cebf76a3acc9cfb1d880c480fc85e868a4c346698d239e409c3446a2c1fdb334")) {
		t.Fatalf("invalid hash: %x", h)
	}
}

func TestNodeSerde(t *testing.T) {
	width := 10
	tree := New(width)
	tree.Insert(zeroKeyTest, testValue)
	tree.Insert(fourtyKeyTest, testValue)
	root := tree.(*InternalNode)

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
	res, err := ParseNode(ls0, 1, width)
	if err != nil {
		t.Error(err)
	}
	resLeaf0 := res.(*LeafNode)

	res, err = ParseNode(ls256, 1, width)
	if err != nil {
		t.Error(err)
	}
	resLeaf256 := res.(*LeafNode)

	res, err = ParseNode(rs, 0, width)
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
	if !bytes.Equal(a.key, b.key) {
		return false
	}

	for i, v := range a.values {
		if !bytes.Equal(v, b.values[i]) {
			return false
		}
	}

	return true
}
