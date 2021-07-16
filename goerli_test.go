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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/go-kzg/bls"
)

func TestGoerliInsertBug(t *testing.T) {
	root := New(8)
	root.InsertOrdered(common.Hex2Bytes("000c9f87eb59996c38b587bb3a5a49b85a64b8b6bb7dd76e87125fe1370071a2"), common.Hex2Bytes("f84b018701d7c17cd98200a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), nil)
	root.InsertOrdered(common.Hex2Bytes("000ca9506198b51956083dabde9b3c5c0c4251b56ea4741396ce02631c4be379"), common.Hex2Bytes("f84b018701d7b0b950b200a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), nil)
	root.InsertOrdered(common.Hex2Bytes("000ca9538ed7e9a5688464cc41c8c5f20af324c76ea78360abe7d57185c23834"), common.Hex2Bytes("f8440180a01a67cc51538c651f63e8d55094b0ae7bca7f623f05a9ff77ca815dd44d5c8322a010b37de11f39e0a372615c70e1d4d7c613937e8f61823d59be9bea62112e175c"), nil)
	expected := common.Hex2Bytes("08deb1e229978cc0fe60ab00acbe75545d82871a6530a0564db4ac3b8f0e195b")

	got := bls.FrTo32(root.ComputeCommitment())

	if !bytes.Equal(got[:], expected) {
		t.Fatalf("incorrect root commitment %x != %x", got, expected)
	}
}
