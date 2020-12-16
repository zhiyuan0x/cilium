// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package connector

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unsafe"
)

func TestEntryProgInstructions(t *testing.T) {
	mapFD := 0xaabbccdd
	tmp := (*[4]byte)(unsafe.Pointer(&mapFD))
	immProg0 := []byte{
		0x18, 0x12, 0x00, 0x00, tmp[0], tmp[1], tmp[2], tmp[3],
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x85, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
		0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	prog0 := getEntryProgInstructions(mapFD, 0)
	var buf0 bytes.Buffer
	if err := prog0.Marshal(&buf0, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}

	if insnsProg := buf0.Bytes(); !bytes.Equal(insnsProg, immProg0) {
		t.Errorf("Marshalled entry program does not match immediate encoding:\ngot:\n%s\nwant:\n%s",
			hex.Dump(insnsProg), hex.Dump(immProg0))
	}

	immProg1 := []byte{
		0x18, 0x12, 0x00, 0x00, tmp[0], tmp[1], tmp[2], tmp[3],
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xb7, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x85, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
		0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	prog1 := getEntryProgInstructions(mapFD, 1)
	var buf1 bytes.Buffer
	if err := prog1.Marshal(&buf1, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}

	if insnsProg := buf1.Bytes(); !bytes.Equal(insnsProg, immProg1) {
		t.Errorf("Marshalled entry program does not match immediate encoding:\ngot:\n%s\nwant:\n%s",
			hex.Dump(insnsProg), hex.Dump(immProg1))
	}
}
