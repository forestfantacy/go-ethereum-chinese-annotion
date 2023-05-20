// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package trie

import "github.com/ethereum/go-ethereum/common"

// ID is the identifier for uniquely identifying a trie.
// trie唯一标识：树根，状态根是解决属于哪个块么？Owner是指属于哪个合约？我认为只要树根就可以了
type ID struct {
	//对应的状态根
	StateRoot common.Hash // The root of the corresponding state(block.root)
	//当前trie所属的合约地址哈希
	Owner common.Hash // The contract address hash which the trie belongs to
	//当前trie的根哈希
	Root common.Hash // The root hash of trie
}

// StateTrieID constructs an identifier for state trie with the provided state root.
func StateTrieID(root common.Hash) *ID {
	return &ID{
		StateRoot: root,
		Owner:     common.Hash{},
		Root:      root,
	}
}

// StorageTrieID constructs an identifier for storage trie which belongs to a certain
// state and contract specified by the stateRoot and owner.
func StorageTrieID(stateRoot common.Hash, owner common.Hash, root common.Hash) *ID {
	return &ID{
		StateRoot: stateRoot,
		Owner:     owner,
		Root:      root,
	}
}

// TrieID constructs an identifier for a standard trie(not a second-layer trie)
// with provided root. It's mostly used in tests and some other tries like CHT trie.
// 指定根构造标识符（标准trie树，非第2层树）
func TrieID(root common.Hash) *ID {
	return &ID{
		StateRoot: root,
		Owner:     common.Hash{},
		Root:      root,
	}
}
