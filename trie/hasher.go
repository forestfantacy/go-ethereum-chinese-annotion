// Copyright 2016 The go-ethereum Authors
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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

import (
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// hasher is a type used for the trie Hash operation. A hasher has some
// internal preallocated temp space
// 哈希是用于trie哈希操作的类型。散列器有一些内部预分配的临时空间
type hasher struct {
	sha      crypto.KeccakState
	tmp      []byte
	encbuf   rlp.EncoderBuffer
	parallel bool // Whether to use parallel threads when hashing
}

// hasherPool holds pureHashers
var hasherPool = sync.Pool{
	New: func() interface{} {
		return &hasher{
			tmp:    make([]byte, 0, 550), // cap is as large as a full fullNode.
			sha:    sha3.NewLegacyKeccak256().(crypto.KeccakState),
			encbuf: rlp.NewEncoderBuffer(nil),
		}
	},
}

func newHasher(parallel bool) *hasher {
	h := hasherPool.Get().(*hasher)
	h.parallel = parallel
	return h
}

func returnHasherToPool(h *hasher) {
	hasherPool.Put(h)
}

// hash collapses a node down into a hash node, also returning a copy of the
// original node initialized with the computed hash to replace the original one.
// hash将一个节点折叠成哈希节点，返回输入节点n的hashnode以及n本身。
// 折叠的过程就是计算merkle的过程：从下往上逐层计算所有的子节点hash，从而得到自己的hash。同时返回一个原始节点的副本，用计算的哈希值初始化，以取代原始节点。
// 如果是全节点或短节点，继续递归，当遇到最底层的全短节点，计算当前节点的哈希节点，然后往上回归
// 如果是哈希或值节点，返回原值，
func (h *hasher) hash(n node, force bool) (hashed node, cached node) {
	// Return the cached hash if it's available
	//缓存中存在，直接用
	if hash, _ := n.cache(); hash != nil {
		return hash, n
	}
	// Trie not processed yet, walk the children
	//子节点的类型 shortNode fullNode
	switch n := n.(type) {
	case *shortNode:
		//递归子节点，直到最下层的短节点（子节点是值节点或哈希节点）才返回
		collapsed, cached := h.hashShortNodeChildren(n)
		//计算当前短节点的哈希，返回一个hashNode（所以哈希节点通过计算短或全节点的哈希值而来）
		hashed := h.shortnodeToHash(collapsed, force)
		// We need to retain the possibly _not_ hashed node, in case it was too
		// small to be hashed
		//通过类型预言hashNode来判断shortnodeToHash计算结果hashed是否正常
		if hn, ok := hashed.(hashNode); ok {
			cached.flags.hash = hn
		} else {
			cached.flags.hash = nil
		}
		return hashed, cached
	case *fullNode:
		//递归子节点，直到最下层的全节点（子节点是值节点或哈希节点）才返回
		collapsed, cached := h.hashFullNodeChildren(n)
		hashed = h.fullnodeToHash(collapsed, force)
		if hn, ok := hashed.(hashNode); ok {
			cached.flags.hash = hn
		} else {
			cached.flags.hash = nil
		}
		return hashed, cached
	default:
		// Value and hash nodes don't have children so they're left as were
		//直到值节点或hash节点，递归返回
		return n, n
	}
}

// hashShortNodeChildren collapses the short node. The returned collapsed node
// holds a live reference to the Key, and must not be modified.
// The cached
// 返回的折叠节点保存对Key的动态引用，并且不能被修改
func (h *hasher) hashShortNodeChildren(n *shortNode) (collapsed, cached *shortNode) {
	// Hash the short node's child, caching the newly hashed subtree
	//深拷贝出两份短节点
	collapsed, cached = n.copy(), n.copy()
	// Previously, we did copy this one. We don't seem to need to actually
	// do that, since we don't overwrite/reuse keys
	//cached.Key = common.CopyBytes(n.Key)

	//key 编码：原始值、hex值、压缩值
	collapsed.Key = hexToCompact(n.Key)
	// Unless the child is a valuenode or hashnode, hash it
	//value是全节点和短节点 递归hash子节点
	switch n.Val.(type) {
	case *fullNode, *shortNode:
		//n.Val就是n的子节点，h.hash遇到最下层的叶子节点才返回，此时将返回的叶子节点的hash交给父节点的Val （collapsed.Val）
		collapsed.Val, cached.Val = h.hash(n.Val, false)
	}

	return collapsed, cached
}

func (h *hasher) hashFullNodeChildren(n *fullNode) (collapsed *fullNode, cached *fullNode) {
	// Hash the full node's children, caching the newly hashed subtrees
	//深拷贝出两份短节点
	cached = n.copy()
	collapsed = n.copy()
	if h.parallel { //并行
		var wg sync.WaitGroup
		wg.Add(16)
		for i := 0; i < 16; i++ {
			go func(i int) {
				hasher := newHasher(false)
				if child := n.Children[i]; child != nil {
					collapsed.Children[i], cached.Children[i] = hasher.hash(child, false)
				} else {
					collapsed.Children[i] = nilValueNode
				}
				returnHasherToPool(hasher)
				wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		//深度优先，遍历n的17个子节点
		for i := 0; i < 16; i++ {
			if child := n.Children[i]; child != nil {
				//子节点有值，如果是全节点或短节点，继续递归，如果是哈希或值节点，返回原值
				collapsed.Children[i], cached.Children[i] = h.hash(child, false)
			} else {
				//子节点是nil，赋值空值节点
				collapsed.Children[i] = nilValueNode
			}
		}
	}
	return collapsed, cached
}

// shortnodeToHash creates a hashNode from a shortNode. The supplied shortnode
// should have hex-type Key, which will be converted (without modification)
// into compact form for RLP encoding.
// If the rlp data is smaller than 32 bytes, `nil` is returned.
// shortnodeToHash从一个shortNode创建一个hashNode。提供的短节点应该具有十六进制类型的Key，它将被转换(无需修改)压缩成RLP编码的紧凑形式。如果rlp数据小于32字节，则返回' nil '。
func (h *hasher) shortnodeToHash(n *shortNode, force bool) node {
	n.encode(h.encbuf)
	enc := h.encodedBytes()

	if len(enc) < 32 && !force {
		return n // Nodes smaller than 32 bytes are stored inside their parent
	}
	return h.hashData(enc)
}

// shortnodeToHash is used to creates a hashNode from a set of hashNodes, (which
// may contain nil values)
func (h *hasher) fullnodeToHash(n *fullNode, force bool) node {
	n.encode(h.encbuf)
	enc := h.encodedBytes()

	if len(enc) < 32 && !force {
		return n // Nodes smaller than 32 bytes are stored inside their parent
	}
	return h.hashData(enc)
}

// encodedBytes returns the result of the last encoding operation on h.encbuf.
// This also resets the encoder buffer.
//
// All node encoding must be done like this:
//
//	node.encode(h.encbuf)
//	enc := h.encodedBytes()
//
// This convention exists because node.encode can only be inlined/escape-analyzed when
// called on a concrete receiver type.
func (h *hasher) encodedBytes() []byte {
	h.tmp = h.encbuf.AppendToBytes(h.tmp[:0])
	h.encbuf.Reset(nil)
	return h.tmp
}

// hashData hashes the provided data
func (h *hasher) hashData(data []byte) hashNode {
	n := make(hashNode, 32)
	h.sha.Reset()
	h.sha.Write(data)
	h.sha.Read(n)
	return n
}

// proofHash is used to construct trie proofs, and returns the 'collapsed'
// node (for later RLP encoding) as well as the hashed node -- unless the
// node is smaller than 32 bytes, in which case it will be returned as is.
// This method does not do anything on value- or hash-nodes.
func (h *hasher) proofHash(original node) (collapsed, hashed node) {
	switch n := original.(type) {
	case *shortNode:
		sn, _ := h.hashShortNodeChildren(n)
		return sn, h.shortnodeToHash(sn, false)
	case *fullNode:
		fn, _ := h.hashFullNodeChildren(n)
		return fn, h.fullnodeToHash(fn, false)
	default:
		// Value and hash nodes don't have children so they're left as were
		return n, n
	}
}
