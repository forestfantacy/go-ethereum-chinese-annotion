// Copyright 2020 The go-ethereum Authors
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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// leaf represents a trie leaf node
type leaf struct {
	blob   []byte      // raw blob of leaf
	parent common.Hash // the hash of parent node
}

// committer is the tool used for the trie Commit operation. The committer will
// capture all dirty nodes during the commit process and keep them cached in
// insertion order.
// 捕获所有脏节点，并按插入顺序缓存它们。
type committer struct {
	nodes       *NodeSet
	tracer      *tracer
	collectLeaf bool
}

// newCommitter creates a new committer or picks one from the pool.
func newCommitter(nodeset *NodeSet, tracer *tracer, collectLeaf bool) *committer {
	return &committer{
		nodes:       nodeset,
		tracer:      tracer,
		collectLeaf: collectLeaf,
	}
}

// Commit collapses a node down into a hash node.
func (c *committer) Commit(n node) hashNode {
	return c.commit(nil, n).(hashNode)
}

// commit collapses a node down into a hash node and returns it.
func (c *committer) commit(path []byte, n node) node {
	// if this path is clean, use available cached data
	hash, dirty := n.cache()
	if hash != nil && !dirty {
		return hash
	}
	// Commit children, then parent, and remove the dirty flag.
	switch cn := n.(type) {
	case *shortNode:
		// Commit child
		collapsed := cn.copy()

		// If the child is fullNode, recursively commit,
		// otherwise it can only be hashNode or valueNode.
		//子节点是全节点则递归调用c.commit
		if _, ok := cn.Val.(*fullNode); ok {
			collapsed.Val = c.commit(append(path, cn.Key...), cn.Val)
		}
		// The key needs to be copied, since we're adding it to the
		// modified nodeset.
		collapsed.Key = hexToCompact(cn.Key)
		//将collapsed添加到已修改数据集
		hashedNode := c.store(path, collapsed)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn
		}
		return collapsed
	case *fullNode:
		//递归提交
		hashedKids := c.commitChildren(path, cn)
		collapsed := cn.copy()
		collapsed.Children = hashedKids
		//添加到已修改数据集
		hashedNode := c.store(path, collapsed)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn
		}
		return collapsed
	case hashNode:
		return cn
	default:
		// nil, valuenode shouldn't be committed
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// commitChildren commits the children of the given fullnode
func (c *committer) commitChildren(path []byte, n *fullNode) [17]node {
	var children [17]node
	for i := 0; i < 16; i++ {
		child := n.Children[i]
		if child == nil {
			continue
		}
		// If it's the hashed child, save the hash value directly.
		// Note: it's impossible that the child in range [0, 15]
		// is a valueNode.
		if hn, ok := child.(hashNode); ok {
			children[i] = hn
			continue
		}
		// Commit the child recursively and store the "hashed" value.
		// Note the returned node can be some embedded nodes, so it's
		// possible the type is not hashNode.
		children[i] = c.commit(append(path, byte(i)), child)
	}
	// For the 17th child, it's possible the type is valuenode.
	if n.Children[16] != nil {
		children[16] = n.Children[16]
	}
	return children
}

// store hashes the node n and adds it to the modified nodeset. If leaf collection
// is enabled, leaf nodes will be tracked in the modified nodeset as well.
// 对n计算哈希并构造新节点，然后将其添加到修改后的节点集c.nodes。如果启用了叶节点收集，则也跟踪叶节点。
func (c *committer) store(path []byte, n node) node {
	// Larger nodes are replaced by their hash and stored in the database.
	var hash, _ = n.cache()

	// This was not generated - must be a small node stored in the parent.
	// In theory, we should check if the node is leaf here (embedded node
	// usually is leaf node). But small value (less than 32bytes) is not
	// our target (leaves in account trie only).
	if hash == nil {
		// The node is embedded in its parent, in other words, this node
		// will not be stored in the database independently, mark it as
		// deleted only if the node was existent in database before.
		prev, ok := c.tracer.accessList[string(path)]
		if ok {
			c.nodes.addNode(path, trienode.NewWithPrev(common.Hash{}, nil, prev))
		}
		return n
	}
	// Collect the dirty node to nodeset for return.
	var (
		nhash = common.BytesToHash(hash)
		node  = trienode.NewWithPrev(
			nhash,
			nodeToBytes(n),
			c.tracer.accessList[string(path)],
		)
	)
	c.nodes.addNode(path, node)

	// Collect the corresponding leaf node if it's required. We don't check
	// full node since it's impossible to store value in fullNode. The key
	// length of leaves should be exactly same.
	if c.collectLeaf {
		if sn, ok := n.(*shortNode); ok {
			if val, ok := sn.Val.(valueNode); ok {
				c.nodes.addLeaf(&leaf{blob: val, parent: nhash})
			}
		}
	}
	return hash
}

// mptResolver the children resolver in merkle-patricia-tree.
type mptResolver struct{}

// ForEach implements childResolver, decodes the provided node and
// traverses the children inside.
func (resolver mptResolver) forEach(node []byte, onChild func(common.Hash)) {
	forGatherChildren(mustDecodeNodeUnsafe(nil, node), onChild)
}

// forGatherChildren traverses the node hierarchy and invokes the callback
// for all the hashnode children.
func forGatherChildren(n node, onChild func(hash common.Hash)) {
	switch n := n.(type) {
	case *shortNode:
		forGatherChildren(n.Val, onChild)
	case *fullNode:
		for i := 0; i < 16; i++ {
			forGatherChildren(n.Children[i], onChild)
		}
	case hashNode:
		onChild(common.BytesToHash(n))
	case valueNode, nil:
	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}
