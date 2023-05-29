// Copyright 2014 The go-ethereum Authors
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

// Package trie implements Merkle Patricia Tries.
package trie

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// Trie is a Merkle Patricia Trie. Use New to create a trie that sits on
// top of a database. Whenever trie performs a commit operation, the generated
// nodes will be gathered and returned in a set. Once the trie is committed,
// it's not usable anymore. Callers have to re-create the trie with new root
// based on the updated trie database.
//
// Trie is not safe for concurrent use.

// Trie 表示字典树：由key转换成path，找到叶子节点上的val

// Merkle Trie 默克尔树：叶子节点存数据，分支节点存哈希值，由hash(子树哈希)而来。最实用的两个场景：
// 1.快速比较两份大数据是否相等，可以从根节点上就直接判断出两份数据是否相同（哪怕一个子数据不同，根节点的哈希值都不同）
// 2.可以做 “Merkle证明”，即在仅通过下载部分数据，而不是整棵树，就能快速判断某数据是否存在，以及其应处的位置是否正确

// Merkle Patricia Trie，MPT树，融合了merkle树和字典树的数据结构
// 高效的数据结构，插入、删除、查询操作的复杂度是log(N)，通过优化字典数实现而来，并且具备将节点持久化到硬盘的功能
// 同时具备merkle树的快速真伪鉴定和存在性检查的功能，通过将每个节点转换成hash，并将节点hash维护成merkle树

// 可以存储键值对 (key-value pair) 的高效数据结构，键、值分别可以是任意的序列化过的字符串

// Trie 使用new方法新建MPT，它位于数据库的顶部。
// 不论什么时候trie执行commit，生成的节点将被收集并以集合的形式返回，一旦提交，它就不再可用了。调用者必须使用基于更新的trie数据库的新根重新创建该trie。
type Trie struct {
	root  node
	owner common.Hash

	// Keep track of the number leaves which have been inserted since the last
	// hashing operation. This number will not directly map to the number of
	// actually unhashed nodes.
	//跟踪自上次哈希操作以来插入的叶子数。这个数字不会直接映射到实际未散列节点的数量。
	unhashed int

	// reader is the handler trie can retrieve nodes from.
	//用于从trie中读取节点
	reader *trieReader

	// tracer is the tool to track the trie changes.
	// It will be reset after each commit operation.
	//用于跟踪trie的变化，每次提交后将重置
	tracer *tracer
}

// newFlag returns the cache flag value for a newly created node.
func (t *Trie) newFlag() nodeFlag {
	return nodeFlag{dirty: true}
}

// Copy returns a copy of Trie.
func (t *Trie) Copy() *Trie {
	return &Trie{
		root:     t.root,
		owner:    t.owner,
		unhashed: t.unhashed,
		reader:   t.reader,
		tracer:   t.tracer.copy(),
	}
}

// New creates the trie instance with provided trie id and the read-only
// database. The state specified by trie id must be available, otherwise
// an error will be returned. The trie root specified by trie id can be
// zero hash or the sha3 hash of an empty string, then trie is initially
// empty, otherwise, the root node must be present in database or returns
// a MissingNodeError if not.
// 创建trie，需要提供trie id和只读数据库
// 由trieid指定的状态必须是可用的，否则将返回错误。
// 由trieid指定的树根可以是零散列或空字符串的sha3散列，则trie初始为空，否则，根节点必须存在于数据库中，否则返回MissingNodeError。
func New(id *ID, db NodeReader) (*Trie, error) {
	reader, err := newTrieReader(id.StateRoot, id.Owner, db)
	if err != nil {
		return nil, err
	}
	trie := &Trie{
		owner:  id.Owner,
		reader: reader,
		tracer: newTracer(),
	}
	//如果树的ID标识指向的根节点不是kong哈希值
	if id.Root != (common.Hash{}) && id.Root != types.EmptyRootHash {
		//根据root hash从底层数据库中加载根节点
		rootnode, err := trie.resolveAndTrack(id.Root[:], nil)
		//根节点未找到报错，所以root hash在db中要提前存在
		if err != nil {
			return nil, err
		}
		//库中trie树根挂在trie.root
		trie.root = rootnode
	}
	return trie, nil
}

// NewEmpty is a shortcut to create empty tree. It's mostly used in tests.
func NewEmpty(db *Database) *Trie {
	tr, _ := New(TrieID(common.Hash{}), db)
	return tr
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration starts at
// the key after the given start key.
// 从start位置开始迭代树节点
func (t *Trie) NodeIterator(start []byte) NodeIterator {
	return newNodeIterator(t, start)
}

// MustGet is a wrapper of Get and will omit any encountered error but just
// print out an error message.
func (t *Trie) MustGet(key []byte) []byte {
	res, err := t.Get(key)
	if err != nil {
		log.Error("Unhandled trie error in Trie.Get", "err", err)
	}
	return res
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) Get(key []byte) ([]byte, error) {
	//在root底下找key
	value, newroot, didResolve, err := t.get(t.root, keybytesToHex(key), 0)
	if err == nil && didResolve {
		t.root = newroot
	}
	return value, err
}

func (t *Trie) get(origNode node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, false, nil
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			// key not found in trie
			return nil, n, false, nil
		}
		//递归查找
		value, newnode, didResolve, err = t.get(n.Val, key, pos+len(n.Key))
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
		}
		return value, n, didResolve, err
	case *fullNode:
		//递归
		value, newnode, didResolve, err = t.get(n.Children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.Children[key[pos]] = newnode
		}
		return value, n, didResolve, err
	case hashNode:
		//加载n到内存
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}
		//递归
		value, newnode, _, err := t.get(child, key, pos)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// MustGetNode is a wrapper of GetNode and will omit any encountered error but
// just print out an error message.
// 返回item
func (t *Trie) MustGetNode(path []byte) ([]byte, int) {
	item, resolved, err := t.GetNode(path)
	if err != nil {
		log.Error("Unhandled trie error in Trie.GetNode", "err", err)
	}
	return item, resolved
}

// GetNode retrieves a trie node by compact-encoded path. It is not possible
// to use keybyte-encoding as the path might contain odd nibbles.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
// 返回item resolved error
func (t *Trie) GetNode(path []byte) ([]byte, int, error) {
	item, newroot, resolved, err := t.getNode(t.root, compactToHex(path), 0)
	if err != nil {
		return nil, resolved, err
	}
	if resolved > 0 {
		t.root = newroot
	}
	if item == nil {
		return nil, resolved, nil
	}
	return item, resolved, nil
}

// 输入：原始节点，压缩路径，位置
// 输出：
func (t *Trie) getNode(origNode node, path []byte, pos int) (item []byte, newnode node, resolved int, err error) {
	// If non-existent path requested, abort
	if origNode == nil {
		return nil, nil, 0, nil
	}
	// If we reached the requested path, return the current node
	if pos >= len(path) {
		// Although we most probably have the original node expanded, encoding
		// that into consensus form can be nasty (needs to cascade down) and
		// time consuming. Instead, just pull the hash up from disk directly.
		//虽然我们很可能已经扩展了原始节点，但把它编码为共识形式可能会很麻烦(需要向下级联)并且很耗时。不如直接从磁盘提取散列。
		var hash hashNode
		if node, ok := origNode.(hashNode); ok {
			hash = node
		} else {
			hash, _ = origNode.cache()
		}
		if hash == nil {
			return nil, origNode, 0, errors.New("non-consensus node")
		}
		blob, err := t.reader.node(path, common.BytesToHash(hash))
		return blob, origNode, 1, err
	}
	// Path still needs to be traversed, descend into children
	//根据类型向下遍历
	switch n := (origNode).(type) {
	//原始节点为值节点，path不合格
	case valueNode:
		// Path prematurely ended, abort
		return nil, nil, 0, nil

	case *shortNode:
		if len(path)-pos < len(n.Key) || !bytes.Equal(n.Key, path[pos:pos+len(n.Key)]) {
			// Path branches off from short node
			return nil, n, 0, nil
		}
		item, newnode, resolved, err = t.getNode(n.Val, path, pos+len(n.Key))
		if err == nil && resolved > 0 {
			n = n.copy()
			n.Val = newnode
		}
		return item, n, resolved, err

	case *fullNode:
		item, newnode, resolved, err = t.getNode(n.Children[path[pos]], path, pos+1)
		if err == nil && resolved > 0 {
			n = n.copy()
			n.Children[path[pos]] = newnode
		}
		return item, n, resolved, err

	case hashNode:
		child, err := t.resolveAndTrack(n, path[:pos])
		if err != nil {
			return nil, n, 1, err
		}
		item, newnode, resolved, err := t.getNode(child, path, pos)
		return item, newnode, resolved + 1, err

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// MustUpdate is a wrapper of Update and will omit any encountered error but
// just print out an error message.
func (t *Trie) MustUpdate(key, value []byte) {
	if err := t.Update(key, value); err != nil {
		log.Error("Unhandled trie error in Trie.Update", "err", err)
	}
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
// 更新key对应的value，如果value空，删除key
func (t *Trie) Update(key, value []byte) error {
	return t.update(key, value)
}

func (t *Trie) update(key, value []byte) error {
	t.unhashed++
	//hex编码key
	k := keybytesToHex(key)
	if len(value) != 0 {
		//返回插入后根节点
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		//更新trie树的根节点
		t.root = n
	} else {
		//从trie中删掉key
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	//key4Debug := string(hexToKeybytes(key)[:])
	//fmt.Printf("key=%s,value=%s\n", key4Debug, value)

	//key为空，do nothing ，直接返回value
	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}
	//判断挂载点的类型
	switch n := n.(type) {
	case *shortNode:
		//得到插入的key与挂载点的key的公共前缀
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		//如果插入key完全包含挂载点key do dogglesworth，直接更新挂载点下
		if matchlen == len(n.Key) {
			//在n的子节点(n.val)下插入，而不是在n下插入，也就是说已经存在以n为前缀的子节点，那就在这个子节点执行插入逻辑
			//insert(n的子节点（前缀do的全节点）， do， glesworth  cat）
			dirty, nn, err := t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
			if !dirty || err != nil {
				return false, n, err
			}
			//新建短节点为根，用它指向nn
			return true, &shortNode{n.Key, nn, t.newFlag()}, nil
		}

		// Otherwise branch out at the index where they differ.
		//新建一个全节点f，2个短节点a和b，ab的key分别为二者原来key的差异部分,f的children下标为差异开始的那个字节

		branch := &fullNode{flags: t.newFlag()}
		var err error
		//t.insert 第1个参数nil，那么结果一定返回一个短节点
		//新建短接点a（prefix=原节点公共前缀,key=原节点后半段，val=原节点val）
		//n.Key[matchlen]，n.Key公共前缀后的第1个字节，也就是设abc abcdef，应该找出d
		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		//新建短接点b（prefix=新插入key公共前缀,key=新插入key后半段，val=新插入val）
		//n.Key[matchlen]，key公共前缀后的第1个字节
		_, branch.Children[key[matchlen]], err = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}

		// Replace this shortNode with the branch if it occurs at index 0.
		//如果在第一位则直接用branch为根，也就是二者没有公共前缀
		if matchlen == 0 {
			return true, branch, nil
		}
		// New branch node is created as a child of the original short node.
		// Track the newly inserted node in the tracer. The node identifier
		// passed is the path from the root node.
		t.tracer.onInsert(append(prefix, key[:matchlen]...))

		// Replace it with a short node leading up to the branch.
		//新建短节点（key=公共前缀，val=branch）为根
		return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil

	case *fullNode:
		//key[0]=g，n.Children[key[0]]表示g指向的短节点，
		//insert(g指向的节点（短节点）， dog， glesworth  cat）
		dirty, nn, err := t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		//指向新建的子节点nn，此时整个key都已经没有公共前缀了，直接取key第1个字节作为子节点索引
		n.Children[key[0]] = nn
		return true, n, nil

	case nil:
		// New short node is created and track it in the tracer. The node identifier
		// passed is the path from the root node. Note the valueNode won't be tracked
		// since it's always embedded in its parent.
		t.tracer.onInsert(prefix)
		//新建短节点 指定key value
		return true, &shortNode{key, value, t.newFlag()}, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		//我们碰到了树中尚未加载的部分。负载并插入节点。这使得所有子节点都位于到该树中值的路径上。
		//根据节点哈希值和路径前缀从底层存储加载节点
		//所以如果n是hashnode，表示n不在当前树中，也就是说trie树默认不存数据，用时从磁盘或db中加载
		rn, err := t.resolveAndTrack(n, prefix)
		//没找到报错
		if err != nil {
			return false, nil, err
		}
		//当前节点rn加载完毕，递归插入key value
		dirty, nn, err := t.insert(rn, prefix, key, value)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// MustDelete is a wrapper of Delete and will omit any encountered error but
// just print out an error message.
func (t *Trie) MustDelete(key []byte) {
	if err := t.Delete(key); err != nil {
		log.Error("Unhandled trie error in Trie.Delete", "err", err)
	}
}

// Delete removes any existing value for key from the trie.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
func (t *Trie) Delete(key []byte) error {
	t.unhashed++
	k := keybytesToHex(key)
	_, n, err := t.delete(t.root, nil, k)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

// delete returns the new root of the trie with key deleted.
// It reduces the trie to minimal form by simplifying
// nodes on the way up after deleting recursively.
// 返回已删除key对应节点的trie树的根
func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		//要删除的key不包含挂载点的key，直接返回。例如：n.key=abc  key=abdfe
		if matchlen < len(n.Key) {
			return false, n, nil // don't replace n on mismatch
		}
		//如果要删除的key正好跟挂载点key，说明要删除的是n
		if matchlen == len(key) {
			// The matched short node is deleted entirely and track
			// it in the deletion set. The same the valueNode doesn't
			// need to be tracked at all since it's always embedded.
			t.tracer.onDelete(prefix)

			//返回nil会让n被删除
			return true, nil, nil // remove n entirely for whole matches
		}
		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		//键比n键长。从子条目中删除剩余的后缀。Child在这里永远不能为nil，因为子树必须包含至少两个键长度大于n.Key的其他值。
		dirty, child, err := t.delete(n.Val, append(prefix, key[:len(n.Key)]...), key[len(n.Key):])
		if !dirty || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// The child shortNode is merged into its parent, track
			// is deleted as well.
			t.tracer.onDelete(append(prefix, n.Key...))

			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			//从子树中删除将其减少到另一个短节点。合并节点以避免创建shortNode{…, shortNode{…}}。使用concat(它总是创建一个新切片)而不是append来避免修改n.k key，因为它可能与其他节点共享。
			return true, &shortNode{concat(n.Key, child.Key...), child.Val, t.newFlag()}, nil
		default:
			return true, &shortNode{n.Key, child, t.newFlag()}, nil
		}

	case *fullNode:
		dirty, nn, err := t.delete(n.Children[key[0]], append(prefix, key[0]), key[1:])
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn

		// Because n is a full node, it must've contained at least two children
		// before the delete operation. If the new child value is non-nil, n still
		// has at least two children after the deletion, and cannot be reduced to
		// a short node.
		if nn != nil {
			return true, n, nil
		}
		// Reduction:
		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		pos := -1
		for i, cld := range &n.Children {
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// If the remaining entry is a short node, it replaces
				// n and its key gets the missing nibble tacked to the
				// front. This avoids creating an invalid
				// shortNode{..., shortNode{...}}.  Since the entry
				// might not be loaded yet, resolve it just for this
				// check.
				cnode, err := t.resolve(n.Children[pos], append(prefix, byte(pos)))
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					// Replace the entire full node with the short node.
					// Mark the original short node as deleted since the
					// value is embedded into the parent now.
					t.tracer.onDelete(append(prefix, byte(pos)))

					k := append([]byte{byte(pos)}, cnode.Key...)
					return true, &shortNode{k, cnode.Val, t.newFlag()}, nil
				}
			}
			// Otherwise, n is replaced by a one-nibble short node
			// containing the child.
			return true, &shortNode{[]byte{byte(pos)}, n.Children[pos], t.newFlag()}, nil
		}
		// n still contains at least two values and cannot be reduced.
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(rn, prefix, key)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key))
	}
}

func concat(s1 []byte, s2 ...byte) []byte {
	r := make([]byte, len(s1)+len(s2))
	copy(r, s1)
	copy(r[len(s1):], s2)
	return r
}

func (t *Trie) resolve(n node, prefix []byte) (node, error) {
	if n, ok := n.(hashNode); ok {
		return t.resolveAndTrack(n, prefix)
	}
	return n, nil
}

// resolveAndTrack loads node from the underlying store with the given node hash
// and path prefix and also tracks the loaded node blob in tracer treated as the
// node's original value. The rlp-encoded blob is preferred to be loaded from
// database because it's easy to decode node while complex to encode node to blob.
// resolveAndTrack使用给定的节点哈希值和路径前缀从底层存储加载节点，并在跟踪器中跟踪加载的节点blob，将其视为节点的原始值。
// rlp编码的blob最好从数据库中加载，因为对节点进行解码比较容易，而将节点编码为blob比较复杂
func (t *Trie) resolveAndTrack(n hashNode, prefix []byte) (node, error) {
	//从底层存储查询
	blob, err := t.reader.node(prefix, common.BytesToHash(n))
	if err != nil {
		return nil, err
	}
	t.tracer.onRead(prefix, blob)
	//解码得到node
	return mustDecodeNode(n, blob), nil
}

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
// /返回树的根哈希值。它不会写入数据库，即使没有，也可以使用。
func (t *Trie) Hash() common.Hash {
	//hash： t.root的hashcode
	//cached： t.root
	hash, cached := t.hashRoot()
	t.root = cached
	return common.BytesToHash(hash.(hashNode))
}

// Commit collects all dirty nodes in the trie and replaces them with the
// corresponding node hash. All collected nodes (including dirty leaves if
// collectLeaf is true) will be encapsulated into a nodeset for return.
// The returned nodeset can be nil if the trie is clean (nothing to commit).
// Once the trie is committed, it's not usable anymore. A new trie must
// be created with new root and updated trie database for following usage
// Commit收集树中的所有脏节点，并用相应的节点哈希替换它们。所有收集到的节点(包括脏叶子，如果collectLeaf为true)将被封装到一个节点集中返回。
// 如果树是干净的(没有要提交的)，返回的节点集可以是nil。一旦提交，它就不再可用了。
// 为了后续使用，必须使用新根创建一个新树和更新trie数据库
func (t *Trie) Commit(collectLeaf bool) (common.Hash, *NodeSet) {
	defer t.tracer.reset()

	//所有被替换的脏节点
	nodes := NewNodeSet(t.owner)
	t.tracer.markDeletions(nodes)

	// Trie is empty and can be classified into two types of situations:
	// - The trie was empty and no update happens
	// - The trie was non-empty and all nodes are dropped
	if t.root == nil {
		return types.EmptyRootHash, nodes
	}
	// Derive the hash for all dirty nodes first. We hold the assumption
	// in the following procedure that all nodes are hashed.
	//首先算一次merkle树，产生旧节点被修改
	rootHash := t.Hash()

	// Do a quick check if we really need to commit. This can happen e.g.
	// if we load a trie for reading storage values, but don't write to it.
	//快速检查是不是真需要执行提交，因为当前trie只读不写
	if hashedNode, dirty := t.root.cache(); !dirty {
		// Replace the root node with the origin hash in order to
		// ensure all resolved nodes are dropped after the commit.
		t.root = hashedNode
		return rootHash, nil
	}
	//收集被修改过的node放入c.nodes，返回并更新trie树的根节点
	t.root = newCommitter(nodes, t.tracer, collectLeaf).Commit(t.root)
	//返回根节点hash和被修改的节点集
	return rootHash, nodes
}

// hashRoot calculates the root hash of the given trie
// 计算给定树的根哈希值
func (t *Trie) hashRoot() (node, node) {
	//根节点为空，返回常量EmptyRootHash
	if t.root == nil {
		return hashNode(types.EmptyRootHash.Bytes()), nil
	}
	// If the number of changes is below 100, we let one thread handle it
	//构建Hasher，如果更改的数量>=100，多线程处理
	h := newHasher(t.unhashed >= 100)
	defer func() {
		//池化Hasher
		returnHasherToPool(h)
		t.unhashed = 0
	}()

	//计算t.root的merkle根
	hashed, cached := h.hash(t.root, true)
	return hashed, cached
}

// Reset drops the referenced root node and cleans all internal state.
func (t *Trie) Reset() {
	t.root = nil
	t.owner = common.Hash{}
	t.unhashed = 0
	t.tracer.reset()
}
