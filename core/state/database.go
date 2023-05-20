// Copyright 2017 The go-ethereum Authors
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

package state

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	// Number of codehash->size associations to keep.
	codeSizeCacheSize = 100000

	// Cache size granted for caching clean code.
	codeCacheSize = 64 * 1024 * 1024
)

// Database wraps access to tries and contract code.
// 访问trie树和合约代码的接口
type Database interface {
	// OpenTrie opens the main account trie.
	//打开账户trie树
	OpenTrie(root common.Hash) (Trie, error)

	// OpenStorageTrie opens the storage trie of an account.
	//打开指定账户的trie？
	OpenStorageTrie(stateRoot common.Hash, addrHash, root common.Hash) (Trie, error)

	// CopyTrie returns an independent copy of the given trie.
	CopyTrie(Trie) Trie

	// ContractCode retrieves a particular contract's code.
	//获得合约代码
	ContractCode(addrHash, codeHash common.Hash) ([]byte, error)

	// ContractCodeSize retrieves a particular contracts code's size.
	//获得合约代码大小
	ContractCodeSize(addrHash, codeHash common.Hash) (int, error)

	// DiskDB returns the underlying key-value disk database.
	//返回底层键值数据库
	DiskDB() ethdb.KeyValueStore

	// TrieDB retrieves the low level trie database used for data storage.
	//用于数据存储的低级trie数据库
	TrieDB() *trie.Database
}

// Trie is a Ethereum Merkle Patricia trie.
// Merkle Patricia trie 接口
type Trie interface {
	// GetKey returns the sha3 preimage of a hashed key that was previously used
	// to store a value.
	//
	// TODO(fjl): remove this when StateTrie is removed
	GetKey([]byte) []byte

	// GetStorage returns the value for key stored in the trie. The value bytes
	// must not be modified by the caller. If a node was not found in the database,
	// a trie.MissingNodeError is returned.
	GetStorage(addr common.Address, key []byte) ([]byte, error)

	// GetAccount abstracts an account read from the trie. It retrieves the
	// account blob from the trie with provided account address and decodes it
	// with associated decoding algorithm. If the specified account is not in
	// the trie, nil will be returned. If the trie is corrupted(e.g. some nodes
	// are missing or the account blob is incorrect for decoding), an error will
	// be returned.
	//根据地址获取账户详情
	GetAccount(address common.Address) (*types.StateAccount, error)

	// UpdateStorage associates key with value in the trie. If value has length zero,
	// any existing value is deleted from the trie. The value bytes must not be modified
	// by the caller while they are stored in the trie. If a node was not found in the
	// database, a trie.MissingNodeError is returned.
	UpdateStorage(addr common.Address, key, value []byte) error

	// UpdateAccount abstracts an account write to the trie. It encodes the
	// provided account object with associated algorithm and then updates it
	// in the trie with provided address.
	UpdateAccount(address common.Address, account *types.StateAccount) error

	// DeleteStorage removes any existing value for key from the trie. If a node
	// was not found in the database, a trie.MissingNodeError is returned.
	DeleteStorage(addr common.Address, key []byte) error

	// DeleteAccount abstracts an account deletion from the trie.
	DeleteAccount(address common.Address) error

	// Hash returns the root hash of the trie. It does not write to the database and
	// can be used even if the trie doesn't have one.
	//返回trie树的根哈希值
	Hash() common.Hash

	// Commit collects all dirty nodes in the trie and replace them with the
	// corresponding node hash. All collected nodes(including dirty leaves if
	// collectLeaf is true) will be encapsulated into a nodeset for return.
	// The returned nodeset can be nil if the trie is clean(nothing to commit).
	// Once the trie is committed, it's not usable anymore. A new trie must
	// be created with new root and updated trie database for following usage
	//Commit收集树中所有脏节点，并用对应的节点哈希值替换它们。所有收集到的节点(包括脏叶子，如果collectLeaf为true)将被封装到一个节点集中返回。
	//如果树是干净的(没有要提交的)，返回的节点集可以是nil。一旦提交，它就不再可用了。为了下面的使用，必须使用新的根和更新的trie数据库创建一个新的树
	Commit(collectLeaf bool) (common.Hash, *trie.NodeSet)

	// NodeIterator returns an iterator that returns nodes of the trie. Iteration
	// starts at the key after the given start key.
	NodeIterator(startKey []byte) trie.NodeIterator

	// Prove constructs a Merkle proof for key. The result contains all encoded nodes
	// on the path to the value at key. The value itself is also included in the last
	// node and can be retrieved by verifying the proof.
	//
	// If the trie does not contain a value for key, the returned proof contains all
	// nodes of the longest existing prefix of the key (at least the root), ending
	// with the node that proves the absence of the key.
	//Prove为key构造一个默克尔证明。结果包含到值at key的路径上的所有编码节点。值本身也包含在最后一个节点中，可以通过验证证明来检索。
	//如果trie不包含key的值，则返回的证明包含该键存在的最长前缀的所有节点(至少是根节点)，以证明该键不存在的节点结束。
	Prove(key []byte, fromLevel uint, proofDb ethdb.KeyValueWriter) error
}

// NewDatabase creates a backing store for state. The returned database is safe for
// concurrent use, but does not retain any recent trie nodes in memory. To keep some
// historical state in memory, use the NewDatabaseWithConfig constructor.
func NewDatabase(db ethdb.Database) Database {
	return NewDatabaseWithConfig(db, nil)
}

// NewDatabaseWithConfig creates a backing store for state. The returned database
// is safe for concurrent use and retains a lot of collapsed RLP trie nodes in a
// large memory cache.
func NewDatabaseWithConfig(db ethdb.Database, config *trie.Config) Database {
	return &cachingDB{
		disk:          db,
		codeSizeCache: lru.NewCache[common.Hash, int](codeSizeCacheSize),
		codeCache:     lru.NewSizeConstrainedCache[common.Hash, []byte](codeCacheSize),
		triedb:        trie.NewDatabaseWithConfig(db, config),
	}
}

// NewDatabaseWithNodeDB creates a state database with an already initialized node database.
func NewDatabaseWithNodeDB(db ethdb.Database, triedb *trie.Database) Database {
	return &cachingDB{
		disk:          db,
		codeSizeCache: lru.NewCache[common.Hash, int](codeSizeCacheSize),
		codeCache:     lru.NewSizeConstrainedCache[common.Hash, []byte](codeCacheSize),
		triedb:        triedb,
	}
}

type cachingDB struct {
	disk          ethdb.KeyValueStore
	codeSizeCache *lru.Cache[common.Hash, int]
	codeCache     *lru.SizeConstrainedCache[common.Hash, []byte]
	triedb        *trie.Database
}

// OpenTrie opens the main account trie at a specific root hash.
func (db *cachingDB) OpenTrie(root common.Hash) (Trie, error) {
	tr, err := trie.NewStateTrie(trie.StateTrieID(root), db.triedb)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// OpenStorageTrie opens the storage trie of an account.
func (db *cachingDB) OpenStorageTrie(stateRoot common.Hash, addrHash, root common.Hash) (Trie, error) {
	tr, err := trie.NewStateTrie(trie.StorageTrieID(stateRoot, addrHash, root), db.triedb)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// CopyTrie returns an independent copy of the given trie.
func (db *cachingDB) CopyTrie(t Trie) Trie {
	switch t := t.(type) {
	case *trie.StateTrie:
		return t.Copy()
	default:
		panic(fmt.Errorf("unknown trie type %T", t))
	}
}

// ContractCode retrieves a particular contract's code.
func (db *cachingDB) ContractCode(addrHash, codeHash common.Hash) ([]byte, error) {
	code, _ := db.codeCache.Get(codeHash)
	if len(code) > 0 {
		return code, nil
	}
	code = rawdb.ReadCode(db.disk, codeHash)
	if len(code) > 0 {
		db.codeCache.Add(codeHash, code)
		db.codeSizeCache.Add(codeHash, len(code))
		return code, nil
	}
	return nil, errors.New("not found")
}

// ContractCodeWithPrefix retrieves a particular contract's code. If the
// code can't be found in the cache, then check the existence with **new**
// db scheme.
func (db *cachingDB) ContractCodeWithPrefix(addrHash, codeHash common.Hash) ([]byte, error) {
	code, _ := db.codeCache.Get(codeHash)
	if len(code) > 0 {
		return code, nil
	}
	code = rawdb.ReadCodeWithPrefix(db.disk, codeHash)
	if len(code) > 0 {
		db.codeCache.Add(codeHash, code)
		db.codeSizeCache.Add(codeHash, len(code))
		return code, nil
	}
	return nil, errors.New("not found")
}

// ContractCodeSize retrieves a particular contracts code's size.
func (db *cachingDB) ContractCodeSize(addrHash, codeHash common.Hash) (int, error) {
	if cached, ok := db.codeSizeCache.Get(codeHash); ok {
		return cached, nil
	}
	code, err := db.ContractCode(addrHash, codeHash)
	return len(code), err
}

// DiskDB returns the underlying key-value disk database.
func (db *cachingDB) DiskDB() ethdb.KeyValueStore {
	return db.disk
}

// TrieDB retrieves any intermediate trie-node caching layer.
func (db *cachingDB) TrieDB() *trie.Database {
	return db.triedb
}
