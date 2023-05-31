// Copyright 2021 The go-ethereum Authors
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

package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

//go:generate go run ../../rlp/rlpgen -type StateAccount -out gen_account_rlp.go

// StateAccount is the Ethereum consensus representation of accounts.
// These objects are stored in the main account trie.
// 状态账户：以太坊账户共识状态表示，这些对象存储在主帐户树中
type StateAccount struct {
	//已执行交易总数，用来标示该账户发出的交易数量；
	Nonce uint64
	//持币数量，记录用户的以太币余额；
	Balance *big.Int
	//存储树的根哈希（智能合约账户专有），随着合约的存储区的增加、删除、改动而不断变更
	Root common.Hash // merkle root of the storage trie
	//代码区的哈希值（智能合约账户专有）
	CodeHash []byte
}
