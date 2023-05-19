// Copyright 2015 The go-ethereum Authors
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

package downloader

import "fmt"

// SyncMode represents the synchronisation mode of the downloader.
// It is a uint32 as it is used with atomic operations.
type SyncMode uint32

const (
	// FullSync 完全同步：整个区块链历史
	FullSync SyncMode = iota // Synchronise the entire blockchain history from full blocks
	// SnapSync 快照同步：下载压缩过的快照
	SnapSync // Download the chain and the state via compact snapshots
	// LightSync 轻同步：只下载区块头
	LightSync // Download only the headers and terminate afterwards
)

func (mode SyncMode) IsValid() bool {
	return mode >= FullSync && mode <= LightSync
}

// String implements the stringer interface.
func (mode SyncMode) String() string {
	switch mode {
	case FullSync:
		return "full"
	case SnapSync:
		return "snap"
	case LightSync:
		return "light"
	default:
		return "unknown"
	}
}

func (mode SyncMode) MarshalText() ([]byte, error) {
	switch mode {
	case FullSync:
		return []byte("full"), nil
	case SnapSync:
		return []byte("snap"), nil
	case LightSync:
		return []byte("light"), nil
	default:
		return nil, fmt.Errorf("unknown sync mode %d", mode)
	}
}

func (mode *SyncMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "full":
		*mode = FullSync
	case "snap":
		*mode = SnapSync
	case "light":
		*mode = LightSync
	default:
		return fmt.Errorf(`unknown sync mode %q, want "full", "snap" or "light"`, text)
	}
	return nil
}
