// Copyright 2019 The go-ethereum Authors
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

package discover

import (
	"context"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// lookup performs a network search for nodes close to the given target. It approaches the
// target by querying nodes that are closer to it on each iteration. The given target does
// not need to be an actual node identifier.
// 查找指定目标的一组邻近节点，通过多次迭代逐渐接近目标，这个目标节点可以不是一个实际的节点
type lookup struct {
	tab *Table
	//查询函数定义了输入目标节点，输出一组节点
	queryfunc func(*node) ([]*node, error)
	//控制查询并发度的信号量
	replyCh  chan []*node
	cancelCh <-chan struct{}
	//已经查询过的节点、已经可见的节点
	asked, seen map[enode.ID]bool
	//自定义类型：根据距离排序的节点组
	result      nodesByDistance
	replyBuffer []*node
	queries     int
}

// 查询函数，输入一个目标节点，输出一组节点（查询结果）
type queryFunc func(*node) ([]*node, error)

// 新建查询
func newLookup(ctx context.Context, tab *Table, target enode.ID, q queryFunc) *lookup {
	it := &lookup{
		tab:       tab,
		queryfunc: q,
		asked:     make(map[enode.ID]bool),
		seen:      make(map[enode.ID]bool),
		result:    nodesByDistance{target: target},
		replyCh:   make(chan []*node, alpha), //3并发
		cancelCh:  ctx.Done(),
		queries:   -1,
	}
	// Don't query further if we hit ourself.
	// Unlikely to happen often in practice.
	//命中自己就直接停，实际发生概率低
	it.asked[tab.self().ID()] = true
	return it
}

// run runs the lookup to completion and returns the closest nodes found.
// 启动查询
func (it *lookup) run() []*enode.Node {
	//持续查询，找到为止
	for it.advance() {
	}
	//返回结果
	return unwrapNodes(it.result.entries)
}

// advance advances the lookup until any new nodes have been found.
// It returns false when the lookup has ended.
// 持续查询直到找到新节点，查找结束返回false
func (it *lookup) advance() bool {
	for it.startQueries() {
		select {
		//收到it.query查询结果
		case nodes := <-it.replyCh:
			// 清空操作  it.replyBuffer = []
			it.replyBuffer = it.replyBuffer[:0]

			for _, n := range nodes {
				if n != nil && !it.seen[n.ID()] {
					//节点可见状态，查到即可见
					it.seen[n.ID()] = true
					//放入结果组（最多16个），作为下轮查询目标
					it.result.push(n, bucketSize)
					//应答节点组
					it.replyBuffer = append(it.replyBuffer, n)
				}
			}
			it.queries--
			//返回结果
			if len(it.replyBuffer) > 0 {
				return true
			}
		//取消查询
		case <-it.cancelCh:
			it.shutdown()
		}
	}
	return false
}

func (it *lookup) shutdown() {
	for it.queries > 0 {
		<-it.replyCh
		it.queries--
	}
	it.queryfunc = nil
	it.replyBuffer = nil
}

// 启动查询，参数来自结果组，结果放入可见组，查询算法来自queryfunc
func (it *lookup) startQueries() bool {
	//具体查询算法必须有值，下面的逻辑是解决查询节点参数和返回处理的问题
	if it.queryfunc == nil {
		return false
	}

	// The first query returns nodes from the local table.
	//首次查询：根据节点id找对应的K桶
	if it.queries == -1 {
		closest := it.tab.findnodeByID(it.result.target, bucketSize, false)
		// Avoid finishing the lookup too quickly if table is empty. It'd be better to wait
		// for the table to fill in this case, but there is no good mechanism for that
		// yet.
		//没找到，暂停1s
		if len(closest.entries) == 0 {
			it.slowdown()
		}
		//查询计数
		it.queries = 1

		//把查询到的结果写入应答管道
		it.replyCh <- closest.entries
		return true
	}

	// Ask the closest nodes that we haven't asked yet.
	//遍历结果节点组，且最多查alpha个节点（并发）
	for i := 0; i < len(it.result.entries) && it.queries < alpha; i++ {
		n := it.result.entries[i]
		//query没查过的节点
		if !it.asked[n.ID()] {
			it.asked[n.ID()] = true
			//计数器递增
			it.queries++
			//并发查询当前节点的邻近节点，查询结果放入可见组
			go it.query(n, it.replyCh)
		}
	}

	// The lookup ends when no more nodes can be asked.
	return it.queries > 0
}

func (it *lookup) slowdown() {
	sleep := time.NewTimer(1 * time.Second)
	defer sleep.Stop()
	select {
	case <-sleep.C:
	case <-it.tab.closeReq:
	}
}

// 根据目标节点查询，查到了把邻近节点放入可见组，没查到落库查询记录，发生错误退出
func (it *lookup) query(n *node, reply chan<- []*node) {
	fails := it.tab.db.FindFails(n.ID(), n.IP())
	//查询算法是在外部回调函数中定义的
	r, err := it.queryfunc(n)

	//发生错误或者没查到
	if errors.Is(err, errClosed) {
		// Avoid recording failures on shutdown.
		reply <- nil
		return
	} else if len(r) == 0 { //没查到
		fails++
		//把查询失败记录到db
		it.tab.db.UpdateFindFails(n.ID(), n.IP(), fails)
		// Remove the node from the local table if it fails to return anything useful too
		// many times, but only if there are enough other nodes in the bucket.
		dropped := false
		if fails >= maxFindnodeFailures && it.tab.bucketLen(n.ID()) >= bucketSize/2 {
			dropped = true
			it.tab.delete(n)
		}
		it.tab.log.Trace("FINDNODE failed", "id", n.ID(), "failcount", fails, "dropped", dropped, "err", err)
	} else if fails > 0 {
		// Reset failure counter because it counts _consecutive_ failures.
		it.tab.db.UpdateFindFails(n.ID(), n.IP(), 0)
	}

	// Grab as many nodes as possible. Some of them might not be alive anymore, but we'll
	// just remove those again during revalidation.
	//抓取尽可能多的节点，放入可见组
	for _, n := range r {
		it.tab.addSeenNode(n)
	}
	//将查询结果写入管道
	reply <- r
}

// lookupIterator performs lookup operations and iterates over all seen nodes.
// When a lookup finishes, a new one is created through nextLookup.
// 查询迭代器
type lookupIterator struct {
	buffer     []*node
	nextLookup lookupFunc
	ctx        context.Context
	cancel     func()
	lookup     *lookup
}

type lookupFunc func(ctx context.Context) *lookup

func newLookupIterator(ctx context.Context, next lookupFunc) *lookupIterator {
	ctx, cancel := context.WithCancel(ctx)
	return &lookupIterator{ctx: ctx, cancel: cancel, nextLookup: next}
}

// Node returns the current node.
func (it *lookupIterator) Node() *enode.Node {
	if len(it.buffer) == 0 {
		return nil
	}
	return unwrapNode(it.buffer[0])
}

// Next moves to the next node.
func (it *lookupIterator) Next() bool {
	// Consume next node in buffer.
	if len(it.buffer) > 0 {
		it.buffer = it.buffer[1:]
	}
	// Advance the lookup to refill the buffer.
	for len(it.buffer) == 0 {
		if it.ctx.Err() != nil {
			it.lookup = nil
			it.buffer = nil
			return false
		}
		if it.lookup == nil {
			it.lookup = it.nextLookup(it.ctx)
			continue
		}
		if !it.lookup.advance() {
			it.lookup = nil
			continue
		}
		it.buffer = it.lookup.replyBuffer
	}
	return true
}

// Close ends the iterator.
func (it *lookupIterator) Close() {
	it.cancel()
}
