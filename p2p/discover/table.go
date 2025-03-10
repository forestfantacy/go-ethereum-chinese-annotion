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

// Package discover implements the Node Discovery Protocol.
//
// The Node Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.
package discover

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const (
	alpha = 3 // Kademlia concurrency factor
	//每个桶最多放16个节点
	bucketSize = 16 // Kademlia bucket size
	//候补节点列表长度10
	maxReplacements = 10 // Size of per-bucket replacement list

	// We keep buckets for the upper 1/15 of distances because
	// it's very unlikely we'll ever encounter a node that's closer.
	hashBits          = len(common.Hash{}) * 8
	nBuckets          = hashBits / 15       // Number of buckets
	bucketMinDistance = hashBits - nBuckets // Log distance of closest bucket

	// IP address limits.
	//来自相同C类子网最多只能有2个IP
	bucketIPLimit, bucketSubnet = 2, 24 // at most 2 addresses from the same /24
	tableIPLimit, tableSubnet   = 10, 24

	refreshInterval    = 30 * time.Minute
	revalidateInterval = 10 * time.Second
	copyNodesInterval  = 30 * time.Second
	seedMinTableTime   = 5 * time.Minute
	seedCount          = 30
	seedMaxAge         = 5 * 24 * time.Hour
)

// Table is the 'node table', a Kademlia-like index of neighbor nodes. The table keeps
// itself up-to-date by verifying the liveness of neighbors and requesting their node
// records when announcements of a new record version are received.
// 节点表用来存储邻近节点，并保持节点列表始终是最新状态
type Table struct {
	mutex sync.Mutex // protects buckets, bucket content, nursery, rand
	//17个桶
	buckets [nBuckets]*bucket // index of known nodes by distance
	//初始节点
	nursery []*node // bootstrap nodes
	//随机数生成器
	rand *mrand.Rand // source of randomness, periodically reseeded
	//ip限制
	ips netutil.DistinctNetSet

	log log.Logger
	db  *enode.DB // database of known nodes
	//传输层协议
	net transport
	//刷新请求管道：管道里的元素是刷新请求，而请求本身也是管道
	refreshReq chan chan struct{}
	//初始化结束
	initDone chan struct{}
	closeReq chan struct{}
	closed   chan struct{}

	nodeAddedHook func(*node) // for testing
}

// transport is implemented by the UDP transports.
// UDP传输层业务，v4 v5 两种实现
type transport interface {
	//本端节点
	Self() *enode.Node
	RequestENR(*enode.Node) (*enode.Node, error)
	//查找随机节点的邻居
	lookupRandom() []*enode.Node
	//查找本端的邻居
	lookupSelf() []*enode.Node
	ping(*enode.Node) (seq uint64, err error)
}

// bucket contains nodes, ordered by their last activity. the entry
// that was most recently active is the first element in entries.
// K桶用于存一组节点
type bucket struct {
	//在线节点，按活跃时间排序
	entries []*node // live entries, sorted by time of last contact
	//候补节点列表
	replacements []*node // recently seen nodes to be used if revalidation fails
	ips          netutil.DistinctNetSet
}

func newTable(t transport, db *enode.DB, bootnodes []*enode.Node, log log.Logger) (*Table, error) {
	tab := &Table{
		net:        t,
		db:         db,
		refreshReq: make(chan chan struct{}),
		initDone:   make(chan struct{}),
		closeReq:   make(chan struct{}),
		closed:     make(chan struct{}),
		rand:       mrand.New(mrand.NewSource(0)),
		ips:        netutil.DistinctNetSet{Subnet: tableSubnet, Limit: tableIPLimit},
		log:        log,
	}
	if err := tab.setFallbackNodes(bootnodes); err != nil {
		return nil, err
	}
	//初始化空桶，桶里没有节点
	for i := range tab.buckets {
		tab.buckets[i] = &bucket{
			ips: netutil.DistinctNetSet{Subnet: bucketSubnet, Limit: bucketIPLimit},
		}
	}
	//初始化随机数生成器
	tab.seedRand()

	//从数据库和配置中加载种子节点，然后根据节点id把节点加入对应k桶
	tab.loadSeedNodes()

	return tab, nil
}

// 返回当前节点
func (tab *Table) self() *enode.Node {
	return tab.net.Self()
}

// 初始化节点表的随机数源
func (tab *Table) seedRand() {
	var b [8]byte
	crand.Read(b[:])

	tab.mutex.Lock()
	tab.rand.Seed(int64(binary.BigEndian.Uint64(b[:])))
	tab.mutex.Unlock()
}

// ReadRandomNodes fills the given slice with random nodes from the table. The results
// are guaranteed to be unique for a single invocation, no node will appear twice.
// 获取当前节点表中所有的节点，打乱原顺序，放入列表
func (tab *Table) ReadRandomNodes(buf []*enode.Node) (n int) {
	if !tab.isInitDone() {
		return 0
	}
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	//遍历节点表 所有的桶 所有节点
	var nodes []*enode.Node
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			nodes = append(nodes, unwrapNode(n))
		}
	}
	// Shuffle.
	for i := 0; i < len(nodes); i++ {
		j := tab.rand.Intn(len(nodes))
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
	return copy(buf, nodes)
}

// getNode returns the node with the given ID or nil if it isn't in the table.
func (tab *Table) getNode(id enode.ID) *enode.Node {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	//定位桶
	b := tab.bucket(id)

	//顺序扫id
	for _, e := range b.entries {
		if e.ID() == id {
			return unwrapNode(e)
		}
	}
	return nil
}

// close terminates the network listener and flushes the node database.
func (tab *Table) close() {
	close(tab.closeReq)
	<-tab.closed
}

// setFallbackNodes sets the initial points of contact. These nodes
// are used to connect to the network if the table is empty and there
// are no known nodes in the database.
func (tab *Table) setFallbackNodes(nodes []*enode.Node) error {
	for _, n := range nodes {
		if err := n.ValidateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap node %q: %v", n, err)
		}
	}
	tab.nursery = wrapNodes(nodes)
	return nil
}

// isInitDone returns whether the table's initial seeding procedure has completed.
// 节点表初始化加载种子节点是否结束
func (tab *Table) isInitDone() bool {
	select {
	case <-tab.initDone:
		return true
	default:
		return false
	}
}

// 发送重新刷新请求
func (tab *Table) refresh() <-chan struct{} {
	done := make(chan struct{})
	select {
	//给refreshReq发信号，触发refresh
	case tab.refreshReq <- done:
	case <-tab.closeReq:
		close(done)
	}
	return done
}

// loop schedules runs of doRefresh, doRevalidate and copyLiveNodes.
// 节点表的定时任务：保持节点表的最新状态
func (tab *Table) loop() {
	var (
		//定时重新验证
		revalidate = time.NewTimer(tab.nextRevalidateTime())
		//定时重新刷新
		refresh = time.NewTicker(refreshInterval)
		//定时拷贝
		copyNodes = time.NewTicker(copyNodesInterval)
		//重新刷新结束
		refreshDone = make(chan struct{}) // where doRefresh reports completion
		//重新验证结束
		revalidateDone chan struct{} // where doRevalidate reports completion
		//正在刷新过程中的等待列表
		waiting = []chan struct{}{tab.initDone} // holds waiting callers while doRefresh runs
	)

	defer refresh.Stop()
	defer revalidate.Stop()
	defer copyNodes.Stop()

	// Start initial refresh.
	//启动第1次刷新
	go tab.doRefresh(refreshDone)

loop: //定时刷新节点表，每个case是一个阶段，从上往下顺序执行，由多个管道信号量控制顺序
	for {
		select {
		//定时触发，先改变随机数源，启动重新刷新
		case <-refresh.C:
			tab.seedRand()
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}

		// 收到新的刷新请求
		case req := <-tab.refreshReq:
			//先放入等待结束列表
			waiting = append(waiting, req)
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}
		//刷新完毕后，清理等待结束列表中的刷新请求
		case <-refreshDone:
			for _, ch := range waiting {
				close(ch)
			}
			waiting, refreshDone = nil, nil

		//重新验证随机k桶中最后1个节点
		case <-revalidate.C:
			revalidateDone = make(chan struct{})
			go tab.doRevalidate(revalidateDone)
		//重新验证结束
		case <-revalidateDone:
			revalidate.Reset(tab.nextRevalidateTime())
			revalidateDone = nil

		// 定时拷贝存活节点
		case <-copyNodes.C:
			go tab.copyLiveNodes()

		case <-tab.closeReq:
			break loop
		}
	}

	//退出后回收资源
	if refreshDone != nil {
		<-refreshDone
	}
	for _, ch := range waiting {
		close(ch)
	}
	if revalidateDone != nil {
		<-revalidateDone
	}
	close(tab.closed)
}

// doRefresh performs a lookup for a random target to keep buckets full. seed nodes are
// inserted if the table is empty (initial bootstrap or discarded faulty peers).
// 保持节点表的最新状态
func (tab *Table) doRefresh(done chan struct{}) {
	defer close(done)

	// Load nodes from the database and insert
	// them. This should yield a few previously seen nodes that are
	// (hopefully) still alive.

	//从数据库和配置加载种子节点到节点表k桶
	tab.loadSeedNodes()

	// Run self lookup to discover new neighbor nodes.
	//查找自己的邻居节点
	tab.net.lookupSelf()

	// The Kademlia paper specifies that the bucket refresh should
	// perform a lookup in the least recently used bucket. We cannot
	// adhere to this because the findnode target is a 512bit value
	// (not hash-sized) and it is not easily possible to generate a
	// sha3 preimage that falls into a chosen bucket.
	// We perform a few lookups with a random target instead.

	//执行3次随机查找节点
	for i := 0; i < 3; i++ {
		tab.net.lookupRandom()
	}
}

// 加载种子节点：数据库 & 配置
func (tab *Table) loadSeedNodes() {
	//在数据库里查询5天内的30个种子节点
	seeds := wrapNodes(tab.db.QuerySeeds(seedCount, seedMaxAge))
	//与配置的初始节点合并
	seeds = append(seeds, tab.nursery...)
	for i := range seeds {
		seed := seeds[i]
		age := log.Lazy{Fn: func() interface{} { return time.Since(tab.db.LastPongReceived(seed.ID(), seed.IP())) }}
		tab.log.Trace("Found seed node in database", "id", seed.ID(), "addr", seed.addr(), "age", age)
		//把节点放入k桶里
		tab.addSeenNode(seed)
	}
}

// doRevalidate checks that the last node in a random bucket is still live and replaces or
// deletes the node if it isn't.
func (tab *Table) doRevalidate(done chan<- struct{}) {
	defer func() { done <- struct{}{} }()

	last, bi := tab.nodeToRevalidate()
	if last == nil {
		// No non-empty bucket found.
		return
	}

	// Ping the selected node and wait for a pong.
	remoteSeq, err := tab.net.ping(unwrapNode(last))

	// Also fetch record if the node replied and returned a higher sequence number.
	if last.Seq() < remoteSeq {
		n, err := tab.net.RequestENR(unwrapNode(last))
		if err != nil {
			tab.log.Debug("ENR request failed", "id", last.ID(), "addr", last.addr(), "err", err)
		} else {
			last = &node{Node: *n, addedAt: last.addedAt, livenessChecks: last.livenessChecks}
		}
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	b := tab.buckets[bi]
	if err == nil {
		// The node responded, move it to the front.
		last.livenessChecks++
		tab.log.Debug("Revalidated node", "b", bi, "id", last.ID(), "checks", last.livenessChecks)
		tab.bumpInBucket(b, last)
		return
	}
	// No reply received, pick a replacement or delete the node if there aren't
	// any replacements.
	if r := tab.replace(b, last); r != nil {
		tab.log.Debug("Replaced dead node", "b", bi, "id", last.ID(), "ip", last.IP(), "checks", last.livenessChecks, "r", r.ID(), "rip", r.IP())
	} else {
		tab.log.Debug("Removed dead node", "b", bi, "id", last.ID(), "ip", last.IP(), "checks", last.livenessChecks)
	}
}

// nodeToRevalidate returns the last node in a random, non-empty bucket.
func (tab *Table) nodeToRevalidate() (n *node, bi int) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, bi = range tab.rand.Perm(len(tab.buckets)) {
		b := tab.buckets[bi]
		if len(b.entries) > 0 {
			last := b.entries[len(b.entries)-1]
			return last, bi
		}
	}
	return nil, 0
}

func (tab *Table) nextRevalidateTime() time.Duration {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	return time.Duration(tab.rand.Int63n(int64(revalidateInterval)))
}

// copyLiveNodes adds nodes from the table to the database if they have been in the table
// longer than seedMinTableTime.
// 将节点表中存活足够长的节点写入数据库
func (tab *Table) copyLiveNodes() {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	now := time.Now()
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			if n.livenessChecks > 0 && now.Sub(n.addedAt) >= seedMinTableTime {
				tab.db.UpdateNode(unwrapNode(n))
			}
		}
	}
}

// findnodeByID returns the n nodes in the table that are closest to the given id.
// This is used by the FINDNODE/v4 handler.
//
// The preferLive parameter says whether the caller wants liveness-checked results. If
// preferLive is true and the table contains any verified nodes, the result will not
// contain unverified nodes. However, if there are no verified nodes at all, the result
// will contain unverified nodes.
// 根据id查询最近节点，preferLive为true表示只要验证过的节点
func (tab *Table) findnodeByID(target enode.ID, nresults int, preferLive bool) *nodesByDistance {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// Scan all buckets. There might be a better way to do this, but there aren't that many
	// buckets, so this solution should be fine. The worst-case complexity of this loop
	// is O(tab.len() * nresults).
	nodes := &nodesByDistance{target: target}
	liveNodes := &nodesByDistance{target: target}

	//遍历节点表
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			nodes.push(n, nresults)
			if preferLive && n.livenessChecks > 0 {
				liveNodes.push(n, nresults)
			}
		}
	}

	if preferLive && len(liveNodes.entries) > 0 {
		return liveNodes
	}
	return nodes
}

// len returns the number of nodes in the table.
func (tab *Table) len() (n int) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, b := range &tab.buckets {
		n += len(b.entries)
	}
	return n
}

// bucketLen returns the number of nodes in the bucket for the given ID.
func (tab *Table) bucketLen(id enode.ID) int {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	return len(tab.bucket(id).entries)
}

// bucket returns the bucket for the given node ID hash.
// 根据节点id查询桶
func (tab *Table) bucket(id enode.ID) *bucket {
	d := enode.LogDist(tab.self().ID(), id)
	return tab.bucketAtDistance(d)
}

// 根据距离查询桶
func (tab *Table) bucketAtDistance(d int) *bucket {
	if d <= bucketMinDistance {
		return tab.buckets[0]
	}
	return tab.buckets[d-bucketMinDistance-1]
}

// addSeenNode adds a node which may or may not be live to the end of a bucket. If the
// bucket has space available, adding the node succeeds immediately. Otherwise, the node is
// added to the replacements list.
//
// The caller must not hold tab.mutex.
// 根据节点id把节点加入对应k桶，如果桶有空间则直接加入，否则放到候补列表
func (tab *Table) addSeenNode(n *node) {
	if n.ID() == tab.self().ID() {
		return
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	//根据节点id定位到桶
	b := tab.bucket(n.ID())

	//节点已经在桶里直接返回
	if contains(b.entries, n.ID()) {
		// Already in bucket, don't add.
		return
	}

	//当前桶满了，超过16个了，还可以放候补列表
	if len(b.entries) >= bucketSize {
		// Bucket full, maybe add as replacement.
		tab.addReplacement(b, n)
		return
	}

	//IP限制校验不通过，返回
	if !tab.addIP(b, n.IP()) {
		// Can't add: IP limit reached.
		return
	}

	// Add to end of bucket:
	//加桶
	b.entries = append(b.entries, n)
	//之前可能因为桶满了，先放入了候选列表
	b.replacements = deleteNode(b.replacements, n)
	n.addedAt = time.Now()
	if tab.nodeAddedHook != nil {
		tab.nodeAddedHook(n)
	}
}

// addVerifiedNode adds a node whose existence has been verified recently to the front of a
// bucket. If the node is already in the bucket, it is moved to the front. If the bucket
// has no space, the node is added to the replacements list.
//
// There is an additional safety measure: if the table is still initializing the node
// is not added. This prevents an attack where the table could be filled by just sending
// ping repeatedly.
//
// The caller must not hold tab.mutex.
// 将已验证存在的节点放到桶的前端，如果这个节点之前就存在，直接换到最前端位置，如果不存在且桶已没空间，则放入替换列表
func (tab *Table) addVerifiedNode(n *node) {
	if !tab.isInitDone() {
		return
	}
	if n.ID() == tab.self().ID() {
		return
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	b := tab.bucket(n.ID())
	if tab.bumpInBucket(b, n) {
		// Already in bucket, moved to front.
		return
	}
	if len(b.entries) >= bucketSize {
		// Bucket full, maybe add as replacement.
		tab.addReplacement(b, n)
		return
	}
	if !tab.addIP(b, n.IP()) {
		// Can't add: IP limit reached.
		return
	}
	// Add to front of bucket.
	b.entries, _ = pushNode(b.entries, n, bucketSize)
	b.replacements = deleteNode(b.replacements, n)
	n.addedAt = time.Now()
	if tab.nodeAddedHook != nil {
		tab.nodeAddedHook(n)
	}
}

// delete removes an entry from the node table. It is used to evacuate dead nodes.
// 删除节点
func (tab *Table) delete(node *node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	tab.deleteInBucket(tab.bucket(node.ID()), node)
}

// 校验IP
func (tab *Table) addIP(b *bucket, ip net.IP) bool {
	if len(ip) == 0 {
		return false // Nodes without IP cannot be added.
	}
	if netutil.IsLAN(ip) {
		return true
	}
	if !tab.ips.Add(ip) {
		tab.log.Debug("IP exceeds table limit", "ip", ip)
		return false
	}
	if !b.ips.Add(ip) {
		tab.log.Debug("IP exceeds bucket limit", "ip", ip)
		tab.ips.Remove(ip)
		return false
	}
	return true
}

func (tab *Table) removeIP(b *bucket, ip net.IP) {
	if netutil.IsLAN(ip) {
		return
	}
	tab.ips.Remove(ip)
	b.ips.Remove(ip)
}

func (tab *Table) addReplacement(b *bucket, n *node) {
	for _, e := range b.replacements {
		if e.ID() == n.ID() {
			return // already in list
		}
	}
	if !tab.addIP(b, n.IP()) {
		return
	}
	var removed *node
	b.replacements, removed = pushNode(b.replacements, n, maxReplacements)
	if removed != nil {
		tab.removeIP(b, removed.IP())
	}
}

// replace removes n from the replacement list and replaces 'last' with it if it is the
// last entry in the bucket. If 'last' isn't the last entry, it has either been replaced
// with someone else or became active.
// 从替换列表中删除节点
func (tab *Table) replace(b *bucket, last *node) *node {
	if len(b.entries) == 0 || b.entries[len(b.entries)-1].ID() != last.ID() {
		// Entry has moved, don't replace it.
		return nil
	}
	// Still the last entry.
	if len(b.replacements) == 0 {
		tab.deleteInBucket(b, last)
		return nil
	}
	r := b.replacements[tab.rand.Intn(len(b.replacements))]
	b.replacements = deleteNode(b.replacements, r)
	b.entries[len(b.entries)-1] = r
	tab.removeIP(b, last.IP())
	return r
}

// bumpInBucket moves the given node to the front of the bucket entry list
// if it is contained in that list.
// 将指点节点移动到桶的前端位置
func (tab *Table) bumpInBucket(b *bucket, n *node) bool {
	for i := range b.entries {
		if b.entries[i].ID() == n.ID() {
			if !n.IP().Equal(b.entries[i].IP()) {
				// Endpoint has changed, ensure that the new IP fits into table limits.
				tab.removeIP(b, b.entries[i].IP())
				if !tab.addIP(b, n.IP()) {
					// It doesn't, put the previous one back.
					tab.addIP(b, b.entries[i].IP())
					return false
				}
			}
			// Move it to the front.
			copy(b.entries[1:], b.entries[:i])
			b.entries[0] = n
			return true
		}
	}
	return false
}

// 从桶中删除节点
func (tab *Table) deleteInBucket(b *bucket, n *node) {
	b.entries = deleteNode(b.entries, n)
	tab.removeIP(b, n.IP())
}

func contains(ns []*node, id enode.ID) bool {
	for _, n := range ns {
		if n.ID() == id {
			return true
		}
	}
	return false
}

// pushNode adds n to the front of list, keeping at most max items.
// 从最前端插入节点列表
func pushNode(list []*node, n *node, max int) ([]*node, *node) {
	if len(list) < max {
		list = append(list, nil)
	}
	removed := list[len(list)-1]
	copy(list[1:], list)
	list[0] = n
	return list, removed
}

// deleteNode removes n from list.
// 节点列表删除节点
func deleteNode(list []*node, n *node) []*node {
	for i := range list {
		if list[i].ID() == n.ID() {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// nodesByDistance is a list of nodes, ordered by distance to target.
// 根据距离指定节点的距离排序的一组节点
type nodesByDistance struct {
	entries []*node
	target  enode.ID
}

// push adds the given node to the list, keeping the total size below maxElems.
// 往节点列表中添加节点，控制列表总大小不超过上限
func (h *nodesByDistance) push(n *node, maxElems int) {
	ix := sort.Search(len(h.entries), func(i int) bool {
		return enode.DistCmp(h.target, h.entries[i].ID(), n.ID()) > 0
	})

	end := len(h.entries)
	if len(h.entries) < maxElems {
		h.entries = append(h.entries, n)
	}
	if ix < end {
		// Slide existing entries down to make room.
		// This will overwrite the entry we just appended.
		copy(h.entries[ix+1:], h.entries[ix:])
		h.entries[ix] = n
	}
}
