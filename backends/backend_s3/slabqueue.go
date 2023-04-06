package main

import (
	"container/heap"
	"sync"
	"time"
)

type SlabHint struct {
	ParentIno  uint64
	ParentBase int64
	Ino        uint64
	Base       int64
	LoadedAt   time.Time
}

type QueuedSlab struct {
	Slab *SlabHint
	Idx  int
}

type SlabQueue struct {
	Items []*QueuedSlab
	Index map[SlabHint]*QueuedSlab
	Mtx   sync.Mutex
}

func (q SlabQueue) Len() int {
	return len(q.Items)
}

func (q SlabQueue) Less(i, j int) bool {
	return q.Items[i].Slab.LoadedAt.Before(q.Items[j].Slab.LoadedAt)
}

func (q SlabQueue) Swap(i, j int) {
	q.Items[i], q.Items[j] = q.Items[j], q.Items[i]
	q.Items[i].Idx = i
	q.Items[j].Idx = j
}

func (q *SlabQueue) Push(x interface{}) {
	s := x.(*SlabHint)
	k := SlabHint{
		ParentIno:  s.ParentIno,
		ParentBase: s.ParentBase,
		Ino:        s.Ino,
		Base:       s.Base,
	}

	if qs, ok := q.Index[k]; ok {
		if qs.Slab.LoadedAt.After(s.LoadedAt) {
			qs.Slab.LoadedAt = s.LoadedAt
			heap.Fix(q, qs.Idx)
		}
		return
	}

	qs := &QueuedSlab{
		Idx:  len(q.Items),
		Slab: s,
	}
	q.Items = append(q.Items, qs)
	q.Index[k] = qs
}

func (q *SlabQueue) Pop() interface{} {
	qs := q.Items[len(q.Items)-1]
	q.Items = q.Items[0 : len(q.Items)-1]
	idx := SlabHint{
		ParentIno:  qs.Slab.ParentIno,
		ParentBase: qs.Slab.ParentBase,
		Ino:        qs.Slab.Ino,
		Base:       qs.Slab.Base,
	}
	delete(q.Index, idx)
	return qs.Slab
}

func (q *SlabQueue) Remove(i int) *SlabHint {
	s := heap.Remove(q, i).(*SlabHint)
	idx := SlabHint{
		ParentIno:  s.ParentIno,
		ParentBase: s.ParentBase,
		Ino:        s.Ino,
		Base:       s.Base,
	}
	delete(q.Index, idx)
	return s
}

func (q *SlabQueue) Peek() interface{} {
	return q.Items[0].Slab
}

func (q *SlabQueue) Lookup(ino uint64, base int64) *SlabHint {
	s := SlabHint{
		Ino:  ino,
		Base: base,
	}
	if qs, ok := q.Index[s]; ok {
		return qs.Slab
	}
	return nil
}

func (q *SlabQueue) AllSlabs() []SlabHint {
	q.Mtx.Lock()
	defer q.Mtx.Unlock()

	var allSlabs []SlabHint
	for _, slab := range q.Items {
		allSlabs = append(allSlabs, *slab.Slab)
	}
	return allSlabs
}

func NewSlabQueue() SlabQueue {
	s := SlabQueue{
		Index: make(map[SlabHint]*QueuedSlab),
	}
	heap.Init(&s)
	return s
}

func (q *SlabQueue) Empty() {
	q.Mtx.Lock()
	q.Index = make(map[SlabHint]*QueuedSlab)
	q.Items = []*QueuedSlab{}
	heap.Init(q)
	q.Mtx.Unlock()
}

func (q *SlabQueue) Process(claims chan<- SlabHint) {
	now := time.Now()
	q.Mtx.Lock()
	defer q.Mtx.Unlock()
	for q.Len() > 0 {
		slab := q.Peek().(*SlabHint)
		if now.After(slab.LoadedAt) {
			claims <- *(heap.Pop(q).(*SlabHint))
		} else {
			break
		}
	}
}

func (q *SlabQueue) Purge(maxAge time.Duration) {
	now := time.Now()
	q.Mtx.Lock()
	defer q.Mtx.Unlock()

	for q.Len() > 0 {
		hint := q.Peek().(*SlabHint)
		if now.Sub(hint.LoadedAt) > maxAge {
			heap.Pop(q)
		} else {
			break
		}
	}
}
