package main

import (
	"container/heap"
	"sync"
	"time"

	"github.com/petar/GoLLRB/llrb"
)

type HitTrackerItem struct {
	ParentIno  uint64
	ParentBase int64
	Ino        uint64
	Base       int64
	LoadedAt   time.Time
	HeapIdx    int
}

func (i *HitTrackerItem) Equal(to llrb.Item) bool {
	x := to.(*HitTrackerItem)
	if i.ParentIno == x.ParentIno && i.ParentBase == x.ParentBase && i.Ino == x.Ino && i.Base == x.Base {
		return true
	}
	return false
}

// Hit tracker items are sorted by their ino/base only, not their parent.
// We update hits for all parent hints that successfully "predicted" the
// current slab.
func (i *HitTrackerItem) Less(than llrb.Item) bool {
	x := than.(*HitTrackerItem)
	if i.Ino < x.Ino || i.Ino == x.Ino && i.Base < x.Base {
		return true
	}
	return false
}

type HitTrackerHeap []*HitTrackerItem

type SlabHitTracker struct {
	Items       HitTrackerHeap
	Index       *llrb.LLRB
	Mtx         sync.Mutex
	Wg          *sync.WaitGroup
	Stop        <-chan bool
	DecrementFn func(uint64, int64, uint64, int64)
	IncrementFn func(uint64, int64, uint64, int64)
}

func (h HitTrackerHeap) Len() int {
	return len(h)
}

func (h HitTrackerHeap) Less(i, j int) bool {
	return h[i].LoadedAt.Before(h[j].LoadedAt)
}

func (h HitTrackerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].HeapIdx = i
	h[j].HeapIdx = j
}

func (h *HitTrackerHeap) Push(x interface{}) {
	i := x.(*HitTrackerItem)
	i.HeapIdx = len(*h)
	*h = append(*h, i)
}

func (h *HitTrackerHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func NewSlabHitTracker(stop <-chan bool, wg *sync.WaitGroup, incrementFn func(uint64, int64, uint64, int64), decrementFn func(uint64, int64, uint64, int64)) *SlabHitTracker {
	h := &SlabHitTracker{
		Index:       llrb.New(),
		Wg:          wg,
		Stop:        stop,
		IncrementFn: incrementFn,
		DecrementFn: decrementFn,
	}
	heap.Init(&h.Items)
	go h.Purge()
	return h
}

func (h *SlabHitTracker) Purge() {
	defer h.Wg.Done()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-h.Stop:
			logger.Info("SlabHitTracker.Purge: stop received")
			return
		case <-ticker.C:
			now := time.Now()
			h.Mtx.Lock()
			for h.Items.Len() > 0 {
				i := h.Items[0]
				if now.After(i.LoadedAt) {
					i = heap.Pop(&h.Items).(*HitTrackerItem)
					h.Index.Delete(i)
					logger.Infof("SlabHitTracker.Purge: hit tracker %d/%d decremented", i.Ino, i.Base)
					h.DecrementFn(i.ParentIno, i.ParentBase, i.Ino, i.Base)
				} else {
					break
				}
			}
			h.Mtx.Unlock()
		}
	}
}

func (h *SlabHitTracker) Add(parentIno uint64, parentBase int64, ino uint64, base int64, loadedAt time.Time) {
	h.Mtx.Lock()
	defer h.Mtx.Unlock()
	iNew := &HitTrackerItem{
		ParentIno:  parentIno,
		ParentBase: parentBase,
		Ino:        ino,
		Base:       base,
		LoadedAt:   loadedAt,
	}

	found := false
	h.Index.AscendGreaterOrEqual(iNew, func(x llrb.Item) bool {
		i := x.(*HitTrackerItem)
		if i.Ino != ino || i.Base != base {
			return false
		}
		if i.Equal(iNew) {
			found = true
			// Update the loadedAt time if we have it in our
			// tree, and move down in the heap index.
			if i.LoadedAt.After(iNew.LoadedAt) {
				i.LoadedAt = iNew.LoadedAt
				heap.Fix(&h.Items, i.HeapIdx)
			}
			return false
		}
		return true
	})

	if !found {
		heap.Push(&h.Items, iNew)
		h.Index.InsertNoReplace(iNew)
	}
}

func (h *SlabHitTracker) UpdateHits(ino uint64, base int64) {
	iGe := &HitTrackerItem{
		Ino:  ino,
		Base: base,
	}
	h.Mtx.Lock()
	h.Index.AscendGreaterOrEqual(iGe, func(x llrb.Item) bool {
		i := x.(*HitTrackerItem)
		if i.Ino != ino || i.Base != base {
			return false
		}
		h.IncrementFn(i.ParentIno, i.ParentBase, i.Ino, i.Base)
		return true
	})
	h.Mtx.Unlock()
}
