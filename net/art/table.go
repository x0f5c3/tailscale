// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package art provides a routing table that implements the Allotment Routing
// Table (ART) algorithm by Donald Knuth, as described in the paper by Yoichi
// Hariguchi.
//
// ART outperforms the traditional radix tree implementations for route lookups,
// insertions, and deletions.
//
// For more information, see Yoichi Hariguchi's paper:
// https://cseweb.ucsd.edu//~varghese/TEACH/cs228/artlookup.pdf
package art

import (
	"bytes"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"strings"
	"sync"
)

const (
	debugInsert = false
	debugDelete = false
)

// Table is an IPv4 and IPv6 routing table.
type Table[T any] struct {
	v4       strideTable[T]
	v6       strideTable[T]
	initOnce sync.Once
}

func (t *Table[T]) init() {
	t.initOnce.Do(func() {
		t.v4.prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		t.v6.prefix = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	})
}

// Get does a route lookup for addr and returns the associated value, or nil if
// no route matched.
func (t *Table[T]) Get(addr netip.Addr) *T {
	t.init()
	st := &t.v4
	if addr.Is6() {
		st = &t.v6
	}

	i := 0
	bs := addr.AsSlice()
	// With path compression, we might skip over some address bits while walking
	// to a strideTable leaf. This means the leaf answer we find might not be
	// correct, because path compression took us down the wrong subtree. When
	// that happens, we have to backtrack and figure out which most specific
	// route further up the tree is relevant to addr, and return that.
	//
	// So, as we walk down the stride tables, each time we find a non-nil route
	// result, we have to remember it and the associated strideTable prefix.
	//
	// We could also deal with this edge case of path compression by checking
	// the strideTable prefix on each table as we descend, but that means we
	// have to pay N prefix.Contains checks on every route lookup (where N is
	// the number of strideTables in the path), rather than only paying M prefix
	// comparisons in the edge case (where M is the number of strideTables in
	// the path with a non-nil route of their own).
	strideIdx := 0
	stridePrefixes := [16]netip.Prefix{}
	strideRoutes := [16]*T{}
findLeaf:
	for {
		rt, child := st.getValAndChild(bs[i])
		if rt != nil {
			// This strideTable contains a route that may be relevant to our
			// search, remember it.
			stridePrefixes[strideIdx] = st.prefix
			strideRoutes[strideIdx] = rt
			strideIdx++
		}
		if child == nil {
			// No sub-routes further down, the last thing we recorded in
			// strideRoutes is tentatively the result, barring path compression
			// misdirection.
			break findLeaf
		}
		st = child
		// Path compression means we may be skipping over some intermediate
		// tables. We have to skip forward to whatever depth st now references.
		i = st.prefix.Bits() / 8
	}

	// Walk backwards through the hits we recorded in strideRoutes and
	// stridePrefixes, returning the first one whose subtree matches addr.
	//
	// In the common case where path compression did not mislead us, we'll
	// return on the first loop iteration because the last route we recorded was
	// the correct most-specific route.
	for strideIdx > 0 {
		strideIdx--
		if stridePrefixes[strideIdx].Contains(addr) {
			return strideRoutes[strideIdx]
		}
	}

	// We either found no route hits at all (both previous loops terminated
	// immediately), or we went on a wild goose chase down a compressed path for
	// the wrong prefix, and also found no usable routes on the way back up to
	// the root. This is a miss.
	return nil
}

// Insert adds pfx to the table, with value val.
// If pfx is already present in the table, its value is set to val.
func (t *Table[T]) Insert(pfx netip.Prefix, val *T) {
	t.init()
	if val == nil {
		panic("Table.Insert called with nil value")
	}

	if debugInsert {
		defer func() {
			fmt.Printf("%s", t.debugSummary())
		}()
	}

	// The standard library doesn't enforce normalized prefixes (where
	// the non-prefix bits are all zero). Our algorithms all require
	// normalized prefixes though, so do it upfront.
	pfx = pfx.Masked()

	if debugInsert {
		fmt.Printf("\ninsert: start pfx=%s\n", pfx)
	}

	st := &t.v4
	if pfx.Addr().Is6() {
		st = &t.v6
	}

	// This algorithm is full of off-by-one headaches that boil down
	// to the fact that pfx.Bits() has (2^n)+1 values, rather than
	// just 2^n. For example, an IPv4 prefix length can be 0 through
	// 32, which is 33 values.
	//
	// This extra possible value creates all kinds of headaches as we
	// do bits and bytes math to traverse strideTables below. So, we
	// treat the default route 0/0 specially here, that way the rest
	// of the logic goes back to having 2^n values to reason about,
	// which can be done in a nice and regular fashion with no edge
	// cases.
	if pfx.Bits() == 0 {
		if debugInsert {
			fmt.Printf("insert: default route\n")
		}
		st.insert(0, 0, val)
		return
	}

	bs := pfx.Addr().AsSlice()

	// No matter what we do as we traverse strideTables, our final
	// action will be to insert the last 1-8 bits of pfx into a
	// strideTable somewhere.
	//
	// We calculate upfront the byte position in bs of the end of the
	// prefix; the number of bits within that byte that contain prefix
	// data; and the prefix owned by the strideTable into which we'll
	// eventually insert.
	//
	// We need this in a couple different branches of the code below,
	// and because the possible values are 1-indexed (1 through 32 for
	// ipv4, 1 through 128 for ipv6), the math is very slightly
	// unusual to account for the off-by-one indexing. Do it once up
	// here, with this large comment, rather than reproduce the subtle
	// math in multiple places further down.
	finalByteIdx := (pfx.Bits() - 1) / 8
	finalBits := pfx.Bits() - (finalByteIdx * 8)
	finalStridePrefix := mustPrefix(pfx.Addr(), finalByteIdx*8)
	if debugInsert {
		fmt.Printf("insert: finalByteIdx=%d finalBits=%d finalStridePrefix=%s\n", finalByteIdx, finalBits, finalStridePrefix)
	}

	// The strideTable we want to insert into is potentially at the
	// end of a chain of strideTables, each one encoding 8 bits of the
	// prefix.
	//
	// We're expecting to walk down a path of tables, although with
	// prefix compression we may end up skipping some links in the
	// chain, or taking wrong turns and having to course correct.
	//
	// As we walk down the tree, byteIdx is the byte of bs we're
	// currently examining to choose our next step, and numBits is the
	// number of bits that remain in pfx, starting with the byte at
	// byteIdx inclusive.
	byteIdx := 0
	numBits := pfx.Bits()
	for {
		if debugInsert {
			fmt.Printf("insert: loop byteIdx=%d numBits=%d st.prefix=%s\n", byteIdx, numBits, st.prefix)
		}
		if numBits <= 8 {
			if debugInsert {
				fmt.Printf("insert: existing leaf st.prefix=%s addr=%d/%d\n", st.prefix, bs[finalByteIdx], finalBits)
			}
			// We've reached the end of the prefix, whichever
			// strideTable we're looking at now is the place where we
			// need to insert.
			st.insert(bs[finalByteIdx], finalBits, val)
			return
		}

		// Otherwise, we need to go down at least one more level of
		// strideTables. With prefix compression, each level of
		// descent can have one of three outcomes: we find a place
		// where prefix compression is possible; a place where prefix
		// compression made us take a "wrong turn"; or a point along
		// our intended path that we have to keep following.
		child, created := st.getOrCreateChild(bs[byteIdx])
		switch {
		case created:
			// The subtree we need for pfx doesn't exist yet. The rest
			// of the path, if we were to create it, will consist of a
			// bunch of strideTables with a single child. We can use
			// path compression to elide those intermediates, and jump
			// straight to the final strideTable that hosts this
			// prefix.
			child.prefix = finalStridePrefix
			child.insert(bs[finalByteIdx], finalBits, val)
			if debugInsert {
				fmt.Printf("insert: new leaf st.prefix=%s child.prefix=%s addr=%d/%d\n", st.prefix, child.prefix, bs[finalByteIdx], finalBits)
			}
			return
		case child.prefix == pfx:
			// Edge case, /16 vs. /24
			// Still fucked, rerun TestDeleteCompare to figure out why
			intermediatePrefix, _ := pfx.Addr().Prefix(pfx.Bits() - 8)
			intermediate := &strideTable[T]{prefix: intermediatePrefix}
			st.setChild(bs[byteIdx], intermediate)
			intermediate.setChild(bs[child.prefix.Bits()/8], child)
			intermediate.insert(bs[finalByteIdx], finalBits, val)
			return
		case !prefixContains(child.prefix, pfx):
			// child already exists, but its prefix does not contain
			// pfx. This means that the path between st and child was
			// compressed by a previous insertion, and somewhere in
			// the (implicit) compressed path we took a wrong turn,
			// into the wrong part of st's subtree.
			//
			// This is okay, because pfx and child.prefix must have a
			// common ancestor node somewhere between st and child. We
			// can figure out what node that is, materialize it
			// between st and child, and resume from there.
			intermediatePrefix, addrOfExisting, addrOfNew := computePrefixSplit(child.prefix, pfx)
			intermediate := &strideTable[T]{prefix: intermediatePrefix} // TODO: make this whole thing be st.AddIntermediate or something?
			st.setChild(bs[byteIdx], intermediate)
			intermediate.setChild(addrOfExisting, child)

			if debugInsert {
				fmt.Printf("insert: new intermediate st.prefix=%s intermediate.prefix=%s child.prefix=%s\n", st.prefix, intermediate.prefix, child.prefix)
			}

			// Now, we have a chain of st -> intermediate -> child.
			//
			// pfx either lives in a different child of intermediate,
			// or in intermediate itself. For example, if we created
			// the intermediate 1.2.0.0/16, pfx=1.2.3.4/32 would have
			// to go into a new child of intermediate, but
			// pfx=1.2.0.0/18 would go into intermediate directly.
			if remain := pfx.Bits() - intermediate.prefix.Bits(); remain <= 8 {
				if debugInsert {
					fmt.Printf("insert: into intermediate intermediate.prefix=%s addr=%d/%d\n", intermediate.prefix, bs[finalByteIdx], finalBits)
				}
				// pfx lives in intermediate.
				intermediate.insert(bs[finalByteIdx], finalBits, val)
			} else {
				// pfx lives in a different child subtree of
				// intermediate. By definition this subtree doesn't
				// exist at all, otherwise we'd never have entereed
				// this entire "wrong turn" codepath in the first
				// place.
				//
				// This means we can apply prefix compression as we
				// create this new child, and we're done.
				st, created = intermediate.getOrCreateChild(addrOfNew)
				if !created {
					panic("new child path unexpectedly exists during path decompression")
				}
				st.prefix = finalStridePrefix
				st.insert(bs[finalByteIdx], finalBits, val)
				if debugInsert {
					fmt.Printf("insert: new child st.prefix=%s addr=%d/%d\n", st.prefix, bs[finalByteIdx], finalBits)
				}
			}
			return
		default:
			// An expected child table exists along pfx's
			// path. Continue traversing downwards.
			st = child
			byteIdx = child.prefix.Bits() / 8
			numBits = pfx.Bits() - child.prefix.Bits()
			if debugInsert {
				fmt.Printf("insert: descend st.prefix=%s\n", st.prefix)
			}
		}
	}
}

// Delete removes pfx from the table, if it is present.
func (t *Table[T]) Delete(pfx netip.Prefix) {
	t.init()

	// The standard library doesn't enforce normalized prefixes (where
	// the non-prefix bits are all zero). Our algorithms all require
	// normalized prefixes though, so do it upfront.
	pfx = pfx.Masked()

	if debugDelete {
		defer func() {
			fmt.Printf("%s", t.debugSummary())
		}()
		fmt.Printf("\ndelete: start pfx=%s table:\n%s", pfx, t.debugSummary())
	}

	st := &t.v4
	if pfx.Addr().Is6() {
		st = &t.v6
	}

	// Deletion may drive the refcount of some strideTables down to
	// zero. We need to clean up these dangling tables, so we have to
	// keep track of which tables we touch on the way down, and which
	// strideEntry index each child is registered in.
	strideIdx := 0
	strideTables := [16]*strideTable[T]{st}
	strideIndexes := [16]int{}

	// Similar to Insert, navigate down the tree of strideTables,
	// looking for the one that houses this prefix. This part is
	// easier than with insertion, since we can bail if the path ends
	// early or takes an unexpected detour.  However, unlike
	// insertion, there's a whole post-deletion cleanup phase later
	// on.
	//
	// As we walk down the tree, byteIdx is the byte of bs we're
	// currently examining to choose our next step, and numBits is the
	// number of bits that remain in pfx, starting with the byte at
	// byteIdx inclusive.
	bs := pfx.Addr().AsSlice()
	byteIdx := 0
	numBits := pfx.Bits()
	for numBits > 8 {
		if debugDelete {
			fmt.Printf("delete: loop byteIdx=%d numBits=%d st.prefix=%s\n", byteIdx, numBits, st.prefix)
		}
		child, idx := st.getChild(bs[byteIdx])
		if child == nil {
			// Prefix can't exist in the table, one of the necessary
			// strideTables doesn't exist.
			if debugDelete {
				fmt.Printf("delete: missing needed child pfx=%s\n", pfx)
			}
			return
		}
		// Note that the strideIndex and strideTables entries are off-by-one.
		// The child table pointer is recorded at i+1, but it is referenced by a
		// particular index in the parent table, at index i.
		strideIndexes[strideIdx] = idx
		strideTables[strideIdx+1] = child
		strideIdx++

		// Path compression means byteIdx can jump forwards
		// unpredictably. Recompute the next byte to look at from the
		// child we just found.
		byteIdx = child.prefix.Bits() / 8
		numBits = pfx.Bits() - child.prefix.Bits()
		st = child

		if debugDelete {
			fmt.Printf("delete: descend st.prefix=%s\n", st.prefix)
		}
	}

	// We reached a leaf stride table that seems to be in the right
	// spot. But path compression might have led us to the wrong
	// table. Or, we might be in the right place, but the strideTable
	// just doesn't contain the prefix at all.
	if !prefixContains(st.prefix, pfx) {
		// Wrong table, the requested prefix can't exist since its
		// path led us to the wrong place.
		if debugDelete {
			fmt.Printf("delete: wrong leaf table pfx=%s\n", pfx)
		}
		return
	}
	if debugDelete {
		fmt.Printf("delete: delete from st.prefix=%s addr=%d/%d\n", st.prefix, bs[byteIdx], numBits)
	}
	if st.delete(bs[byteIdx], numBits) == nil {
		// We're in the right strideTable, but pfx wasn't in
		// it. Refcounts haven't changed, so no need to run through
		// cleanup.
		if debugDelete {
			fmt.Printf("delete: prefix not present pfx=%s\n", pfx)
		}
		return
	}

	// st.delete reduced st's refcount by one. This table may now be
	// reclaimable, and depending on how we can reclaim it, the parent
	// tables may also need to be considered for reclamation. This
	// loop ends as soon as an iteration takes no action, or takes an
	// action that doesn't alter the parent table's refcounts.
	//
	// We start our walk back at strideTables[strideIdx], which
	// contains st.
	for strideIdx > 0 {
		cur := strideTables[strideIdx]
		if debugDelete {
			fmt.Printf("delete: GC strideIdx=%d st.prefix=%s\n", strideIdx, cur.prefix)
		}
		if cur.routeRefs > 0 {
			// the strideTable has route entries, it cannot be deleted
			// or compacted.
			if debugDelete {
				fmt.Printf("delete: has other routes st.prefix=%s\n", cur.prefix)
			}
			return
		}
		switch cur.childRefs {
		case 0:
			// no routeRefs and no childRefs, this table can be
			// deleted. This will alter the parent table's refcount,
			// so we'll have to look at it as well (in the next loop
			// iteration).
			if debugDelete {
				fmt.Printf("delete: remove st.prefix=%s\n", cur.prefix)
			}
			strideTables[strideIdx-1].deleteChild(strideIndexes[strideIdx-1])
			strideIdx--
		case 1:
			// This table has no routes, and a single child. Compact
			// this table out of existence by making the parent point
			// directly at the one child. This does not affect the
			// parent's refcounts, so the parent can't be eligible for
			// deletion or compaction, and we can stop.
			child := strideTables[strideIdx].findFirstChild()
			parent := strideTables[strideIdx-1]
			if debugDelete {
				fmt.Printf("delete: compact parent.prefix=%s st.prefix=%s child.prefix=%s\n", parent.prefix, cur.prefix, child.prefix)
			}
			strideTables[strideIdx-1].setChildByIdx(strideIndexes[strideIdx-1], child)
			return
		default:
			// This table has two or more children, so it's acting as a "fork in
			// the road" between two prefix subtrees. It cannot be deleted, and
			// thus no further cleanups are possible.
			if debugDelete {
				fmt.Printf("delete: fork table st.prefix=%s\n", cur.prefix)
			}
			return
		}
	}
}

func (t *Table[T]) numStrides() int {
	seen := map[*strideTable[T]]bool{}
	return t.numStridesRec(seen, &t.v4) + t.numStridesRec(seen, &t.v6)
}

func (t *Table[T]) numStridesRec(seen map[*strideTable[T]]bool, st *strideTable[T]) int {
	ret := 1
	if st.childRefs == 0 {
		return ret
	}
	for i := firstHostIndex; i <= lastHostIndex; i++ {
		if c := st.entries[i].child; c != nil && !seen[c] {
			seen[c] = true
			ret += t.numStridesRec(seen, c)
		}
	}
	return ret
}

// debugSummary prints the tree of allocated strideTables in t, with each
// strideTable's refcount.
func (t *Table[T]) debugSummary() string {
	t.init()
	var ret bytes.Buffer
	fmt.Fprintf(&ret, "v4: ")
	strideSummary(&ret, &t.v4, 4)
	fmt.Fprintf(&ret, "v6: ")
	strideSummary(&ret, &t.v6, 4)
	return ret.String()
}

func strideSummary[T any](w io.Writer, st *strideTable[T], indent int) {
	fmt.Fprintf(w, "%s: %d routes, %d children\n", st.prefix, st.routeRefs, st.childRefs)
	indent += 4
	st.treeDebugStringRec(w, 1, indent)
	for i := firstHostIndex; i <= lastHostIndex; i++ {
		if child := st.entries[i].child; child != nil {
			addr, len := inversePrefixIndex(i)
			fmt.Fprintf(w, "%s%d/%d (%02x/%d): ", strings.Repeat(" ", indent), addr, len, addr, len)
			strideSummary(w, child, indent)
		}
	}
}

func prefixContains(parent, child netip.Prefix) bool {
	return parent.Overlaps(child) && parent.Bits() < child.Bits()
}

// computePrefixSplit returns the smallest common prefix that contains both a
// and b. lastCommon is 8-bit aligned, with aStride and bStride indicating the
// value of the 8-bit stride immediately following lastCommon.
//
// computePrefixSplit is used in constructing an intermediate strideTable when a
// new prefix needs to be inserted in a compressed table. It can be read as:
// given that a is already in the table, and b is being inserted, what is the
// prefix of the new intermediate strideTable that needs to be created, and at
// what host addresses in that new strideTable should a and b's subsequent
// strideTables be attached?
func computePrefixSplit(a, b netip.Prefix) (lastCommon netip.Prefix, aStride, bStride uint8) {
	a = a.Masked()
	b = b.Masked()
	if a == b {
		panic("computePrefixSplit called with identical prefixes")
	}
	if a.Addr().Is4() != b.Addr().Is4() {
		panic("computePrefixSplit called with mismatched address families")
	}

	minPrefixLen := a.Bits()
	if b.Bits() < minPrefixLen {
		minPrefixLen = b.Bits()
	}

	commonStrides := commonStrides(a.Addr(), b.Addr(), minPrefixLen)
	lastCommon, err := a.Addr().Prefix(commonStrides * 8)
	if err != nil {
		panic(fmt.Sprintf("computePrefixSplit constructing common prefix: %v", err))
	}
	if a.Addr().Is4() {
		aStride = a.Addr().As4()[commonStrides]
		bStride = b.Addr().As4()[commonStrides]
	} else {
		aStride = a.Addr().As16()[commonStrides]
		bStride = b.Addr().As16()[commonStrides]
	}
	return lastCommon, aStride, bStride
}

func commonStrides(a, b netip.Addr, maxBits int) int {
	if a.Is4() != b.Is4() {
		panic("commonStrides called with mismatched address families")
	}
	var common int
	if a.Is4() {
		aNum, bNum := ipv4AsUint(a), ipv4AsUint(b)
		common = bits.LeadingZeros32(aNum ^ bNum)
	} else {
		aNumHi, aNumLo := ipv6AsUint(a)
		bNumHi, bNumLo := ipv6AsUint(b)
		common = bits.LeadingZeros64(aNumHi ^ bNumHi)
		if common == 64 {
			common += bits.LeadingZeros64(aNumLo ^ bNumLo)
		}
	}
	if common > maxBits {
		common = maxBits
	}
	return common / 8
}

func ipv4AsUint(ip netip.Addr) uint32 {
	bs := ip.As4()
	return uint32(bs[0])<<24 | uint32(bs[1])<<16 | uint32(bs[2])<<8 | uint32(bs[3])
}

func ipv6AsUint(ip netip.Addr) (uint64, uint64) {
	bs := ip.As16()
	hi := uint64(bs[0])<<56 | uint64(bs[1])<<48 | uint64(bs[2])<<40 | uint64(bs[3])<<32 | uint64(bs[4])<<24 | uint64(bs[5])<<16 | uint64(bs[6])<<8 | uint64(bs[7])
	lo := uint64(bs[8])<<56 | uint64(bs[9])<<48 | uint64(bs[10])<<40 | uint64(bs[11])<<32 | uint64(bs[12])<<24 | uint64(bs[13])<<16 | uint64(bs[14])<<8 | uint64(bs[15])
	return hi, lo
}
