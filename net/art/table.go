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
	st := &t.v4
	if pfx.Addr().Is6() {
		st = &t.v6
	}
	bs := pfx.Addr().AsSlice()
	i := 0
	numBits := pfx.Bits()

	// The strideTable we want to insert into is potentially at the end of a
	// chain of strideTables, each one encoding successive 8 bits of the prefix.
	//
	// We're expecting to walk down a path of tables, although with prefix
	// compression we may end up skipping some links in the chain, or taking
	// wrong turns and having to course correct.
	//
	// When this loop exits, st points to the strideTable to insert into;
	// numBits is the prefix length to insert in the strideTable (0-8), and i is
	// the index into bs of the address byte containing the final numBits bits
	// of the prefix.
	fmt.Printf("process %s i=%d numBits=%d\n", pfx, i, numBits)
findLeafTable:
	for numBits > 8 {
		fmt.Printf("find %s i=%d numBits=%d\n", pfx, i, numBits)
		child, created := st.getOrCreateChild(bs[i])

		// At each step of our path through strideTables, one of three things
		// can happen:
		switch {
		case created:
			// The path we were on for our prefix stopped at a dead end, a
			// subtree we need doesn't exist. The rest of the path, if we were
			// to create it, will consist of a bunch of tables with a single
			// child. We can use path compression to elide those intermediates,
			// and jump straight to the final strideTable that hosts this
			// prefix.
			if pfx.Bits() == pfx.Addr().BitLen() {
				i = len(bs) - 1
				numBits = 8
			} else {
				i = pfx.Bits() / 8
				numBits = pfx.Bits() % 8
			}
			child.prefix = mustPrefix(pfx.Addr(), i*8)
			st = child
			fmt.Printf("created child table, i=%d numBits=%d childPrefix=%s\n", i, numBits, child.prefix)
			break findLeafTable
		case !prefixIsChild(child.prefix, pfx):
			fmt.Printf("wrong way, child.prefix=%s pfx=%s\n", child.prefix, pfx)
			// A child exists, but its prefix is not a parent of pfx. This means
			// that this subtree was compressed in service of a different
			// prefix, and we are missing an intermediate strideTable that
			// differentiates our desired path and the path we've currently
			// ended up on.
			//
			// We can fix this by inserting an intermediate strideTable that
			// represents the first non-equal byte of the two prefixes.
			// Effectively, we decompress the existing path, insert pfx (which
			// creates a new, different subtree somewhere), then recompress the
			// entire subtree to end up with 3 strideTables: the one we just
			// found, the leaf table we need for pfx, and a common parent that
			// distinguishes the two.
			intermediatePrefix, addrOfExisting, addrOfNew := computePrefixSplit(child.prefix, pfx)
			intermediate := &strideTable[T]{prefix: intermediatePrefix}
			st.setChild(bs[i], intermediate)
			intermediate.setChild(addrOfExisting, child)

			// Is the new intermediate we just made the final resting
			// insertion point for the new prefix? It could either
			// belong in intermediate, or in a new child of
			// intermediate.
			if remain := pfx.Bits() - intermediate.prefix.Bits(); remain <= 8 {
				// pfx belongs directly in intermediate.
				i = pfx.Bits() / 8
				if pfx.Bits()%8 == 0 && pfx.Bits() != 0 {
					i--
				}
				numBits = remain
				st = intermediate
				fmt.Printf("pfx directly in intermediate, %d into %s\n", bs[i], st.prefix)
				break findLeafTable
			}

			// Otherwise, we need a new child subtree hanging off the
			// intermediate. By definition this subtree doesn't exist
			// yet, which means we can fully compress it and jump from
			// the intermediate straight to the final stride that pfx
			// needs.
			st, created = intermediate.getOrCreateChild(addrOfNew)
			if !created {
				panic("new child path unexpectedly exists during path decompression")
			}
			// Having now created a new child for our prefix, we're back in the
			// previous case: the rest of the path definitely doesn't exist,
			// since we just made it. We just need to set up the new leaf table
			// and get it ready for final insertion.
			if pfx.Bits() == pfx.Addr().BitLen() {
				i = len(bs) - 1
				numBits = 8
			} else {
				i = pfx.Bits() / 8
				numBits = pfx.Bits() % 8
			}
			st.prefix = mustPrefix(pfx.Addr(), i*8)
			fmt.Printf("created intermediate table, i=%d numBits=%d intermediate=%s childPrefix=%s\n", i, numBits, intermediate.prefix, st.prefix)
			break findLeafTable
		default:
			// An expected child table exists along pfx's path. Continue traversing
			// downwards, or exit the loop if we run out of prefix bits and this
			// child is the leaf we should insert into.
			st = child
			i++
			numBits -= 8
			fmt.Printf("walking down, i=%d numBits=%d childPrefix=%s\n", i, numBits, st.prefix)
		}
	}

	fmt.Printf("inserting %s i=%d numBits=%d\n\n", pfx, i, numBits)
	// Finally, insert the remaining 0-8 bits of the prefix into the child
	// table.
	st.insert(bs[i], numBits, val)
}

// Delete removes pfx from the table, if it is present.
func (t *Table[T]) Delete(pfx netip.Prefix) {
	t.init()
	st := &t.v4
	if pfx.Addr().Is6() {
		st = &t.v6
	}
	bs := pfx.Addr().AsSlice()
	i := 0
	numBits := pfx.Bits()

	// Deletion may drive the refcount of some strideTables down to zero. We
	// need to clean up these dangling tables, so we have to keep track of which
	// tables we touch on the way down, and which strideEntry index each child
	// is registered in.
	strideIdx := 0
	strideTables := [16]*strideTable[T]{st}
	strideIndexes := [16]int{}

	// Similar to Insert, navigate down the tree of strideTables, looking for
	// the one that houses this prefix. This part is easier than with insertion,
	// since we can bail if the path ends early or takes an unexpected detour.
	// However, unlike insertion, there's a whole post-deletion cleanup phase
	// later on.
	for numBits > 8 {
		child, idx := st.getChild(bs[i])
		if child == nil {
			// Prefix can't exist in the table, one of the necessary
			// strideTables doesn't exist.
			return
		}
		// Note that the strideIndex and strideTables entries are off-by-one.
		// The child table pointer is recorded at i+1, but it is referenced by a
		// particular index in the parent table, at index i.
		strideIndexes[strideIdx] = idx
		strideIdx++
		strideTables[strideIdx] = child
		i = child.prefix.Bits() / 8
		numBits = pfx.Bits() - child.prefix.Bits()
		st = child
	}

	// We reached a leaf stride table that seems to be in the right spot. But
	// path compression might have led us to the wrong table. Or, we might be in
	// the right place, but the strideTable just doesn't contain the prefix at
	// all.
	if !prefixIsChild(st.prefix, pfx) {
		// Wrong table, the requested prefix can't exist since its path led us
		// to the wrong place.
		return
	}
	if st.delete(bs[i], numBits) == nil {
		// We're in the right strideTable, but pfx wasn't in it. Refcount hasn't
		// changed, so no need to run through cleanup.
		return
	}

	// st.delete reduced st's refcount by one. This table may now be
	// reclaimable, and depending on how we can reclaim it, the parent tables
	// may also need to be considered for reclamation. This loop ends as soon as
	// take no action, or take an action that doesn't alter the parent table's
	// refcounts.
	for i > 0 {
		if strideTables[i].routeRefs > 0 {
			// the strideTable has route entries, it cannot be deleted or
			// compacted.
			return
		}
		switch strideTables[i].childRefs {
		case 0:
			// no routeRefs and no childRefs, this table can be deleted. This
			// will alter the parent table's refcount, so we'll have to look at
			// it as well (in the next loop iteration).
			strideTables[i-1].deleteChild(strideIndexes[i-1])
			i--
		case 1:
			// This table has no routes, and a single child. Compact this table
			// out of existence by making the parent point directly at the
			// child. This does not affect the parent's refcounts, so the parent
			// can't be eligible for deletion or compaction, and we can stop.
			strideTables[i-1].setChildByIdx(strideIndexes[i-1], strideTables[i].findFirstChild())
			return
		default:
			// This table has two or more children, so it's acting as a "fork in
			// the road" between two prefix subtrees. It cannot be deleted, and
			// thus no further cleanups are possible.
			return
		}
	}
}

// debugSummary prints the tree of allocated strideTables in t, with each
// strideTable's refcount.
func (t *Table[T]) debugSummary() string {
	t.init()
	var ret bytes.Buffer
	fmt.Fprintf(&ret, "v4: ")
	strideSummary(&ret, &t.v4, 0)
	fmt.Fprintf(&ret, "v6: ")
	strideSummary(&ret, &t.v6, 0)
	return ret.String()
}

func strideSummary[T any](w io.Writer, st *strideTable[T], indent int) {
	fmt.Fprintf(w, "%s: %d routes, %d children\n", st.prefix, st.routeRefs, st.childRefs)
	indent += 2
	st.treeDebugStringRec(w, 1, indent)
	for i := firstHostIndex; i <= lastHostIndex; i++ {
		if child := st.entries[i].child; child != nil {
			addr, len := inversePrefixIndex(i)
			fmt.Fprintf(w, "%s%d/%d: ", strings.Repeat(" ", indent), addr, len)
			strideSummary(w, child, indent)
		}
	}
}

func prefixIsChild(parent, child netip.Prefix) bool {
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
	fmt.Printf("split: %s vs. %s\n", a, b)

	minPrefixLen := a.Bits()
	if b.Bits() < minPrefixLen {
		minPrefixLen = b.Bits()
	}
	fmt.Printf("maxbits=%d\n", minPrefixLen)

	commonStrides := commonStrides(a.Addr(), b.Addr(), minPrefixLen)
	fmt.Printf("commonstrides=%d\n", commonStrides)
	lastCommon, err := a.Addr().Prefix(commonStrides * 8)
	fmt.Printf("lastCommon=%s\n", lastCommon)
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
	fmt.Printf("aStride=%d, bStride=%d\n", aStride, bStride)
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
