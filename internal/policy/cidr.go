package policy

import (
	"math/bits"
	"net/netip"
	"sort"
)

// interval is an inclusive IPv4 range.
type interval struct{ lo, hi uint32 }

func v4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func addr(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

func toInterval(p netip.Prefix) interval {
	p = p.Masked()
	lo := v4(p.Addr())
	size := uint64(1) << (32 - p.Bits())
	return interval{lo, uint32(uint64(lo) + size - 1)}
}

func toIntervals(ps []netip.Prefix) []interval {
	out := make([]interval, 0, len(ps))
	for _, p := range ps {
		if p.Addr().Is4() {
			out = append(out, toInterval(p))
		}
	}
	return mergeIntervals(out)
}

func mergeIntervals(iv []interval) []interval {
	if len(iv) == 0 {
		return nil
	}
	sort.Slice(iv, func(i, j int) bool { return iv[i].lo < iv[j].lo })
	out := []interval{iv[0]}
	for _, x := range iv[1:] {
		last := &out[len(out)-1]
		if uint64(x.lo) <= uint64(last.hi)+1 {
			if x.hi > last.hi {
				last.hi = x.hi
			}
			continue
		}
		out = append(out, x)
	}
	return out
}

// intervalPrefixes splits a range into the minimal list of prefixes.
func intervalPrefixes(x interval) []netip.Prefix {
	var out []netip.Prefix
	lo := uint64(x.lo)
	hi := uint64(x.hi)
	for lo <= hi {
		// largest block aligned at lo
		var size uint64 = 1 << 32
		if lo != 0 {
			size = 1 << bits.TrailingZeros32(uint32(lo))
		}
		for lo+size-1 > hi {
			size >>= 1
		}
		pl := 32 - bits.TrailingZeros64(size)
		out = append(out, netip.PrefixFrom(addr(uint32(lo)), pl))
		lo += size
	}
	return out
}

func fromIntervals(iv []interval) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range iv {
		out = append(out, intervalPrefixes(x)...)
	}
	return out
}

// Aggregate merges duplicate, nested and adjacent prefixes.
func Aggregate(ps []netip.Prefix) []netip.Prefix {
	return fromIntervals(toIntervals(ps))
}

// Subtract returns include minus exclude, aggregated. Both lists are
// walked once in address order, so tens of thousands of exclusions take
// milliseconds.
func Subtract(include, exclude []netip.Prefix) []netip.Prefix {
	inc := toIntervals(include)
	exc := toIntervals(exclude)
	var out []interval
	j := 0
	for _, x := range inc {
		for j < len(exc) && exc[j].hi < x.lo {
			j++
		}
		lo := uint64(x.lo)
		// exc[j] may also reach into the next include, so j stays.
		for k := j; k < len(exc) && exc[k].lo <= x.hi; k++ {
			if e := exc[k]; uint64(e.lo) > lo {
				out = append(out, interval{uint32(lo), e.lo - 1})
			}
			lo = uint64(exc[k].hi) + 1
		}
		if lo <= uint64(x.hi) {
			out = append(out, interval{uint32(lo), x.hi})
		}
	}
	return fromIntervals(out)
}

// Contains reports whether any prefix contains a.
func Contains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Covers reports whether every address of inner is inside outer.
func Covers(outer, inner []netip.Prefix) bool {
	return len(Subtract(inner, outer)) == 0
}

// Widen reduces ps to at most limit prefixes, adding as few extra
// addresses as it can; the result always covers the input. Every prefix
// is given a price in addresses: for one price the best cover is a single
// pass over the prefix tree, and the price is searched for the limit.
func Widen(ps []netip.Prefix, limit int) (out []netip.Prefix, widened bool) {
	out = Aggregate(ps)
	if limit <= 0 || len(out) <= limit {
		return out, false
	}
	return widen(out, limit), true
}

// widen covers in (aggregated, more than limit prefixes) with at most
// limit prefixes.
func widen(in []netip.Prefix, limit int) []netip.Prefix {
	t := newCoverTree(in)
	// At 2^33 a prefix costs more than all addresses: one prefix is left.
	// At 0 nothing is merged, which is over the limit.
	lo, hi := uint64(1), uint64(1)<<33
	for lo < hi {
		mid := lo + (hi-lo)/2
		if t.solve(mid).count[t.root()] <= limit {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	// Many prefixes can change at the same price, so the solution at lo
	// may stay far below the limit and the one just under it far above:
	// fill the room from below or merge down from above, whichever is
	// tighter.
	fit, over := t.solve(lo), t.solve(lo-1)
	a := Aggregate(t.cover(fit, over, limit))
	var b []netip.Prefix
	t.walk(over, t.root(), func(i int) { b = append(b, t.nodes[i].p) })
	b = mergeDown(Aggregate(b), limit)
	if addresses(b) < addresses(a) {
		return b
	}
	return a
}

func addresses(ps []netip.Prefix) (n uint64) {
	for _, p := range ps {
		n += size(p)
	}
	return n
}

// mergeDown replaces neighbours with their common supernet, the merges
// adding the fewest addresses first, until at most limit prefixes are
// left. A pass merges up to half of the pairs still needed; when it
// swallows so many neighbours that the result falls below the limit, it is
// retried with fewer merges.
func mergeDown(out []netip.Prefix, limit int) []netip.Prefix {
	type merge struct {
		i    int
		cost uint64
		sp   netip.Prefix
	}
	for len(out) > limit {
		n := len(out)
		ms := make([]merge, 0, n-1)
		for i := 0; i+1 < n; i++ {
			sp := supernet(out[i], out[i+1])
			ms = append(ms, merge{i, size(sp) - size(out[i]) - size(out[i+1]), sp})
		}
		sort.SliceStable(ms, func(a, b int) bool { return ms[a].cost < ms[b].cost })
		for budget := max(1, (n-limit)/2); ; budget /= 2 {
			take := make(map[int]netip.Prefix, budget)
			used := make([]bool, n)
			for _, m := range ms {
				if len(take) == budget {
					break
				}
				if used[m.i] || used[m.i+1] {
					continue
				}
				used[m.i], used[m.i+1] = true, true
				take[m.i] = m.sp
			}
			next := make([]netip.Prefix, 0, n-len(take))
			for i := 0; i < n; i++ {
				if sp, ok := take[i]; ok {
					next = append(next, sp)
					i++
					continue
				}
				next = append(next, out[i])
			}
			if next = Aggregate(next); len(next) >= limit || budget == 1 {
				out = next
				break
			}
		}
	}
	return out
}

// coverTree is the binary tree of disjoint prefixes: leaves are the
// prefixes, inner nodes the supernets where they branch. Children come
// before their parent; the root is last.
type coverTree struct{ nodes []coverNode }

type coverNode struct {
	p     netip.Prefix
	l, r  int    // children; -1 for a leaf
	extra uint64 // addresses of p that are not in the input
}

// coverSolution is the best cover of every subtree at one price.
type coverSolution struct {
	price uint64
	cost  []uint64 // extra addresses plus price per prefix
	count []int
	whole []bool // the cover is the node's own prefix
}

func newCoverTree(ps []netip.Prefix) *coverTree {
	t := &coverTree{}
	t.build(ps)
	return t
}

func (t *coverTree) root() int { return len(t.nodes) - 1 }

// build adds the subtree of ps (sorted, disjoint) and returns its root
// and the number of input addresses in it.
func (t *coverTree) build(ps []netip.Prefix) (int, uint64) {
	if len(ps) == 1 {
		t.nodes = append(t.nodes, coverNode{p: ps[0], l: -1, r: -1})
		return len(t.nodes) - 1, size(ps[0])
	}
	sp := supernet(ps[0], ps[len(ps)-1])
	bit := uint32(1) << (31 - sp.Bits())
	k := sort.Search(len(ps), func(i int) bool { return v4(ps[i].Addr())&bit != 0 })
	l, nl := t.build(ps[:k])
	r, nr := t.build(ps[k:])
	t.nodes = append(t.nodes, coverNode{p: sp, l: l, r: r, extra: size(sp) - nl - nr})
	return len(t.nodes) - 1, nl + nr
}

// solve finds the covers with the least extra addresses plus price per
// prefix; ties go to fewer prefixes.
func (t *coverTree) solve(price uint64) *coverSolution {
	n := len(t.nodes)
	s := &coverSolution{price, make([]uint64, n), make([]int, n), make([]bool, n)}
	for i, nd := range t.nodes {
		s.whole[i] = true
		s.cost[i], s.count[i] = nd.extra+price, 1
		if nd.l < 0 {
			continue
		}
		if split := s.cost[nd.l] + s.cost[nd.r]; split < s.cost[i] {
			s.whole[i] = false
			s.cost[i], s.count[i] = split, s.count[nd.l]+s.count[nd.r]
		}
	}
	return s
}

// cover returns the prefixes of fit (within limit) and splits those that
// over splits as well while they fit, the ones saving most addresses per
// added prefix first.
func (t *coverTree) cover(fit, over *coverSolution, limit int) []netip.Prefix {
	var keep []int
	t.walk(fit, t.root(), func(i int) { keep = append(keep, i) })
	type split struct {
		i           int
		saved, more uint64
	}
	var splits []split
	for _, i := range keep {
		if over.whole[i] {
			continue
		}
		extra := over.cost[i] - over.price*uint64(over.count[i])
		splits = append(splits, split{i, t.nodes[i].extra - extra, uint64(over.count[i] - 1)})
	}
	sort.Slice(splits, func(a, b int) bool {
		return splits[a].saved*splits[b].more > splits[b].saved*splits[a].more
	})
	room := limit - len(keep)
	chosen := map[int]bool{}
	for _, sp := range splits {
		if int(sp.more) <= room {
			room -= int(sp.more)
			chosen[sp.i] = true
		}
	}
	var out []netip.Prefix
	for _, i := range keep {
		if !chosen[i] {
			out = append(out, t.nodes[i].p)
			continue
		}
		t.walk(over, i, func(j int) { out = append(out, t.nodes[j].p) })
	}
	return out
}

// walk calls f for the prefixes of s's cover of the subtree at i.
func (t *coverTree) walk(s *coverSolution, i int, f func(int)) {
	if s.whole[i] {
		f(i)
		return
	}
	t.walk(s, t.nodes[i].l, f)
	t.walk(s, t.nodes[i].r, f)
}

func size(p netip.Prefix) uint64 { return uint64(1) << (32 - p.Bits()) }

func supernet(a, b netip.Prefix) netip.Prefix {
	x, y := v4(a.Addr()), v4(b.Addr())
	l := bits.LeadingZeros32(x ^ y)
	if a.Bits() < l {
		l = a.Bits()
	}
	if b.Bits() < l {
		l = b.Bits()
	}
	p, _ := addr(x).Prefix(l)
	return p
}

// WidenTo widens ps to at most limit prefixes whose text ("10.0.0.0/8",
// plus 2 bytes of attribute header each) takes at most maxBytes: a RADIUS
// packet holds 4096 bytes in all. maxBytes <= 0: no byte limit.
func WidenTo(ps []netip.Prefix, limit, maxBytes int) ([]netip.Prefix, bool) {
	out, widened := Widen(ps, limit)
	for maxBytes > 0 && len(out) > 1 && routeBytes(out) > maxBytes {
		out, _ = Widen(out, len(out)*3/4)
		widened = true
	}
	return out, widened
}

func routeBytes(ps []netip.Prefix) int {
	n := 0
	for _, p := range ps {
		n += 2 + len(p.String())
	}
	return n
}
