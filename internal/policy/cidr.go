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

// Subtract returns include minus exclude, aggregated.
func Subtract(include, exclude []netip.Prefix) []netip.Prefix {
	inc := toIntervals(include)
	exc := toIntervals(exclude)
	var out []interval
	for _, x := range inc {
		cur := []interval{x}
		for _, e := range exc {
			var next []interval
			for _, c := range cur {
				if e.hi < c.lo || e.lo > c.hi {
					next = append(next, c)
					continue
				}
				if e.lo > c.lo {
					next = append(next, interval{c.lo, e.lo - 1})
				}
				if e.hi < c.hi {
					next = append(next, interval{e.hi + 1, c.hi})
				}
			}
			cur = next
		}
		out = append(out, cur...)
	}
	return fromIntervals(mergeIntervals(out))
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

// Widen reduces ps to at most limit prefixes by replacing pairs of
// neighbours with their common supernet, preferring the merges that add the
// fewest extra addresses. The result always covers the input. Each pass
// merges up to half of the pairs still needed, cheapest first, so large
// lists (thousands of routes) take milliseconds.
func Widen(ps []netip.Prefix, limit int) (out []netip.Prefix, widened bool) {
	out = Aggregate(ps)
	if limit <= 0 {
		return out, false
	}
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
		budget := max(1, (n-limit)/2)
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
		out = Aggregate(next)
		widened = true
	}
	return out, widened
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
