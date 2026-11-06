package pcap

import (
	"math"
	"sort"
)

type beaconFlow struct {
	Key         string
	Count       int
	Intervals   []float64
	MeanSeconds float64
	JitterPct   float64
}

func detectBeacons(pkts []pktTS, maxFlows int) []beaconFlow {
	byKey := map[string][]float64{}
	for _, p := range pkts {
		byKey[p.Key] = append(byKey[p.Key], p.TS)
	}

	var out []beaconFlow
	for k, tss := range byKey {
		if len(tss) < 6 {
			continue
		}
		sort.Float64s(tss)
		var deltas []float64
		for i := 1; i < len(tss); i++ {
			deltas = append(deltas, tss[i]-tss[i-1])
		}
		sum := 0.0
		for _, d := range deltas {
			sum += d
		}
		mean := sum / float64(len(deltas))
		if mean < 5 || mean > 1800 {
			continue
		}
		var varSum float64
		for _, d := range deltas {
			diff := d - mean
			varSum += diff * diff
		}
		stdev := math.Sqrt(varSum / float64(len(deltas)))
		cv := stdev / mean
		if cv < 0.15 {
			out = append(out, beaconFlow{
				Key: k, Count: len(tss), Intervals: deltas,
				MeanSeconds: mean, JitterPct: cv * 100,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JitterPct < out[j].JitterPct })
	if len(out) > maxFlows {
		out = out[:maxFlows]
	}
	return out
}

type scanCandidate struct {
	Src           string
	DistinctPorts int
	DistinctDst   int
}

func detectPortScans(pkts []portPkt) []scanCandidate {
	type stat struct {
		src      string
		dstPorts map[uint16]bool
		dstIPs   map[string]bool
	}
	stats := map[string]*stat{}
	for _, p := range pkts {
		s, ok := stats[p.Src]
		if !ok {
			s = &stat{src: p.Src, dstPorts: map[uint16]bool{}, dstIPs: map[string]bool{}}
			stats[p.Src] = s
		}
		s.dstPorts[p.DstPort] = true
		s.dstIPs[p.Dst] = true
	}
	var out []scanCandidate
	for _, s := range stats {
		if len(s.dstPorts) >= 20 && len(s.dstIPs) >= 10 {
			out = append(out, scanCandidate{
				Src: s.src, DistinctPorts: len(s.dstPorts), DistinctDst: len(s.dstIPs),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DistinctPorts > out[j].DistinctPorts })
	return out
}
