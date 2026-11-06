package t07_phototrace

// ParseDQT walks JPEG DQT markers and returns the first quantization
// table (64 entries in zigzag order). Empty slice when not found.
func ParseDQT(data []byte) []int {
	for i := 0; i < len(data)-1; i++ {
		if data[i] != 0xFF || data[i+1] != 0xDB {
			continue
		}
		off := i + 4
		if off+64 > len(data) {
			return nil
		}
		pq := data[off-2] >> 4
		var dqt []int
		if pq == 0 {
			for k := 0; k < 64 && off+k < len(data); k++ {
				dqt = append(dqt, int(data[off+k]))
			}
		}
		return dqt
	}
	return nil
}
