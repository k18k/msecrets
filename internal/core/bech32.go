package core

import "strings"

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32Generators = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func bech32Polymod(values []byte) uint32 {
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for bit, generator := range bech32Generators {
			if (top>>bit)&1 == 1 {
				checksum ^= generator
			}
		}
	}
	return checksum
}

func bech32HrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	maxValue := uint32(1)<<to - 1
	var out []byte
	var accumulator uint32
	var bits uint
	for _, value := range data {
		accumulator = accumulator<<from | uint32(value)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(accumulator>>bits&maxValue))
		}
		accumulator &= 1<<bits - 1
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(accumulator<<(to-bits)&maxValue))
		}
	} else if bits >= from || accumulator != 0 {
		return nil, newError(CodeInvalidKey, "Invalid Bech32 padding")
	}
	return out, nil
}

// bech32Encode encodes Bech32 (BIP173) without the 90 character limit, as age does.
func bech32Encode(hrp string, data []byte) string {
	hrp = strings.ToLower(hrp)
	values, _ := convertBits(data, 8, 5, true)
	polymod := bech32Polymod(append(append(bech32HrpExpand(hrp), values...), 0, 0, 0, 0, 0, 0)) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, value := range values {
		b.WriteByte(bech32Charset[value])
	}
	for i := range 6 {
		b.WriteByte(bech32Charset[polymod>>(5*(5-i))&31])
	}
	return b.String()
}

func bech32Decode(text string) (hrp string, data []byte, err error) {
	lower := strings.ToLower(text)
	if text != lower && text != strings.ToUpper(text) {
		return "", nil, newError(CodeInvalidKey, "Bech32 string mixes upper and lower case")
	}
	separator := strings.LastIndexByte(lower, '1')
	if separator < 1 || separator+7 > len(lower) {
		return "", nil, newError(CodeInvalidKey, "Malformed Bech32 string")
	}
	hrp = lower[:separator]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, newError(CodeInvalidKey, "Invalid Bech32 human-readable part")
		}
	}
	values := make([]byte, 0, len(lower)-separator-1)
	for _, char := range lower[separator+1:] {
		value := strings.IndexRune(bech32Charset, char)
		if value < 0 {
			return "", nil, newError(CodeInvalidKey, "Invalid Bech32 character %s", jsQuote(string(char)))
		}
		values = append(values, byte(value))
	}
	if bech32Polymod(append(bech32HrpExpand(hrp), values...)) != 1 {
		return "", nil, newError(CodeInvalidKey, "Invalid Bech32 checksum")
	}
	data, err = convertBits(values[:len(values)-6], 5, 8, false)
	return hrp, data, err
}
