package transport

import "crypto/subtle"

func XorBytes(dst, a, b []byte) int {
	return subtle.XORBytes(dst, a, b)
}
