package zipcrypto

import "hash/crc32"

type keys [3]uint32

func (k *keys) init(password []byte) {
	k[0] = 0x12345678 // 305419896
	k[1] = 0x23456789 // 591751049
	k[2] = 0x34567890 // 878082192

	for _, b := range password {
		k.updateKeys(b)
	}
}

func (k *keys) byte() byte {
	t := k[2] | 2
	return byte((t * (t ^ 1)) >> 8)
}

func (k *keys) updateKeys(b byte) {
	k[0] = crc32Update(k[0], b)
	k[1] = k[1] + (k[0] & 0xff)
	k[1] = k[1]*134775813 + 1
	k[2] = crc32Update(k[2], (byte)(k[1]>>24))
}

func crc32Update(crc uint32, b byte) uint32 {
	return crc32.IEEETable[(crc^uint32(b))&0xff] ^ (crc >> 8)
}
