/**
 * Module for calculating signed CRC32.
 * Adapted from https://github.com/SheetJS/js-crc32:
 * (C) 2014-present SheetJS -- http://sheetjs.com
 * @module
 */

const T = new Int32Array(256).map((_,n) => [...Array(8)]
    .reduce(c => (c>>>1) ^ ((c&1) * 0xEDB88320), n))

export default function crc32(buf: Buffer, seed?: number) {
	let C = seed! ^ -1, L = buf.length - 3, i = 0
	while (i < L) {
		C = (C>>>8) ^ T[(C^buf[i++])&0xFF]
		C = (C>>>8) ^ T[(C^buf[i++])&0xFF]
		C = (C>>>8) ^ T[(C^buf[i++])&0xFF]
		C = (C>>>8) ^ T[(C^buf[i++])&0xFF]
	}
	while (i < L+3) C = (C>>>8) ^ T[(C^buf[i++])&0xFF]
	return C ^ -1
}
