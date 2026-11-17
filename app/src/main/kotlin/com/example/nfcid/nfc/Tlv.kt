package com.example.nfcid.nfc

/** One BER-TLV element. [children] is filled in for constructed tags (bit 6 of the first tag byte). */
class Tlv(val tag: Int, val value: ByteArray, val children: List<Tlv>)

/**
 * Minimal BER-TLV parser, enough for EMV / ISO 7816 FCI templates.
 *
 * Handles multi-byte tags and 1-3 byte long-form lengths, skips 0x00/0xFF padding between elements,
 * and stops (returning what it has so far) on malformed input instead of throwing.
 */
fun parseTlv(data: ByteArray): List<Tlv> {
  val out = mutableListOf<Tlv>()
  var i = 0
  while (i < data.size) {
    val first = data[i].toInt() and 0xFF
    if (first == 0x00 || first == 0xFF) {
      i++
      continue
    }
    var tag = first
    i++
    if ((first and 0x1F) == 0x1F) {
      do {
        if (i >= data.size) return out
        val b = data[i].toInt() and 0xFF
        tag = (tag shl 8) or b
        i++
      } while ((b and 0x80) != 0)
    }
    if (i >= data.size) return out
    var length = data[i].toInt() and 0xFF
    i++
    if ((length and 0x80) != 0) {
      val n = length and 0x7F
      if (n == 0 || n > 3 || i + n > data.size) return out
      length = 0
      repeat(n) {
        length = (length shl 8) or (data[i].toInt() and 0xFF)
        i++
      }
    }
    if (i + length > data.size) return out
    val value = data.copyOfRange(i, i + length)
    i += length
    val constructed = (first and 0x20) != 0
    out += Tlv(tag, value, if (constructed) parseTlv(value) else emptyList())
  }
  return out
}

/** All elements with [tag], searching depth-first through nested templates. */
fun List<Tlv>.allWithTag(tag: Int): List<Tlv> = flatMap {
  (if (it.tag == tag) listOf(it) else emptyList()) + it.children.allWithTag(tag)
}

fun List<Tlv>.firstWithTag(tag: Int): Tlv? = allWithTag(tag).firstOrNull()
