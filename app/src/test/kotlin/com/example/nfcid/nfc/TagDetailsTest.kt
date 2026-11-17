package com.example.nfcid.nfc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TagDetailsTest {

  @Test
  fun toHex_formatsUnsignedBytes() {
    val bytes = byteArrayOf(0x04, 0xA2.toByte(), 0x00, 0xFF.toByte())
    assertEquals("04:A2:00:FF", bytes.toHex())
    assertEquals("04A200FF", bytes.toHex(separator = ""))
  }

  @Test
  fun toHex_emptyArray() {
    assertEquals("", byteArrayOf().toHex())
  }

  @Test
  fun toHexOrNone_emptyShowsNone() {
    assertEquals("(none)", byteArrayOf().toHexOrNone())
    assertEquals("0A:FF", byteArrayOf(0x0A, 0xFF.toByte()).toHexOrNone())
  }

  @Test
  fun decodeText_utf8WithLanguage() {
    val payload = byteArrayOf(0x02) + "en".toByteArray() + "Hello".toByteArray()
    assertEquals("[en] Hello", decodeTextRecordPayload(payload))
  }

  @Test
  fun decodeText_utf16() {
    val text = "Héllo".toByteArray(Charsets.UTF_16)
    val payload = byteArrayOf((0x80 or 0x02).toByte()) + "fr".toByteArray() + text
    assertEquals("[fr] Héllo", decodeTextRecordPayload(payload))
  }

  @Test
  fun decodeText_noLanguage() {
    val payload = byteArrayOf(0x00) + "abc".toByteArray()
    assertEquals("abc", decodeTextRecordPayload(payload))
  }

  @Test
  fun decodeText_malformed() {
    assertNull(decodeTextRecordPayload(byteArrayOf()))
    // Claims a 5-byte language code but only 2 bytes follow.
    assertNull(decodeTextRecordPayload(byteArrayOf(0x05, 0x65, 0x6E)))
  }
}
