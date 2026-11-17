package com.example.nfcid.nfc

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TlvTest {

  @Test
  fun parsesNestedTemplatesAndMultiByteTags() {
    // 6F { 84 "AB", A5 { BF0C { 61 { 4F A0000000031010 } } } }
    val data = "6F14 84024142 A50E BF0C0B 6109 4F07A0000000031010".replace(" ", "").hexToBytes()
    val tlvs = parseTlv(data)
    assertEquals(1, tlvs.size)
    assertEquals(0x6F, tlvs[0].tag)
    assertArrayEquals("AB".toByteArray(), tlvs.firstWithTag(0x84)!!.value)
    assertEquals(0xBF0C, tlvs.firstWithTag(0xBF0C)!!.tag)
    assertArrayEquals("A0000000031010".hexToBytes(), tlvs.firstWithTag(0x4F)!!.value)
  }

  @Test
  fun longFormLength() {
    val value = ByteArray(200) { 0x11 }
    val data = byteArrayOf(0x50, 0x81.toByte(), 200.toByte()) + value
    assertArrayEquals(value, parseTlv(data).single().value)
  }

  @Test
  fun skipsPaddingBetweenElements() {
    val data = "5001410000FF5001 42".replace(" ", "").hexToBytes()
    assertEquals(2, parseTlv(data).allWithTag(0x50).size)
  }

  @Test
  fun truncatedInputReturnsWhatParsed() {
    // Second element claims 5 bytes but only 1 follows.
    val tlvs = parseTlv("500141 5005 41".replace(" ", "").hexToBytes())
    assertEquals(1, tlvs.size)
    assertNull(parseTlv(byteArrayOf(0x5F)).firstOrNull())
    assertTrue(parseTlv(byteArrayOf()).isEmpty())
  }
}
