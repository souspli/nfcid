package com.example.nfcid.nfc

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApplicationProberTest {

  /** Answers APDUs from a table (hex → hex); anything else gets 6A82 "file not found". */
  private class FakeCard(
    private val responses: Map<String, String>,
    private val failAfter: Int = Int.MAX_VALUE,
  ) : Transceiver {
    val sent = mutableListOf<String>()

    override fun transceive(apdu: ByteArray): ByteArray {
      if (sent.size >= failAfter) throw IOException("Tag was lost.")
      val hex = apdu.toHex(separator = "")
      sent += hex
      return (responses[hex] ?: "6A82").hexToBytes()
    }
  }

  private fun tlv(tag: Int, vararg parts: ByteArray): ByteArray {
    val value = parts.fold(byteArrayOf()) { acc, p -> acc + p }
    require(value.size < 0x80)
    val tagBytes = if (tag > 0xFF) byteArrayOf((tag shr 8).toByte(), tag.toByte()) else byteArrayOf(tag.toByte())
    return tagBytes + byteArrayOf(value.size.toByte()) + value
  }

  private fun select(aid: ByteArray, fci: Boolean = true) = Apdu.selectByName(aid, fci).toHex(separator = "")

  private val ppseSelect = select(KnownApplications.PPSE)

  private fun visaPpseFci(): ByteArray =
    tlv(
      0x6F,
      tlv(0x84, KnownApplications.PPSE),
      tlv(
        0xA5,
        tlv(
          0xBF0C,
          tlv(0x61, tlv(0x4F, "A0000000031010".hexToBytes()), tlv(0x50, "VISA CREDIT".toByteArray()), tlv(0x87, byteArrayOf(1))),
        ),
      ),
    )

  @Test
  fun selectApduLayout() {
    assertEquals("00A4040007A000000247100100", select("A0000002471001".hexToBytes()))
    assertEquals("00A4040C07A0000002471001", select("A0000002471001".hexToBytes(), fci = false))
  }

  @Test
  fun paymentCardListsNetworkAndLabel() {
    val card = FakeCard(mapOf(ppseSelect to visaPpseFci().toHex("") + "9000"))
    val found = ApplicationProber.probe(card)
    assertEquals(listOf("Payment: Visa \"VISA CREDIT\" (AID A0000000031010)"), found)
  }

  @Test
  fun neverSendsReadRecordOrGpo() {
    val card = FakeCard(mapOf(ppseSelect to visaPpseFci().toHex("") + "9000"))
    ApplicationProber.probe(card)
    // INS B2 = READ RECORD, A8 = GET PROCESSING OPTIONS: these would expose card data.
    assertTrue(card.sent.none { it.substring(2, 4) == "B2" || it.substring(2, 4) == "A8" })
  }

  @Test
  fun passportFoundWithNoDataSelect() {
    val card = FakeCard(mapOf(select("A0000002471001".hexToBytes(), fci = false) to "9000"))
    assertEquals(listOf("ICAO e-passport (eMRTD)"), ApplicationProber.probe(card))
  }

  @Test
  fun followsGetResponseChaining() {
    val fci = visaPpseFci().toHex("")
    val firstHalf = fci.substring(0, 20)
    val rest = fci.substring(20)
    val restLen = "%02X".format(rest.length / 2)
    val card =
      FakeCard(mapOf(ppseSelect to firstHalf + "61" + restLen, "00C00000$restLen" to rest + "9000"))
    assertEquals(
      listOf("Payment: Visa \"VISA CREDIT\" (AID A0000000031010)"),
      ApplicationProber.probe(card),
    )
  }

  @Test
  fun decodesDesfireVersion() {
    // vendor NXP, type DESFire, subtype 1, major 0x12 (EV2), minor 0, storage 0x1A (8 KB), protocol 5
    val card = FakeCard(mapOf("9060000000" to "04010112001A05" + "91AF"))
    assertEquals(listOf("MIFARE DESFire EV2, 8192 bytes"), ApplicationProber.probe(card))
  }

  @Test
  fun nothingFound() {
    assertEquals(listOf("No known applications answered"), ApplicationProber.probe(FakeCard(emptyMap())))
  }

  @Test
  fun tagLostMidProbeKeepsPartialResults() {
    val card = FakeCard(mapOf(ppseSelect to visaPpseFci().toHex("") + "9000"), failAfter = 2)
    val found = ApplicationProber.probe(card)
    assertEquals(2, found.size)
    assertTrue(found[0].startsWith("Payment: Visa"))
    assertEquals("Probing stopped: Tag was lost.", found[1])
  }

  @Test
  fun unknownPaymentNetworkStillListed() {
    val fci = tlv(0x6F, tlv(0xA5, tlv(0xBF0C, tlv(0x61, tlv(0x4F, "A0000009991010".hexToBytes())))))
    val card = FakeCard(mapOf(ppseSelect to fci.toHex("") + "9000"))
    assertEquals(listOf("Payment: Unknown network (AID A0000009991010)"), ApplicationProber.probe(card))
  }
}
