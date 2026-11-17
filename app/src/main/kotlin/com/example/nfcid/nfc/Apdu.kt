package com.example.nfcid.nfc

/** ISO 7816-4 command/response helpers. Pure Kotlin, no Android dependencies. */
object Apdu {

  const val SW_SUCCESS = 0x9000
  /** DESFire native status "additional frame": more data follows. */
  const val SW_DESFIRE_MORE = 0x91AF

  /** DESFire native GetVersion, ISO-wrapped. Read-only; returns hardware info. */
  val DESFIRE_GET_VERSION = byteArrayOf(0x90.toByte(), 0x60, 0x00, 0x00, 0x00)

  /**
   * SELECT by DF name (AID). With [returnFci] the card is asked for its File Control Information
   * (P2=00, Le=00); without it, no response data is requested (P2=0C), which some applications,
   * such as e-passports, expect.
   */
  fun selectByName(aid: ByteArray, returnFci: Boolean = true): ByteArray {
    require(aid.size in 1..16) { "AID must be 1-16 bytes" }
    val header = byteArrayOf(0x00, 0xA4.toByte(), 0x04, if (returnFci) 0x00 else 0x0C, aid.size.toByte())
    return if (returnFci) header + aid + byteArrayOf(0x00) else header + aid
  }

  fun getResponse(length: Int): ByteArray =
    byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, length.toByte())

  /** The trailing two status bytes as an Int (e.g. 0x9000), or null if the response is too short. */
  fun statusWord(response: ByteArray): Int? =
    if (response.size < 2) null
    else ((response[response.size - 2].toInt() and 0xFF) shl 8) or
      (response[response.size - 1].toInt() and 0xFF)

  /** Response data without the status word. */
  fun data(response: ByteArray): ByteArray =
    if (response.size < 2) byteArrayOf() else response.copyOfRange(0, response.size - 2)
}

/** Parses hex like `A0000002471001` (no separators). */
fun String.hexToBytes(): ByteArray {
  require(length % 2 == 0) { "Odd-length hex: $this" }
  return ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}
