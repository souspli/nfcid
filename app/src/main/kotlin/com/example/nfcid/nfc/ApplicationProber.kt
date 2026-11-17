package com.example.nfcid.nfc

import java.io.ByteArrayOutputStream
import java.io.IOException

/** Sends one APDU and returns the raw response. Wraps `IsoDep.transceive` on a device. */
fun interface Transceiver {
  @Throws(IOException::class) fun transceive(apdu: ByteArray): ByteArray
}

/**
 * Asks an ISO-DEP card which applications it holds, using only read-only commands: SELECT and
 * DESFire GetVersion. It never sends READ RECORD / GET PROCESSING OPTIONS, so payment card numbers
 * and passport data groups are not read.
 */
object ApplicationProber {

  /** Returns one display line per application found. Stops early if the card leaves the field. */
  fun probe(card: Transceiver): List<String> {
    val found = mutableListOf<String>()
    try {
      val ppse = card.send(Apdu.selectByName(KnownApplications.PPSE))
      if (Apdu.statusWord(ppse) == Apdu.SW_SUCCESS) {
        found += describePaymentDirectory(Apdu.data(ppse))
      }
      for (probe in KnownApplications.PROBES) {
        val response = card.send(Apdu.selectByName(probe.aid, probe.returnFci))
        if (Apdu.statusWord(response) == Apdu.SW_SUCCESS) {
          found += describeSelected(probe, Apdu.data(response))
        }
      }
      val version = card.transceive(Apdu.DESFIRE_GET_VERSION)
      if (Apdu.statusWord(version) == Apdu.SW_DESFIRE_MORE) {
        describeDesfireVersion(Apdu.data(version))?.let { found += it }
      }
    } catch (e: IOException) {
      found += "Probing stopped: ${e.message ?: e.javaClass.simpleName}"
    }
    if (found.isEmpty()) found += "No known applications answered"
    return found
  }

  /** Sends [apdu], following `61xx` (more data available) with GET RESPONSE. */
  private fun Transceiver.send(apdu: ByteArray): ByteArray {
    var response = transceive(apdu)
    val collected = ByteArrayOutputStream()
    repeat(MAX_GET_RESPONSE) {
      val sw = Apdu.statusWord(response) ?: return response
      if ((sw shr 8) != 0x61) return collected.toByteArray() + response
      collected.write(Apdu.data(response))
      response = transceive(Apdu.getResponse(sw and 0xFF))
    }
    return collected.toByteArray() + response
  }

  /** Lists the entries (tag 61) of a PPSE FCI: AID (4F), label (50). */
  internal fun describePaymentDirectory(fci: ByteArray): List<String> {
    val entries = parseTlv(fci).allWithTag(0x61)
    if (entries.isEmpty()) return listOf("Payment directory present (no entries listed)")
    return entries.map { entry ->
      val aid = entry.children.firstWithTag(0x4F)?.value
      val label = entry.children.firstWithTag(0x50)?.value?.let(::printable)
      val network = aid?.let(KnownApplications::paymentNetwork) ?: "Unknown network"
      buildString {
        append("Payment: ").append(network)
        if (!label.isNullOrEmpty()) append(" \"").append(label).append('"')
        if (aid != null) append(" (AID ").append(aid.toHex(separator = "")).append(')')
      }
    }
  }

  private fun describeSelected(probe: AppProbe, fci: ByteArray): String {
    val label = parseTlv(fci).firstWithTag(0x50)?.value?.let(::printable)
    return if (label.isNullOrEmpty()) probe.name else "${probe.name} \"$label\""
  }

  /**
   * Decodes the first GetVersion frame: vendor, type, subtype, major, minor, storage, protocol.
   * Returns null if the frame is too short.
   */
  internal fun describeDesfireVersion(frame: ByteArray): String? {
    if (frame.size < 7) return null
    val vendor = frame[0].toInt() and 0xFF
    val type = frame[1].toInt() and 0xFF
    val major = frame[3].toInt() and 0xFF
    val minor = frame[4].toInt() and 0xFF
    val storage = frame[5].toInt() and 0xFF
    // Storage byte: 2^(n/2) bytes; an odd value means "between 2^(n/2) and 2^(n/2 + 1)".
    val size = 1 shl (storage shr 1)
    val sizeText = if (storage and 1 == 1) "${size}-${size * 2} bytes" else "$size bytes"
    val name =
      if (vendor == 0x04 && type == 0x01) {
        val generation =
          when (major) {
            0x00 -> "EV0"
            0x01 -> "EV1"
            0x12 -> "EV2"
            0x33 -> "EV3"
            else -> "version 0x%02X".format(major)
          }
        "MIFARE DESFire $generation"
      } else {
        "NXP GetVersion: vendor 0x%02X, type 0x%02X, version %d.%d".format(vendor, type, major, minor)
      }
    return "$name, $sizeText"
  }

  private fun printable(bytes: ByteArray): String =
    String(bytes, Charsets.ISO_8859_1).filter { it in ' '..'~' }.trim()

  private const val MAX_GET_RESPONSE = 8
}
