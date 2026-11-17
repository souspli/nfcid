package com.example.nfcid.nfc

import android.nfc.NdefRecord
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.MifareClassic
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import android.nfc.tech.NfcF
import android.nfc.tech.NfcV
import java.io.IOException

/**
 * Extracts [TagDetails] from a discovered [Tag].
 *
 * Tech properties come from values Android cached during discovery. For ISO-DEP cards it then
 * connects and runs [ApplicationProber] (read-only SELECTs), so this blocks for a few hundred ms
 * and must run off the main thread — the reader-mode callback thread is fine.
 */
object TagReader {

  /** Generous: passports took ~1 s to answer Android's own NDEF check. */
  private const val PROBE_TIMEOUT_MS = 2000

  fun read(tag: Tag, scannedAtMillis: Long): TagDetails {
    val props = mutableListOf<Pair<String, String>>()

    NfcA.get(tag)?.let {
      props += "ATQA" to it.atqa.toHex()
      props += "SAK" to "0x%02X".format(it.sak.toInt())
    }
    NfcB.get(tag)?.let {
      props += "Application data" to it.applicationData.toHex()
      props += "Protocol info" to it.protocolInfo.toHex()
    }
    NfcF.get(tag)?.let {
      props += "Manufacturer" to it.manufacturer.toHex()
      props += "System code" to it.systemCode.toHex()
    }
    NfcV.get(tag)?.let {
      props += "DSF ID" to "0x%02X".format(it.dsfId.toInt() and 0xFF)
      props += "Response flags" to "0x%02X".format(it.responseFlags.toInt() and 0xFF)
    }
    val isoDep = IsoDep.get(tag)
    isoDep?.let {
      // Empty is meaningful (e.g. passports send none), so show it rather than a blank value.
      it.historicalBytes?.let { bytes -> props += "Historical bytes" to bytes.toHexOrNone() }
      it.hiLayerResponse?.let { bytes -> props += "Hi-layer response" to bytes.toHexOrNone() }
    }
    // MIFARE Classic is only exposed on devices with NXP controllers; elsewhere get() returns null.
    runCatching { MifareClassic.get(tag) }.getOrNull()?.let {
      props += "MIFARE Classic" to "${classicTypeName(it.type)}, ${it.size} bytes"
    }
    MifareUltralight.get(tag)?.let {
      props += "MIFARE Ultralight" to ultralightTypeName(it.type)
    }

    val ndef = Ndef.get(tag)
    ndef?.let {
      props += "NDEF type" to it.type
      props += "NDEF capacity" to "${it.maxSize} bytes"
      props += "NDEF writable" to if (it.isWritable) "yes" else "no"
    }
    val records = ndef?.cachedNdefMessage?.records?.map(::describeRecord).orEmpty()
    val applications = isoDep?.let(::probeApplications).orEmpty()

    return TagDetails(
      uid = tag.id.toHex(),
      techs = tag.techList.map { it.substringAfterLast('.') },
      properties = props,
      ndefRecords = records,
      scannedAtMillis = scannedAtMillis,
      applications = applications,
    )
  }

  private fun probeApplications(isoDep: IsoDep): List<String> =
    try {
      isoDep.connect()
      isoDep.timeout = PROBE_TIMEOUT_MS
      ApplicationProber.probe { apdu -> isoDep.transceive(apdu) }
    } catch (e: IOException) {
      listOf("Could not connect: ${e.message ?: e.javaClass.simpleName}")
    } catch (e: SecurityException) {
      // Thrown when the Tag object is stale (card already gone and rediscovered).
      listOf("Could not connect: ${e.message ?: e.javaClass.simpleName}")
    } finally {
      runCatching { isoDep.close() }
    }

  private fun describeRecord(record: NdefRecord): String {
    record.toUri()?.let { return "URI: $it" }
    if (record.tnf == NdefRecord.TNF_WELL_KNOWN && record.type.contentEquals(NdefRecord.RTD_TEXT)) {
      decodeTextRecordPayload(record.payload)?.let { return "Text: $it" }
    }
    record.toMimeType()?.let { return "MIME $it (${record.payload.size} bytes)" }
    val type = String(record.type, Charsets.US_ASCII)
    return "TNF ${record.tnf}, type \"$type\" (${record.payload.size} bytes)"
  }

  private fun classicTypeName(type: Int) =
    when (type) {
      MifareClassic.TYPE_CLASSIC -> "Classic"
      MifareClassic.TYPE_PLUS -> "Plus"
      MifareClassic.TYPE_PRO -> "Pro"
      else -> "unknown"
    }

  private fun ultralightTypeName(type: Int) =
    when (type) {
      MifareUltralight.TYPE_ULTRALIGHT -> "Ultralight"
      MifareUltralight.TYPE_ULTRALIGHT_C -> "Ultralight C"
      else -> "unknown variant"
    }
}
