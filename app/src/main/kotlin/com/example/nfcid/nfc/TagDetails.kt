package com.example.nfcid.nfc

/** Everything we pulled out of one tag scan, already formatted for display. */
data class TagDetails(
  /** Tag UID as colon-separated hex, e.g. `04:A2:3B:1C:5D:80:00`. */
  val uid: String,
  /** Short tech names reported by Android, e.g. `NfcA`, `IsoDep`, `Ndef`. */
  val techs: List<String>,
  /** Tech-specific properties as label/value pairs (ATQA, SAK, NDEF size, ...). */
  val properties: List<Pair<String, String>>,
  /** One human-readable line per NDEF record, if the tag holds an NDEF message. */
  val ndefRecords: List<String>,
  val scannedAtMillis: Long,
  /** Smart-card applications that answered a SELECT (ISO-DEP cards only). */
  val applications: List<String> = emptyList(),
)

/** Upper-case hex, two digits per byte, joined by [separator]. */
fun ByteArray.toHex(separator: String = ":"): String =
  joinToString(separator) { "%02X".format(it.toInt() and 0xFF) }

/** Like [toHex], but `(none)` for an empty array so the UI never shows a blank value. */
fun ByteArray.toHexOrNone(): String = if (isEmpty()) "(none)" else toHex()

/**
 * Decodes the payload of an NFC Forum "T" (text) well-known record.
 *
 * Layout: one status byte (bit 7 = UTF-16 if set, bits 0-5 = language code length), then the
 * IANA language code, then the text. Returns `"[lang] text"`, or null if the payload is malformed.
 */
fun decodeTextRecordPayload(payload: ByteArray): String? {
  if (payload.isEmpty()) return null
  val status = payload[0].toInt()
  val utf16 = status and 0x80 != 0
  val langLength = status and 0x3F
  if (1 + langLength > payload.size) return null
  val lang = String(payload, 1, langLength, Charsets.US_ASCII)
  val textStart = 1 + langLength
  val charset = if (utf16) Charsets.UTF_16 else Charsets.UTF_8
  val text = String(payload, textStart, payload.size - textStart, charset)
  return if (lang.isEmpty()) text else "[$lang] $text"
}
