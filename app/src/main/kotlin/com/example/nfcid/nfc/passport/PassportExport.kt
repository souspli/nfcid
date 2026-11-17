package com.example.nfcid.nfc.passport

import com.example.nfcid.nfc.toHex
import java.io.File
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * JSON written for circuit development. Raw chip files are base64 (byte-exact); derived values the
 * circuit needs (eContent, signed attributes, signature, offsets) are hex.
 */
@Serializable
data class PassportExport(
  val schemaVersion: Int = SCHEMA_VERSION,
  val readAt: String,
  val accessProtocol: String,
  val paceOid: String? = null,
  /** Base64 of each raw file, keyed `EF.COM`, `EF.SOD`, `DG1`, `DG14`, `DG15`. */
  val files: Map<String, String>,
  val dg1: Dg1Export,
  val passiveAuth: PassiveAuthExport,
  val chipAuth: ChipAuthExport,
) {
  @Serializable
  data class Dg1Export(
    val documentCode: String,
    val documentFormat: String,
    val issuingState: String,
    val nationality: String,
    val dateOfBirth: String,
    val dateOfExpiry: String,
    val sex: String,
  )

  @Serializable
  data class PassiveAuthExport(
    val digestAlgorithm: String,
    val signatureAlgorithm: String,
    val signatureAlgorithmOid: String,
    val signerDigestAlgorithmOid: String,
    /** Stored hash per data group number, hex. */
    val dataGroupHashes: Map<String, String>,
    /** Data group number → whether our hash of the raw file matched. */
    val dataGroupHashMatches: Map<String, Boolean>,
    val signatureValid: Boolean,
    val signatureError: String? = null,
    val eContentHex: String,
    val signedAttributesHex: String,
    val signatureHex: String,
    val dg1HashOffsetInEContent: Int,
    val eContentDigestOffsetInSignedAttributes: Int,
    val dsc: DscExport? = null,
  )

  @Serializable
  data class DscExport(
    val derBase64: String,
    val subject: String,
    val issuer: String,
    val serialHex: String,
    val notBefore: String,
    val notAfter: String,
    val keyAlgorithm: String,
    val keySizeBits: Int,
    val curve: String? = null,
  )

  @Serializable
  data class ChipAuthExport(
    val method: String,
    val status: String,
    val detail: String? = null,
    val aaChallengeHex: String? = null,
    val aaResponseHex: String? = null,
  )

  fun toJson(): String = json.encodeToString(serializer(), this)

  companion object {
    const val SCHEMA_VERSION = 1
    private val json = Json {
      prettyPrint = true
      encodeDefaults = true
    }

    fun fromJson(text: String): PassportExport = json.decodeFromString(serializer(), text)

    fun from(result: PassportReadResult): PassportExport {
      val b64 = Base64.getEncoder()
      val pa = result.passiveAuth
      return PassportExport(
        readAt = iso(result.readAtMillis),
        accessProtocol = result.accessProtocol,
        paceOid = result.paceOid,
        files = result.files.mapValues { (_, bytes) -> b64.encodeToString(bytes) },
        dg1 =
          with(result.dg1) {
            Dg1Export(documentCode, documentFormat, issuingState, nationality, dateOfBirth, dateOfExpiry, sex)
          },
        passiveAuth =
          PassiveAuthExport(
            digestAlgorithm = pa.digestAlgorithm,
            signatureAlgorithm = pa.signatureAlgorithmName,
            signatureAlgorithmOid = pa.signatureAlgorithmOid,
            signerDigestAlgorithmOid = pa.signerDigestAlgorithmOid,
            dataGroupHashes = pa.dataGroupHashes.toSortedMap().entries.associate { (k, v) -> k.toString() to v.toHex("") },
            dataGroupHashMatches = pa.dataGroupChecks.associate { it.dataGroup.toString() to it.matches },
            signatureValid = pa.signatureValid,
            signatureError = pa.signatureError,
            eContentHex = pa.eContent.toHex(""),
            signedAttributesHex = pa.signedAttributes.toHex(""),
            signatureHex = pa.signature.toHex(""),
            dg1HashOffsetInEContent = pa.dg1HashOffsetInEContent,
            eContentDigestOffsetInSignedAttributes = pa.eContentDigestOffsetInSignedAttributes,
            dsc =
              pa.dsc?.let {
                DscExport(
                  derBase64 = b64.encodeToString(it.der),
                  subject = it.subject,
                  issuer = it.issuer,
                  serialHex = it.serialHex,
                  notBefore = iso(it.notBefore),
                  notAfter = iso(it.notAfter),
                  keyAlgorithm = it.keyAlgorithm,
                  keySizeBits = it.keySizeBits,
                  curve = it.curve,
                )
              },
          ),
        chipAuth =
          with(result.chipAuth) {
            ChipAuthExport(method, status.name, detail, aaChallenge?.toHex(""), aaResponse?.toHex(""))
          },
      )
    }

    private fun iso(millis: Long) = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(millis))
  }
}

/** Passport exports in app-private storage (`files/passport/`), never in shared storage or logs. */
class PassportStore(private val dir: File) {

  fun save(export: PassportExport, readAtMillis: Long): File {
    dir.mkdirs()
    val name = "passport-" + FILE_TIME.format(Instant.ofEpochMilli(readAtMillis)) + ".json"
    val file = File(dir, name)
    file.writeText(export.toJson())
    return file
  }

  fun list(): List<File> = dir.listFiles { f -> f.name.endsWith(".json") }?.sortedBy { it.name }.orEmpty()

  /** Deletes every stored export; returns how many were removed. */
  fun deleteAll(): Int = list().count { it.delete() }

  private companion object {
    val FILE_TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneOffset.UTC)
  }
}
