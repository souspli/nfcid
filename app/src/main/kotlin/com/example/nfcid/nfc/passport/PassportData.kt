package com.example.nfcid.nfc.passport

import com.example.nfcid.nfc.firstWithTag
import com.example.nfcid.nfc.parseTlv
import java.io.ByteArrayInputStream
import org.jmrtd.lds.icao.DG1File

/** Non-name DG1 fields, enough for citizenship/age proofs and for showing the user what was read. */
data class Dg1Fields(
  /** e.g. `P` for passport */
  val documentCode: String,
  /** TD1 / TD2 / TD3 */
  val documentFormat: String,
  val issuingState: String,
  val nationality: String,
  /** YYMMDD */
  val dateOfBirth: String,
  /** YYMMDD */
  val dateOfExpiry: String,
  val sex: String,
  /** Last 3 characters of the document number, for display only. */
  val documentNumberSuffix: String,
) {
  companion object {
    fun parse(dg1: ByteArray): Dg1Fields {
      val mrz = DG1File(ByteArrayInputStream(dg1)).mrzInfo
      val docNumber = mrz.documentNumber.trimEnd('<')
      // DG1 is 61 { 5F1F <MRZ characters> }; the MRZ length identifies the document format.
      val mrzLength = parseTlv(dg1).firstWithTag(0x5F1F)?.value?.size
      return Dg1Fields(
        documentCode = mrz.documentCode.trimEnd('<'),
        documentFormat =
          when (mrzLength) {
            90 -> "TD1"
            72 -> "TD2"
            88 -> "TD3"
            else -> "unknown"
          },
        issuingState = mrz.issuingState,
        nationality = mrz.nationality,
        dateOfBirth = mrz.dateOfBirth,
        dateOfExpiry = mrz.dateOfExpiry,
        sex = mrz.genderCode.toString(),
        documentNumberSuffix = docNumber.takeLast(3),
      )
    }
  }
}

/** Outcome of proving the chip is genuine (holds the private key matching DG14/DG15). */
data class ChipAuthResult(
  /** `Chip Authentication`, `Active Authentication`, or `none` */
  val method: String,
  val status: Status,
  val detail: String? = null,
  /** Active Authentication only: the random challenge we sent and the chip's signature over it. */
  val aaChallenge: ByteArray? = null,
  val aaResponse: ByteArray? = null,
) {
  enum class Status { Passed, Failed, Unverified, NotSupported }
}

/** Everything read from one passport. Raw files are kept byte-exact for later proofs. */
data class PassportReadResult(
  val readAtMillis: Long,
  /** `PACE` or `BAC` */
  val accessProtocol: String,
  val paceOid: String?,
  /** Raw files keyed `EF.COM`, `EF.SOD`, `DG1`, `DG14`, `DG15`. */
  val files: Map<String, ByteArray>,
  val dg1: Dg1Fields,
  val passiveAuth: PassiveAuthResult,
  val chipAuth: ChipAuthResult,
  val durationMillis: Long,
)
