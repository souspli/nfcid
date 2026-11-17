package com.example.nfcid.nfc.passport

import com.example.nfcid.nfc.parseTlv
import com.example.nfcid.nfc.toHex
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.DefaultAlgorithmNameFinder
import org.jmrtd.lds.SODFile

/** Whether one data group's hash matches the hash stored in the SOD. */
data class DataGroupCheck(val dataGroup: Int, val expectedHex: String?, val actualHex: String) {
  val matches: Boolean
    get() = expectedHex == actualHex
}

/** Facts about the Document Signer certificate that matter for verification and circuit cost. */
data class DscInfo(
  val der: ByteArray,
  val subject: String,
  val issuer: String,
  val serialHex: String,
  val notBefore: Long,
  val notAfter: Long,
  /** e.g. `RSA`, `EC` */
  val keyAlgorithm: String,
  /** RSA modulus size, or EC field size. */
  val keySizeBits: Int,
  /** Named EC curve, `explicit: <name>` when explicit params match a known curve, else null. */
  val curve: String?,
)

data class PassiveAuthResult(
  val digestAlgorithm: String,
  val dataGroupHashes: Map<Int, ByteArray>,
  val dataGroupChecks: List<DataGroupCheck>,
  val signatureValid: Boolean,
  /** Why verification failed (exception class and message), null when valid. */
  val signatureError: String?,
  val signatureAlgorithmName: String,
  val signatureAlgorithmOid: String,
  val signerDigestAlgorithmOid: String,
  /** DER of the encapsulated LDSSecurityObject, i.e. what the data-group hashes live in. */
  val eContent: ByteArray,
  /** DER (SET) of the signed attributes: the bytes the DSC actually signed. */
  val signedAttributes: ByteArray,
  val signature: ByteArray,
  val dsc: DscInfo?,
  /** Byte offset of the DG1 hash within [eContent], or -1. Handy for circuit inputs. */
  val dg1HashOffsetInEContent: Int,
  /** Byte offset of hash(eContent) (the messageDigest attribute) within [signedAttributes], or -1. */
  val eContentDigestOffsetInSignedAttributes: Int,
) {
  val allDataGroupsMatch: Boolean
    get() = dataGroupChecks.isNotEmpty() && dataGroupChecks.all { it.matches }
}

/**
 * ICAO 9303 passive authentication without the CSCA step: checks each data group against the SOD,
 * and checks the SOD's CMS signature with the Document Signer certificate embedded in it.
 *
 * Chain validation DSC → CSCA needs a country master list and is done separately.
 */
object PassiveAuth {

  private val bouncyCastle = BouncyCastleProvider()

  /**
   * @param sod EF.SOD exactly as read from the chip (with its `77` tag).
   * @param dataGroups raw data-group files keyed by number (1, 14, 15...).
   */
  fun verify(sod: ByteArray, dataGroups: Map<Int, ByteArray>): PassiveAuthResult {
    val sodFile = SODFile(ByteArrayInputStream(sod))
    val digestAlgorithm = sodFile.digestAlgorithm
    val storedHashes = sodFile.dataGroupHashes

    val checks =
      dataGroups.toSortedMap().map { (number, bytes) ->
        val actual = MessageDigest.getInstance(digestAlgorithm, bouncyCastle).digest(bytes)
        DataGroupCheck(number, storedHashes[number]?.toHex(""), actual.toHex(""))
      }

    val signedData = CMSSignedData(unwrapSod(sod))
    val signer = signedData.signerInfos.signers.first()
    val certHolder = signerCertificate(signedData, signer) ?: X509CertificateHolder(sodFile.docSigningCertificate.encoded)

    var error: String? = null
    val valid =
      try {
        signer.verify(JcaSimpleSignerInfoVerifierBuilder().setProvider(bouncyCastle).build(certHolder))
      } catch (e: Exception) {
        error = "${e.javaClass.simpleName}: ${e.message}"
        false
      }
    if (!valid && error == null) error = "Signature does not verify with the embedded DSC"

    // Note: JMRTD's SODFile.getEContent() returns the signed attributes, not the LDSSecurityObject,
    // so take the encapsulated content from the CMS structure directly.
    val eContent = signedData.signedContent?.content as? ByteArray ?: byteArrayOf()
    val signedAttrs = signer.encodedSignedAttributes ?: byteArrayOf()
    val messageDigest =
      signer.signedAttributes?.get(CMSAttributes.messageDigest)?.attrValues?.getObjectAt(0)?.let {
        ASN1OctetString.getInstance(it).octets
      }
    val sigOid = signer.encryptionAlgOID

    return PassiveAuthResult(
      digestAlgorithm = digestAlgorithm,
      dataGroupHashes = storedHashes,
      dataGroupChecks = checks,
      signatureValid = valid,
      signatureError = error,
      signatureAlgorithmName = algorithmName(sigOid),
      signatureAlgorithmOid = sigOid,
      signerDigestAlgorithmOid = signer.digestAlgOID,
      eContent = eContent,
      signedAttributes = signedAttrs,
      signature = signer.signature,
      dsc = describeDsc(certHolder),
      dg1HashOffsetInEContent = storedHashes[1]?.let { eContent.indexOf(it) } ?: -1,
      eContentDigestOffsetInSignedAttributes = messageDigest?.let { signedAttrs.indexOf(it) } ?: -1,
    )
  }

  /** EF.SOD is `77 len ContentInfo`; CMS wants the ContentInfo. */
  internal fun unwrapSod(sod: ByteArray): ByteArray =
    parseTlv(sod).firstOrNull { it.tag == 0x77 }?.value
      ?: throw IllegalArgumentException("EF.SOD does not start with tag 77")

  private fun signerCertificate(data: CMSSignedData, signer: SignerInformation): X509CertificateHolder? =
    data.certificates.getMatches(null).firstOrNull { signer.sid.match(it) }

  private fun algorithmName(oid: String): String =
    runCatching { DefaultAlgorithmNameFinder().getAlgorithmName(ASN1ObjectIdentifier(oid)) }
      .getOrNull()
      ?.takeIf { it != oid } ?: oid

  internal fun describeDsc(cert: X509CertificateHolder): DscInfo {
    val spki: SubjectPublicKeyInfo = cert.subjectPublicKeyInfo
    val algOid = spki.algorithm.algorithm
    var keyAlgorithm = algorithmName(algOid.id)
    var bits = 0
    var curve: String? = null
    when (algOid) {
      PKCSObjectIdentifiers.rsaEncryption,
      PKCSObjectIdentifiers.id_RSASSA_PSS -> {
        keyAlgorithm = "RSA"
        bits = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(spki.parsePublicKey()).modulus.bitLength()
      }
      X9ObjectIdentifiers.id_ecPublicKey -> {
        keyAlgorithm = "EC"
        val params = spki.algorithm.parameters
        if (params is ASN1ObjectIdentifier) {
          curve = ECNamedCurveTable.getName(params) ?: params.id
          bits = ECNamedCurveTable.getByOID(params)?.curve?.fieldSize ?: 0
        } else {
          // Many DSCs spell out the curve parameters instead of naming the curve.
          val explicit = X9ECParameters.getInstance(params)
          bits = explicit.curve.fieldSize
          curve = matchNamedCurve(explicit)?.let { "explicit: $it" } ?: "explicit (${bits}-bit field)"
        }
      }
    }
    return DscInfo(
      der = cert.encoded,
      subject = cert.subject.toString(),
      issuer = cert.issuer.toString(),
      serialHex = cert.serialNumber.toByteArray().toHex(""),
      notBefore = cert.notBefore.time,
      notAfter = cert.notAfter.time,
      keyAlgorithm = keyAlgorithm,
      keySizeBits = bits,
      curve = curve,
    )
  }

  private fun matchNamedCurve(explicit: X9ECParameters): String? {
    val names = ECNamedCurveTable.getNames().toList().filterIsInstance<String>()
    return names.firstOrNull { name ->
      val named = ECNamedCurveTable.getByName(name) ?: return@firstOrNull false
      named.curve.equals(explicit.curve) && named.g.equals(explicit.g) && named.n == explicit.n
    }
  }
}

/** Index of the first occurrence of [needle], or -1. */
internal fun ByteArray.indexOf(needle: ByteArray): Int {
  if (needle.isEmpty() || needle.size > size) return -1
  outer@ for (i in 0..size - needle.size) {
    for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
    return i
  }
  return -1
}
