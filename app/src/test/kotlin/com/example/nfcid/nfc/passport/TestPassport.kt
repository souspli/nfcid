package com.example.nfcid.nfc.passport

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.MRZInfo

/** Builds a fake but correctly signed passport for tests. No real passport data. */
object TestPassport {

  /** ICAO 9303 specimen MRZ (fictional "Utopia" passport for Anna Maria Eriksson). */
  const val SPECIMEN_MRZ =
    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" + "L898902C36UTO7408122F1204159ZE184226B<<<<<10"

  init {
    Security.removeProvider("BC")
    Security.insertProviderAt(BouncyCastleProvider(), 1)
  }

  val dg1: ByteArray by lazy { DG1File(MRZInfo(SPECIMEN_MRZ)).encoded }

  /** Stand-in for DG2 (face): JMRTD requires at least two hashes in a SOD, as ICAO does. */
  val dg2Placeholder = byteArrayOf(0x75, 0x03, 0x01, 0x02, 0x03)

  class Signed(val sod: ByteArray, val dataGroups: Map<Int, ByteArray>, val keyPair: KeyPair)

  fun rsaKeyPair(): KeyPair =
    KeyPairGenerator.getInstance("RSA", "BC").apply { initialize(2048) }.generateKeyPair()

  fun ecKeyPair(curve: String = "brainpoolP256r1"): KeyPair =
    KeyPairGenerator.getInstance("EC", "BC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

  /** A SOD over [dataGroups] (default: DG1 only), signed by a self-signed DSC for [keyPair]. */
  fun sign(
    keyPair: KeyPair,
    signatureAlgorithm: String,
    dataGroups: Map<Int, ByteArray> = mapOf(1 to dg1, 2 to dg2Placeholder),
    digestAlgorithm: String = "SHA-256",
  ): Signed {
    val hashes = dataGroups.mapValues { (_, bytes) -> MessageDigest.getInstance(digestAlgorithm).digest(bytes) }
    val cert = selfSigned(keyPair, signatureAlgorithm)
    val sod = SODFile(digestAlgorithm, signatureAlgorithm, hashes, keyPair.private, cert).encoded
    return Signed(sod, dataGroups, keyPair)
  }

  private fun selfSigned(keyPair: KeyPair, signatureAlgorithm: String): X509Certificate {
    val name = X500Name("C=UT, O=Test Authority, CN=Test Document Signer")
    val now = System.currentTimeMillis()
    val builder =
      JcaX509v3CertificateBuilder(
        name,
        BigInteger.valueOf(4242),
        Date(now - DAY),
        Date(now + 365 * DAY),
        name,
        keyPair.public,
      )
    val signer = JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(keyPair.private)
    return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
  }

  private const val DAY = 24L * 60 * 60 * 1000
}
