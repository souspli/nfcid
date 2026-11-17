package com.example.nfcid.nfc.passport

import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.os.SystemClock
import android.util.Log
import java.io.ByteArrayInputStream
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import net.sf.scuba.smartcards.CardServiceException
import net.sf.scuba.smartcards.IsoDepCardService
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA224Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.signers.ISO9796d2Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jmrtd.BACKey
import org.jmrtd.PassportService
import org.jmrtd.lds.ActiveAuthenticationInfo
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.ChipAuthenticationInfo
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.LDSFileUtil
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.SecurityInfo
import org.jmrtd.lds.icao.COMFile
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG15File

enum class PassportStep(val label: String) {
  Connecting("Connecting"),
  Authenticating("Authenticating (PACE/BAC)"),
  ReadingCom("Reading EF.COM"),
  ReadingSod("Reading EF.SOD"),
  ReadingDg1("Reading DG1"),
  ReadingDg14("Reading DG14"),
  ReadingDg15("Reading DG15"),
  ChipAuthentication("Checking the chip is genuine"),
  Verifying("Verifying signature"),
}

sealed interface PassportReadOutcome {
  data class Success(val result: PassportReadResult) : PassportReadOutcome

  data class Failure(val step: PassportStep, val message: String) : PassportReadOutcome
}

/**
 * Reads the proof-relevant files from an ICAO eMRTD with JMRTD, then runs [PassiveAuth].
 *
 * Blocks for several seconds: call it on the reader-mode callback thread, never the main thread.
 * Logs only step names, timings and error classes — never MRZ or DG1 contents.
 */
class PassportReader(private val onStep: (PassportStep) -> Unit) {

  fun read(tag: Tag, key: MrzKey): PassportReadOutcome {
    val started = SystemClock.elapsedRealtime()
    val isoDep = IsoDep.get(tag) ?: return PassportReadOutcome.Failure(PassportStep.Connecting, "Not an ISO-DEP chip")
    var step = PassportStep.Connecting
    fun enter(next: PassportStep) {
      step = next
      Log.i(TAG, "Passport: ${next.name} at ${SystemClock.elapsedRealtime() - started} ms")
      onStep(next)
    }

    val cardService = IsoDepCardService(isoDep)
    try {
      enter(PassportStep.Connecting)
      isoDep.timeout = TIMEOUT_MS
      cardService.open()
      val service =
        PassportService(
          cardService,
          PassportService.NORMAL_MAX_TRANSCEIVE_LENGTH,
          PassportService.DEFAULT_MAX_BLOCKSIZE,
          false,
          false,
        )
      service.open()

      enter(PassportStep.Authenticating)
      val bacKey = BACKey(key.documentNumber, key.dateOfBirth, key.dateOfExpiry)
      val paceOid = tryPace(service, bacKey)
      service.sendSelectApplet(paceOid != null)
      if (paceOid == null) service.doBAC(bacKey)
      val protocol = if (paceOid != null) "PACE" else "BAC"
      Log.i(TAG, "Passport: authenticated with $protocol")

      val files = linkedMapOf<String, ByteArray>()
      enter(PassportStep.ReadingCom)
      val com = service.readFile(PassportService.EF_COM)
      files["EF.COM"] = com
      enter(PassportStep.ReadingSod)
      val sod = service.readFile(PassportService.EF_SOD)
      files["EF.SOD"] = sod
      enter(PassportStep.ReadingDg1)
      val dg1 = service.readFile(PassportService.EF_DG1)
      files["DG1"] = dg1

      val present =
        LDSFileUtil.getDataGroupNumbers(COMFile(ByteArrayInputStream(com))).toSet() +
          SODFile(ByteArrayInputStream(sod)).dataGroupHashes.keys
      val dataGroups = linkedMapOf(1 to dg1)
      var dg14: DG14File? = null
      var dg15: DG15File? = null
      if (14 in present) {
        enter(PassportStep.ReadingDg14)
        val bytes = service.readFile(PassportService.EF_DG14)
        files["DG14"] = bytes
        dataGroups[14] = bytes
        dg14 = DG14File(ByteArrayInputStream(bytes))
      }
      if (15 in present) {
        enter(PassportStep.ReadingDg15)
        val bytes = service.readFile(PassportService.EF_DG15)
        files["DG15"] = bytes
        dataGroups[15] = bytes
        dg15 = DG15File(ByteArrayInputStream(bytes))
      }

      enter(PassportStep.ChipAuthentication)
      val chipAuth =
        when {
          dg14 != null && dg14.infos<ChipAuthenticationPublicKeyInfo>().isNotEmpty() ->
            chipAuthentication(service, dg14, com)
          dg15 != null -> activeAuthentication(service, dg15.publicKey, dg14)
          else -> ChipAuthResult("none", ChipAuthResult.Status.NotSupported, "No DG14 or DG15 on this chip")
        }
      Log.i(TAG, "Passport: ${chipAuth.method} ${chipAuth.status}")

      enter(PassportStep.Verifying)
      val passive = PassiveAuth.verify(sod, dataGroups)
      Log.i(TAG, "Passport: hashes match=${passive.allDataGroupsMatch} signature valid=${passive.signatureValid}")

      return PassportReadOutcome.Success(
        PassportReadResult(
          readAtMillis = System.currentTimeMillis(),
          accessProtocol = protocol,
          paceOid = paceOid,
          files = files,
          dg1 = Dg1Fields.parse(dg1),
          passiveAuth = passive,
          chipAuth = chipAuth,
          durationMillis = SystemClock.elapsedRealtime() - started,
        )
      )
    } catch (e: Exception) {
      Log.w(TAG, "Passport: failed at ${step.name}: ${e.javaClass.simpleName} ${swOf(e)}")
      return PassportReadOutcome.Failure(step, describe(e, step))
    } finally {
      runCatching { cardService.close() }
    }
  }

  /** Tries each PACEInfo from EF.CardAccess; returns the OID that worked, or null to use BAC. */
  private fun tryPace(service: PassportService, bacKey: BACKey): String? {
    val infos =
      try {
        CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS, PassportService.DEFAULT_MAX_BLOCKSIZE))
          .securityInfos
          .filterIsInstance<PACEInfo>()
      } catch (e: Exception) {
        if (isTagLost(e)) throw e
        Log.i(TAG, "Passport: no EF.CardAccess (${e.javaClass.simpleName}), using BAC")
        return null
      }
    for (info in infos) {
      try {
        service.doPACE(bacKey, info.objectIdentifier, PACEInfo.toParameterSpec(info.parameterId), info.parameterId)
        return info.objectIdentifier
      } catch (e: Exception) {
        if (isTagLost(e)) throw e
        Log.i(TAG, "Passport: PACE ${info.objectIdentifier} failed (${e.javaClass.simpleName} ${swOf(e)})")
      }
    }
    return null
  }

  /**
   * EAC Chip Authentication: key agreement with the chip's DG14 key. Only a chip holding the
   * matching private key can derive the new session keys, so a successful re-read of EF.COM under
   * them proves the chip is genuine (DG14 itself is covered by the SOD signature).
   */
  private fun chipAuthentication(service: PassportService, dg14: DG14File, com: ByteArray): ChipAuthResult {
    val keyInfo = dg14.infos<ChipAuthenticationPublicKeyInfo>().first()
    val publicKey = keyInfo.subjectPublicKey
    val caInfo: ChipAuthenticationInfo? =
      dg14.infos<ChipAuthenticationInfo>().let { infos -> infos.firstOrNull { it.keyId == keyInfo.keyId } ?: infos.firstOrNull() }
    val oid =
      caInfo?.objectIdentifier
        ?: if (publicKey.algorithm.startsWith("EC")) SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC else SecurityInfo.ID_CA_DH_3DES_CBC_CBC
    return try {
      service.doEACCA(keyInfo.keyId, oid, keyInfo.objectIdentifier, publicKey)
      val reread = service.readFile(PassportService.EF_COM)
      if (reread.contentEquals(com)) {
        ChipAuthResult("Chip Authentication", ChipAuthResult.Status.Passed, "OID $oid")
      } else {
        ChipAuthResult("Chip Authentication", ChipAuthResult.Status.Failed, "EF.COM differed after CA")
      }
    } catch (e: Exception) {
      if (isTagLost(e)) throw e
      ChipAuthResult("Chip Authentication", ChipAuthResult.Status.Failed, "${e.javaClass.simpleName} ${swOf(e)}".trim())
    }
  }

  /** Active Authentication: the chip signs our random challenge with its DG15 private key. */
  private fun activeAuthentication(service: PassportService, publicKey: PublicKey, dg14: DG14File?): ChipAuthResult {
    val challenge = ByteArray(8).also { SecureRandom().nextBytes(it) }
    val sigOid = dg14?.infos<ActiveAuthenticationInfo>()?.firstOrNull()?.signatureAlgorithmOID
    val ecAlgorithm = sigOid?.let { runCatching { ActiveAuthenticationInfo.lookupMnemonicByOID(it) }.getOrNull() }
    val (digestAlgorithm, signatureAlgorithm) =
      if (publicKey is RSAPublicKey) "SHA-1" to "SHA1WithRSA/ISO9796-2"
      else (ecAlgorithm ?: "SHA256withECDSA").let { digestNameOf(it) to it }
    return try {
      val result = service.doAA(publicKey, digestAlgorithm, signatureAlgorithm, challenge)
      val response = result.response
      val (status, detail) =
        when (publicKey) {
          is RSAPublicKey -> verifyRsaAa(publicKey, challenge, response)
          is ECPublicKey -> verifyEcAa(publicKey, challenge, response, sigOid)
          else -> ChipAuthResult.Status.Unverified to "Unsupported key type ${publicKey.algorithm}"
        }
      ChipAuthResult("Active Authentication", status, detail, challenge, response)
    } catch (e: Exception) {
      if (isTagLost(e)) throw e
      ChipAuthResult("Active Authentication", ChipAuthResult.Status.Failed, "${e.javaClass.simpleName} ${swOf(e)}".trim(), challenge)
    }
  }

  /** ISO 9796-2 scheme 1: the response embeds a random recoverable part; our challenge is M2. */
  private fun verifyRsaAa(key: RSAPublicKey, challenge: ByteArray, response: ByteArray): Pair<ChipAuthResult.Status, String> {
    val params = RSAKeyParameters(false, key.modulus, key.publicExponent)
    val digests: List<Pair<String, () -> Digest>> =
      listOf("SHA-1" to ::SHA1Digest, "SHA-256" to ::SHA256Digest, "SHA-224" to ::SHA224Digest,
        "SHA-384" to ::SHA384Digest, "SHA-512" to ::SHA512Digest)
    for ((name, digest) in digests) {
      try {
        val signer = ISO9796d2Signer(RSAEngine(), digest(), name == "SHA-1")
        signer.init(false, params)
        signer.updateWithRecoveredMessage(response)
        signer.update(challenge, 0, challenge.size)
        if (signer.verifySignature(response)) return ChipAuthResult.Status.Passed to "RSA ISO 9796-2, $name"
        return ChipAuthResult.Status.Failed to "RSA ISO 9796-2 signature did not verify ($name)"
      } catch (_: Exception) {
        // Wrong digest for this trailer: try the next one.
      }
    }
    return ChipAuthResult.Status.Unverified to "Could not determine the RSA AA digest"
  }

  private fun verifyEcAa(key: ECPublicKey, challenge: ByteArray, response: ByteArray, sigOid: String?): Pair<ChipAuthResult.Status, String> {
    val algorithm =
      sigOid?.let { runCatching { ActiveAuthenticationInfo.lookupMnemonicByOID(it) }.getOrNull() }
        ?: return ChipAuthResult.Status.Unverified to "DG14 does not name the ECDSA AA algorithm"
    return try {
      val ok =
        Signature.getInstance(algorithm, BouncyCastleProvider()).run {
          initVerify(key)
          update(challenge)
          verify(response)
        }
      (if (ok) ChipAuthResult.Status.Passed else ChipAuthResult.Status.Failed) to "ECDSA $algorithm"
    } catch (e: Exception) {
      ChipAuthResult.Status.Unverified to "$algorithm: ${e.javaClass.simpleName}"
    }
  }

  /** `SHA256withPLAIN-ECDSA` → `SHA-256` */
  private fun digestNameOf(signatureAlgorithm: String): String =
    signatureAlgorithm.substringBefore("with").uppercase().replace(Regex("^SHA(\\d)"), "SHA-$1")

  private fun PassportService.readFile(fid: Short): ByteArray =
    getInputStream(fid, PassportService.DEFAULT_MAX_BLOCKSIZE).use { it.readBytes() }

  private inline fun <reified T> DG14File.infos(): List<T> = securityInfos.filterIsInstance<T>()

  private fun describe(e: Exception, step: PassportStep): String =
    when {
      isTagLost(e) -> "The passport moved away. Hold it still against the phone and try again."
      step == PassportStep.Authenticating ->
        "Couldn't unlock the chip. Check the document number and dates, then try again."
      else -> "Failed while ${step.label.lowercase()}: ${e.javaClass.simpleName} ${swOf(e)}".trim()
    }

  private fun isTagLost(e: Throwable): Boolean =
    generateSequence(e) { it.cause }.any { it is TagLostException }

  private fun swOf(e: Throwable): String =
    (e as? CardServiceException)?.sw?.takeIf { it != CardServiceException.SW_NONE && it > 0 }
      ?.let { "SW %04X".format(it and 0xFFFF) }.orEmpty()

  private companion object {
    const val TAG = "NfcId"
    const val TIMEOUT_MS = 5000
  }
}
