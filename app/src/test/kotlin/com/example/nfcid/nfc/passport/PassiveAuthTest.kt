package com.example.nfcid.nfc.passport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PassiveAuthTest {

  @Test
  fun validRsaSod() {
    val signed = TestPassport.sign(TestPassport.rsaKeyPair(), "SHA256withRSA")
    val result = PassiveAuth.verify(signed.sod, signed.dataGroups)

    assertTrue(result.signatureError, result.signatureValid)
    assertTrue(result.allDataGroupsMatch)
    assertEquals("SHA-256", result.digestAlgorithm)
    val dsc = checkNotNull(result.dsc)
    assertEquals("RSA", dsc.keyAlgorithm)
    assertEquals(2048, dsc.keySizeBits)
    assertTrue(dsc.subject.contains("Test Document Signer"))
  }

  @Test
  fun validEcdsaBrainpoolSod() {
    val signed = TestPassport.sign(TestPassport.ecKeyPair("brainpoolP256r1"), "SHA256withECDSA")
    val result = PassiveAuth.verify(signed.sod, signed.dataGroups)

    assertTrue(result.signatureError, result.signatureValid)
    assertTrue(result.allDataGroupsMatch)
    val dsc = checkNotNull(result.dsc)
    assertEquals("EC", dsc.keyAlgorithm)
    assertEquals(256, dsc.keySizeBits)
    assertEquals("brainpoolP256r1", dsc.curve)
  }

  @Test
  fun offsetsPointAtTheHashes() {
    val signed = TestPassport.sign(TestPassport.rsaKeyPair(), "SHA256withRSA")
    val result = PassiveAuth.verify(signed.sod, signed.dataGroups)

    val dg1Hash = result.dataGroupHashes.getValue(1)
    val at = result.dg1HashOffsetInEContent
    assertTrue(at >= 0)
    assertTrue(result.eContent.copyOfRange(at, at + dg1Hash.size).contentEquals(dg1Hash))

    val eContentHash = java.security.MessageDigest.getInstance("SHA-256").digest(result.eContent)
    val md = result.eContentDigestOffsetInSignedAttributes
    assertTrue(md >= 0)
    assertTrue(result.signedAttributes.copyOfRange(md, md + 32).contentEquals(eContentHash))
  }

  @Test
  fun changedDg1FailsHashButSignatureStillValid() {
    val signed = TestPassport.sign(TestPassport.rsaKeyPair(), "SHA256withRSA")
    val tampered = signed.dataGroups.getValue(1).copyOf().also { it[10] = (it[10] + 1).toByte() }
    val result = PassiveAuth.verify(signed.sod, mapOf(1 to tampered))
    // DG2 isn't passed in, so only DG1 is checked.

    assertFalse(result.allDataGroupsMatch)
    assertFalse(result.dataGroupChecks.single().matches)
    assertTrue(result.signatureValid)
  }

  @Test
  fun changedSignatureFails() {
    val signed = TestPassport.sign(TestPassport.rsaKeyPair(), "SHA256withRSA")
    val signature = PassiveAuth.verify(signed.sod, signed.dataGroups).signature
    val at = signed.sod.indexOf(signature)
    assertTrue(at >= 0)
    val badSod = signed.sod.copyOf().also { it[at + 5] = (it[at + 5].toInt() xor 0x01).toByte() }

    val result = PassiveAuth.verify(badSod, signed.dataGroups)
    assertFalse(result.signatureValid)
    assertNotNull(result.signatureError)
    assertTrue(result.allDataGroupsMatch)
  }

  @Test
  fun dataGroupMissingFromSodIsReportedAsMismatch() {
    val signed = TestPassport.sign(TestPassport.rsaKeyPair(), "SHA256withRSA")
    val result = PassiveAuth.verify(signed.sod, signed.dataGroups + (15 to byteArrayOf(1, 2, 3)))
    val dg15 = result.dataGroupChecks.single { it.dataGroup == 15 }
    assertEquals(null, dg15.expectedHex)
    assertFalse(result.allDataGroupsMatch)
  }

  @Test
  fun specimenDg1Fields() {
    val f = Dg1Fields.parse(TestPassport.dg1)
    assertEquals("P", f.documentCode)
    assertEquals("TD3", f.documentFormat)
    assertEquals("UTO", f.issuingState)
    assertEquals("UTO", f.nationality)
    assertEquals("740812", f.dateOfBirth)
    assertEquals("120415", f.dateOfExpiry)
    assertEquals("2C3", f.documentNumberSuffix)
  }
}
