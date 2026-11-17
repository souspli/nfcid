package com.example.nfcid.nfc.passport

import java.nio.file.Files
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PassportExportTest {

  private fun sampleResult(): PassportReadResult {
    val signed = TestPassport.sign(TestPassport.ecKeyPair(), "SHA256withECDSA")
    return PassportReadResult(
      readAtMillis = 1_700_000_000_000,
      accessProtocol = "PACE",
      paceOid = "0.4.0.127.0.7.2.2.4.2.2",
      files = mapOf("EF.SOD" to signed.sod, "DG1" to TestPassport.dg1),
      dg1 = Dg1Fields.parse(TestPassport.dg1),
      passiveAuth = PassiveAuth.verify(signed.sod, signed.dataGroups),
      chipAuth = ChipAuthResult("none", ChipAuthResult.Status.NotSupported),
      durationMillis = 1234,
    )
  }

  @Test
  fun roundTripsThroughJson() {
    val export = PassportExport.from(sampleResult())
    assertEquals(export, PassportExport.fromJson(export.toJson()))
  }

  @Test
  fun rawFilesAreByteExact() {
    val result = sampleResult()
    val export = PassportExport.fromJson(PassportExport.from(result).toJson())
    for ((name, bytes) in result.files) {
      assertTrue(name, Base64.getDecoder().decode(export.files.getValue(name)).contentEquals(bytes))
    }
    assertEquals("2023-11-14T22:13:20Z", export.readAt)
    assertTrue(export.passiveAuth.signatureValid)
    assertEquals(mapOf("1" to true, "2" to true), export.passiveAuth.dataGroupHashMatches)
    assertEquals("UTO", export.dg1.nationality)
  }

  @Test
  fun storeSavesListsAndDeletes() {
    val dir = Files.createTempDirectory("passport-store").toFile()
    val store = PassportStore(dir)
    val export = PassportExport.from(sampleResult())
    val file = store.save(export, 1_700_000_000_000)
    assertEquals("passport-20231114-221320.json", file.name)
    assertEquals(listOf(file), store.list())
    assertEquals(export, PassportExport.fromJson(file.readText()))
    assertEquals(1, store.deleteAll())
    assertTrue(store.list().isEmpty())
    dir.delete()
  }
}
