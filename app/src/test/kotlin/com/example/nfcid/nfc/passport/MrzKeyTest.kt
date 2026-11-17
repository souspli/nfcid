package com.example.nfcid.nfc.passport

import com.example.nfcid.nfc.passport.MrzKey.Field
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MrzKeyTest {

  private fun valid(doc: String, dob: String, exp: String) =
    (MrzKey.parse(doc, dob, exp) as MrzKey.Result.Valid).key

  private fun errors(doc: String, dob: String, exp: String) =
    (MrzKey.parse(doc, dob, exp) as MrzKey.Result.Invalid).errors

  @Test
  fun normalizesAndPads() {
    val key = valid(" l898 902c3 ", "740812", "120415")
    assertEquals("L898902C3", key.documentNumber)
    assertEquals("AB12<<<<<", valid("ab12", "740812", "120415").documentNumber)
  }

  @Test
  fun toStringIsMasked() {
    val text = valid("L898902C3", "740812", "120415").toString()
    assertFalse(text.contains("L898"))
    assertFalse(text.contains("740812"))
  }

  @Test
  fun rejectsBadDocumentNumber() {
    assertTrue(Field.DocumentNumber in errors("", "740812", "120415"))
    assertTrue(Field.DocumentNumber in errors("1234567890", "740812", "120415"))
    assertTrue(Field.DocumentNumber in errors("AB-12", "740812", "120415"))
  }

  @Test
  fun rejectsBadDates() {
    assertTrue(Field.DateOfBirth in errors("A1", "7408", "120415"))
    assertTrue(Field.DateOfBirth in errors("A1", "741312", "120415"))
    assertTrue(Field.DateOfExpiry in errors("A1", "740812", "120431".replace("0431", "0431")))
    assertTrue(Field.DateOfExpiry in errors("A1", "740812", "12023O"))
    assertEquals(setOf(Field.DateOfBirth, Field.DateOfExpiry), errors("A1", "", "").keys)
  }

  @Test
  fun acceptsLeapDay() {
    valid("A1", "000229", "300101")
  }
}
