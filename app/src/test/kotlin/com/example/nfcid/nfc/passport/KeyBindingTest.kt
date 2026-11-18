package com.example.nfcid.nfc.passport

import com.example.nfcid.nfc.toHex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KeyBindingTest {
  private val address = "0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8"

  @Test
  fun parsesAddressWithOrWithoutPrefixInAnyCase() {
    val expected = "04FB06E8BF44EC60B6A99D2F98551172B2F2DED8"
    assertEquals(expected, KeyBinding.parseAddress(address)!!.toHex(""))
    assertEquals(expected, KeyBinding.parseAddress("  ${address.removePrefix("0x").uppercase()} ")!!.toHex(""))
  }

  @Test
  fun rejectsMalformedAddresses() {
    assertNull(KeyBinding.parseAddress(""))
    assertNull(KeyBinding.parseAddress(address.dropLast(1)))
    assertNull(KeyBinding.parseAddress(address + "0"))
    assertNull(KeyBinding.parseAddress(address.replace('4', 'g')))
  }

  /** Fixed vector, so the Souspli verifier can be checked against the same value. */
  @Test
  fun challengeIsFirstEightBytesOfDomainSeparatedHash() {
    val challenge = KeyBinding.challengeFor(KeyBinding.parseAddress(address)!!)
    assertEquals("85887D8FF01345E0", challenge.toHex(""))
  }

  @Test
  fun differentAddressesGiveDifferentChallenges() {
    val other = KeyBinding.parseAddress(address.dropLast(1) + "9")!!
    assertEquals(8, KeyBinding.challengeFor(other).size)
    assert(!KeyBinding.challengeFor(other).contentEquals(KeyBinding.challengeFor(KeyBinding.parseAddress(address)!!)))
  }
}
