package com.example.nfcid.nfc.passport

import java.security.MessageDigest

/**
 * Binds a passport read to a Souspli identity: the chip's Active Authentication challenge is
 * derived from the Souspli address, so the chip's signature shows it was presented for that key.
 *
 * `challenge = SHA-256("souspli-passport-bind-v1:" ‖ address)[0..8]`. Active Authentication
 * signs exactly 8 bytes, so the binding is only as strong as 64 bits of a hash.
 */
object KeyBinding {
  const val DOMAIN = "souspli-passport-bind-v1:"
  private val ADDRESS = Regex("^(0x)?[0-9a-fA-F]{40}$")

  /** The 20 address bytes, or null if [text] is not `0x` plus 40 hex characters. */
  fun parseAddress(text: String): ByteArray? {
    val trimmed = text.trim()
    if (!ADDRESS.matches(trimmed)) return null
    return trimmed.removePrefix("0x").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  }

  fun challengeFor(address: ByteArray): ByteArray {
    require(address.size == 20) { "address must be 20 bytes" }
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(DOMAIN.toByteArray(Charsets.US_ASCII))
    return digest.digest(address).copyOf(8)
  }
}
