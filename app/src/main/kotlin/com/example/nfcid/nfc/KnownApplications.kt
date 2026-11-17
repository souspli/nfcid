package com.example.nfcid.nfc

/** A smart-card application we try to SELECT by its AID. */
class AppProbe(val name: String, aidHex: String, val returnFci: Boolean = true) {
  val aid: ByteArray = aidHex.hexToBytes()
}

object KnownApplications {

  /** EMV contactless Proximity Payment System Environment: the card's payment-app directory. */
  val PPSE: ByteArray = "2PAY.SYS.DDF01".toByteArray(Charsets.US_ASCII)

  /** Non-payment applications to probe. SELECT is read-only; none of these read personal data. */
  val PROBES =
    listOf(
      AppProbe("ICAO e-passport (eMRTD)", "A0000002471001", returnFci = false),
      AppProbe("HID Seos access credential", "A0000004400001010001"),
      AppProbe("NFC Forum Type 4 NDEF", "D2760000850101"),
      AppProbe("PIV smart card", "A000000308"),
      AppProbe("OpenPGP card", "D27600012401"),
      AppProbe("FIDO security key", "A0000006472F0001"),
      AppProbe("Calypso transit", "315449432E494341"),
    )

  /** Payment networks keyed by RID, the first 5 bytes of an AID. */
  private val PAYMENT_NETWORKS =
    mapOf(
      "A000000003" to "Visa",
      "A000000004" to "Mastercard",
      "A000000025" to "American Express",
      "A000000152" to "Discover",
      "A000000065" to "JCB",
      "A000000333" to "UnionPay",
      "A000000277" to "Interac",
      "A000000658" to "Mir",
    )

  fun paymentNetwork(aid: ByteArray): String? =
    if (aid.size < 5) null else PAYMENT_NETWORKS[aid.copyOfRange(0, 5).toHex(separator = "")]
}
