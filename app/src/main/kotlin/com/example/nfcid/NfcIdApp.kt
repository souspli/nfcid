package com.example.nfcid

import android.app.Application
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

class NfcIdApp : Application() {
  override fun onCreate() {
    super.onCreate()
    // Android ships a stripped-down provider named "BC" without brainpool curves and other
    // algorithms passports use for PACE and signatures; replace it with the full BouncyCastle.
    Security.removeProvider("BC")
    Security.insertProviderAt(BouncyCastleProvider(), 1)
  }
}
