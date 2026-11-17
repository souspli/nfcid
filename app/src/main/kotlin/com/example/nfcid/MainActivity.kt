package com.example.nfcid

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.nfcid.nfc.TagDetails
import com.example.nfcid.nfc.TagReader
import com.example.nfcid.nfc.toHex
import com.example.nfcid.ui.main.MainScreen
import com.example.nfcid.ui.main.NfcStatus
import com.example.nfcid.ui.main.NfcViewModel
import com.example.nfcid.ui.theme.NFCIDTheme

/**
 * Hosts the NFC reader.
 *
 * Uses [NfcAdapter.enableReaderMode] while the activity is resumed, so tags come straight to
 * [onTagDiscovered] instead of being dispatched to other apps or the system tag viewer.
 */
class MainActivity : ComponentActivity(), NfcAdapter.ReaderCallback {

  private val viewModel: NfcViewModel by viewModels()
  private var nfcAdapter: NfcAdapter? = null

  /** Picks up NFC being switched on or off (e.g. from quick settings) while we're in front. */
  private val adapterStateReceiver =
    object : BroadcastReceiver() {
      override fun onReceive(context: Context, intent: Intent) = refreshNfcState()
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    nfcAdapter = NfcAdapter.getDefaultAdapter(this)
    // Reader mode only works while we're resumed, so don't let the screen time out mid-session.
    window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

    enableEdgeToEdge()
    setContent {
      NFCIDTheme {
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
          val state by viewModel.uiState.collectAsStateWithLifecycle()
          MainScreen(
            state = state,
            onOpenNfcSettings = { startActivity(Intent(Settings.ACTION_NFC_SETTINGS)) },
            onClear = viewModel::clear,
          )
        }
      }
    }
  }

  override fun onResume() {
    super.onResume()
    registerReceiver(
      adapterStateReceiver,
      IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED),
      RECEIVER_NOT_EXPORTED,
    )
    refreshNfcState()
  }

  override fun onPause() {
    super.onPause()
    unregisterReceiver(adapterStateReceiver)
    nfcAdapter?.disableReaderMode(this)
  }

  private fun refreshNfcState() {
    val adapter = nfcAdapter
    val status =
      when {
        adapter == null -> NfcStatus.Unsupported
        !adapter.isEnabled -> NfcStatus.Disabled
        else -> NfcStatus.Ready
      }
    viewModel.setStatus(status)
    if (status == NfcStatus.Ready) {
      adapter?.enableReaderMode(this, this, READER_FLAGS, null)
    }
  }

  /** Called on an NFC binder thread, not the main thread. */
  override fun onTagDiscovered(tag: Tag) {
    val now = System.currentTimeMillis()
    val details =
      try {
        TagReader.read(tag, now)
      } catch (e: RuntimeException) {
        // Never let a malformed tag crash the binder thread; still show what we can.
        Log.w(TAG, "Failed to read tag details", e)
        TagDetails(
          uid = tag.id.toHex(),
          techs = tag.techList.map { it.substringAfterLast('.') },
          properties = listOf("Error" to (e.message ?: e.javaClass.simpleName)),
          ndefRecords = emptyList(),
          scannedAtMillis = now,
        )
      }
    logDetails(details)
    viewModel.onTagRead(details)
  }

  /** One log line per field so each stays short and greppable with `adb logcat -s NfcId`. */
  private fun logDetails(details: TagDetails) {
    Log.i(TAG, "Tag ${details.uid} techs=${details.techs}")
    details.properties.forEach { (label, value) -> Log.i(TAG, "  $label: $value") }
    details.ndefRecords.forEach { Log.i(TAG, "  NDEF $it") }
    details.applications.forEach { Log.i(TAG, "  App $it") }
  }

  private companion object {
    const val TAG = "NfcId"
    const val READER_FLAGS =
      NfcAdapter.FLAG_READER_NFC_A or
        NfcAdapter.FLAG_READER_NFC_B or
        NfcAdapter.FLAG_READER_NFC_F or
        NfcAdapter.FLAG_READER_NFC_V
  }
}
