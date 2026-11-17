package com.example.nfcid.ui.main

import androidx.lifecycle.ViewModel
import com.example.nfcid.nfc.TagDetails
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

enum class NfcStatus {
  /** The device has no NFC hardware. */
  Unsupported,
  /** NFC hardware exists but is switched off in settings. */
  Disabled,
  /** Reader mode is active and waiting for a tag. */
  Ready,
}

data class NfcUiState(
  val status: NfcStatus = NfcStatus.Ready,
  /** Scanned tags, newest first. */
  val tags: List<TagDetails> = emptyList(),
)

class NfcViewModel : ViewModel() {
  private val _uiState = MutableStateFlow(NfcUiState())
  val uiState: StateFlow<NfcUiState> = _uiState.asStateFlow()

  fun setStatus(status: NfcStatus) = _uiState.update { it.copy(status = status) }

  /** Safe to call from the NFC binder thread: [update] is atomic. */
  fun onTagRead(tag: TagDetails) =
    _uiState.update { it.copy(tags = (listOf(tag) + it.tags).take(MAX_HISTORY)) }

  fun clear() = _uiState.update { it.copy(tags = emptyList()) }

  companion object {
    const val MAX_HISTORY = 50
  }
}
