package com.example.nfcid.ui.passport

import android.nfc.Tag
import androidx.lifecycle.ViewModel
import com.example.nfcid.nfc.passport.MrzKey
import com.example.nfcid.nfc.passport.PassportExport
import com.example.nfcid.nfc.passport.PassportReadOutcome
import com.example.nfcid.nfc.passport.PassportReadResult
import com.example.nfcid.nfc.passport.PassportReader
import com.example.nfcid.nfc.passport.PassportStep
import com.example.nfcid.nfc.passport.PassportStore
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

data class PassportUiState(
  val documentNumber: String = "",
  val dateOfBirth: String = "",
  val dateOfExpiry: String = "",
  /** Validation errors for the current input (the screen shows them only for non-empty fields). */
  val errors: Map<MrzKey.Field, String> = emptyMap(),
  val keyReady: Boolean = false,
  /** Non-null while a read is in progress. */
  val step: PassportStep? = null,
  val result: PassportReadResult? = null,
  /** File name of the export saved for [result]. */
  val savedFile: String? = null,
  val failure: String? = null,
  val storedCount: Int = 0,
)

/**
 * Holds the MRZ key in memory only (never persisted) and runs passport reads.
 *
 * [onTag] is called on the NFC binder thread and blocks for the duration of the read.
 */
class PassportViewModel(private val store: PassportStore) : ViewModel() {

  private val _uiState = MutableStateFlow(PassportUiState(storedCount = store.list().size))
  val uiState: StateFlow<PassportUiState> = _uiState.asStateFlow()

  @Volatile private var key: MrzKey? = null
  private val reading = AtomicBoolean(false)

  fun onDocumentNumberChange(value: String) = updateInput { it.copy(documentNumber = value) }

  fun onDateOfBirthChange(value: String) = updateInput { it.copy(dateOfBirth = value.filter(Char::isDigit).take(6)) }

  fun onDateOfExpiryChange(value: String) = updateInput { it.copy(dateOfExpiry = value.filter(Char::isDigit).take(6)) }

  private fun updateInput(change: (PassportUiState) -> PassportUiState) {
    _uiState.update { old ->
      val new = change(old)
      when (val parsed = MrzKey.parse(new.documentNumber, new.dateOfBirth, new.dateOfExpiry)) {
        is MrzKey.Result.Valid -> {
          key = parsed.key
          new.copy(errors = emptyMap(), keyReady = true)
        }
        is MrzKey.Result.Invalid -> {
          key = null
          new.copy(errors = parsed.errors, keyReady = false)
        }
      }
    }
  }

  fun onTag(tag: Tag) {
    val key = key
    if (key == null) {
      _uiState.update { it.copy(failure = "Enter the document number and dates first.") }
      return
    }
    if (!reading.compareAndSet(false, true)) return
    try {
      _uiState.update { it.copy(step = PassportStep.Connecting, failure = null, result = null, savedFile = null) }
      val reader = PassportReader { step -> _uiState.update { it.copy(step = step) } }
      when (val outcome = reader.read(tag, key)) {
        is PassportReadOutcome.Success -> {
          val file = store.save(PassportExport.from(outcome.result), outcome.result.readAtMillis)
          _uiState.update {
            it.copy(result = outcome.result, savedFile = file.name, storedCount = store.list().size)
          }
        }
        is PassportReadOutcome.Failure -> _uiState.update { it.copy(failure = outcome.message) }
      }
    } finally {
      reading.set(false)
      _uiState.update { it.copy(step = null) }
    }
  }

  /** Removes stored exports and clears the on-screen result. */
  fun deleteStoredData() {
    store.deleteAll()
    _uiState.update { it.copy(result = null, savedFile = null, storedCount = store.list().size) }
  }
}
