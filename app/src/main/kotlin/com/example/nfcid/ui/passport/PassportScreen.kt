package com.example.nfcid.ui.passport

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.example.nfcid.R
import com.example.nfcid.nfc.toHex
import com.example.nfcid.nfc.passport.ChipAuthResult
import com.example.nfcid.nfc.passport.MrzKey
import com.example.nfcid.nfc.passport.PassportReadResult
import com.example.nfcid.nfc.passport.PassportStep
import com.example.nfcid.ui.main.NfcStatus
import com.example.nfcid.ui.main.PropertyRow
import com.example.nfcid.ui.main.StatusCard
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val dateFormatter: DateTimeFormatter =
  DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneId.systemDefault())

@Composable
fun PassportScreen(
  state: PassportUiState,
  nfcStatus: NfcStatus,
  contentPadding: PaddingValues,
  onDocumentNumberChange: (String) -> Unit,
  onDateOfBirthChange: (String) -> Unit,
  onDateOfExpiryChange: (String) -> Unit,
  onBindAddressChange: (String) -> Unit,
  onDeleteStoredData: () -> Unit,
  onOpenNfcSettings: () -> Unit,
) {
  LazyColumn(
    // Edge-to-edge: the keyboard overlays content unless we pad for it.
    modifier = Modifier.fillMaxSize().imePadding(),
    contentPadding = contentPadding,
    verticalArrangement = Arrangement.spacedBy(12.dp),
  ) {
    if (nfcStatus != NfcStatus.Ready) item { StatusCard(nfcStatus, onOpenNfcSettings) }
    item { KeyCard(state, onDocumentNumberChange, onDateOfBirthChange, onDateOfExpiryChange) }
    item { BindCard(state, onBindAddressChange) }
    state.step?.let { step -> item { ProgressCard(step) } }
    if (state.step == null && state.keyReady && state.result == null && state.failure == null) {
      item { InfoCard(stringResource(R.string.passport_hold)) }
    }
    state.failure?.let { item { InfoCard(it, MaterialTheme.colorScheme.errorContainer) } }
    state.result?.let { result -> item { ResultCard(result, state.savedFile, state.resultBindRequested) } }
    item { StoredDataCard(state.storedCount, onDeleteStoredData) }
  }
}

@Composable
private fun KeyCard(
  state: PassportUiState,
  onDocumentNumberChange: (String) -> Unit,
  onDateOfBirthChange: (String) -> Unit,
  onDateOfExpiryChange: (String) -> Unit,
) {
  Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Text(stringResource(R.string.passport_key_title), style = MaterialTheme.typography.titleMedium)
      KeyField(
        value = state.documentNumber,
        label = stringResource(R.string.passport_document_number),
        error = state.errors[MrzKey.Field.DocumentNumber],
        keyboard = KeyboardOptions(KeyboardCapitalization.Characters, autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii),
        onChange = onDocumentNumberChange,
      )
      KeyField(
        value = state.dateOfBirth,
        label = stringResource(R.string.passport_date_of_birth),
        error = state.errors[MrzKey.Field.DateOfBirth],
        keyboard = KeyboardOptions(keyboardType = KeyboardType.Number),
        onChange = onDateOfBirthChange,
      )
      KeyField(
        value = state.dateOfExpiry,
        label = stringResource(R.string.passport_date_of_expiry),
        error = state.errors[MrzKey.Field.DateOfExpiry],
        keyboard = KeyboardOptions(keyboardType = KeyboardType.Number),
        onChange = onDateOfExpiryChange,
      )
      Text(
        stringResource(R.string.passport_key_privacy),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
  }
}

@Composable
private fun BindCard(state: PassportUiState, onBindAddressChange: (String) -> Unit) {
  Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Text(stringResource(R.string.passport_bind_title), style = MaterialTheme.typography.titleMedium)
      KeyField(
        value = state.bindAddress,
        label = stringResource(R.string.passport_bind_address),
        error = state.bindAddressError,
        keyboard = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii),
        onChange = onBindAddressChange,
      )
      Text(
        stringResource(R.string.passport_bind_help),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
  }
}

@Composable
private fun KeyField(
  value: String,
  label: String,
  error: String?,
  keyboard: KeyboardOptions,
  onChange: (String) -> Unit,
) {
  // Only complain about fields the user has started typing in.
  val shownError = error?.takeIf { value.isNotEmpty() }
  OutlinedTextField(
    value = value,
    onValueChange = onChange,
    label = { Text(label) },
    singleLine = true,
    isError = shownError != null,
    supportingText = shownError?.let { { Text(it) } },
    keyboardOptions = keyboard,
    modifier = Modifier.fillMaxWidth(),
  )
}

@Composable
private fun ProgressCard(step: PassportStep) {
  Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Text(step.label + "…", style = MaterialTheme.typography.bodyLarge)
      LinearProgressIndicator(
        progress = { (step.ordinal + 1f) / PassportStep.entries.size },
        modifier = Modifier.fillMaxWidth(),
      )
      Text(stringResource(R.string.passport_keep_still), style = MaterialTheme.typography.bodySmall)
    }
  }
}

@Composable
private fun InfoCard(text: String, color: Color = MaterialTheme.colorScheme.secondaryContainer) {
  Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = color)) {
    Text(text, Modifier.padding(16.dp), style = MaterialTheme.typography.bodyLarge)
  }
}

@Composable
private fun ResultCard(result: PassportReadResult, savedFile: String?, bindRequested: Boolean) {
  val pa = result.passiveAuth
  Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
      Text(stringResource(R.string.passport_result_title), style = MaterialTheme.typography.titleMedium)

      with(result.dg1) {
        PropertyRow("Document", "$documentCode ($documentFormat)")
        PropertyRow("Issuing state", issuingState)
        PropertyRow("Nationality", nationality)
        PropertyRow("Date of birth", dateOfBirth)
        PropertyRow("Expiry", dateOfExpiry)
        PropertyRow("Sex", sex)
        PropertyRow("Document no.", "•••$documentNumberSuffix")
      }

      HorizontalDivider(Modifier.padding(vertical = 4.dp))
      Text("Checks", style = MaterialTheme.typography.labelLarge)
      pa.dataGroupChecks.forEach { CheckRow("DG${it.dataGroup} hash matches SOD", it.matches) }
      CheckRow("SOD signature valid (embedded DSC)", pa.signatureValid, pa.signatureError)
      CheckRow(
        "Chip genuine (${result.chipAuth.method})",
        when (result.chipAuth.status) {
          ChipAuthResult.Status.Passed -> true
          ChipAuthResult.Status.Failed -> false
          else -> null
        },
        result.chipAuth.detail,
      )
      val bound = result.chipAuth.aaBoundAddress
      if (bound != null) {
        CheckRow("Chip signed Souspli address 0x${bound.toHex("")}", result.chipAuth.status == ChipAuthResult.Status.Passed)
      } else if (bindRequested) {
        CheckRow("Chip signed Souspli address", false, "This chip has no Active Authentication, so it cannot sign an address")
      }
      Text(
        stringResource(R.string.passport_csca_note),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )

      HorizontalDivider(Modifier.padding(vertical = 4.dp))
      Text("Signature", style = MaterialTheme.typography.labelLarge)
      PropertyRow("Access", result.accessProtocol)
      PropertyRow("Digest", pa.digestAlgorithm)
      PropertyRow("Algorithm", pa.signatureAlgorithmName)
      pa.dsc?.let { dsc ->
        PropertyRow("DSC key", listOfNotNull(dsc.keyAlgorithm, "${dsc.keySizeBits} bit", dsc.curve).joinToString(" · "))
        PropertyRow("DSC issuer", dsc.issuer)
        PropertyRow("DSC valid", "${dateFormatter.format(Instant.ofEpochMilli(dsc.notBefore))} → ${dateFormatter.format(Instant.ofEpochMilli(dsc.notAfter))}")
      }
      PropertyRow("Read time", "${result.durationMillis} ms")

      savedFile?.let {
        HorizontalDivider(Modifier.padding(vertical = 4.dp))
        Text(stringResource(R.string.passport_saved, it), style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
      }
    }
  }
}

/** [ok] null means "not checked / unsupported". */
@Composable
private fun CheckRow(label: String, ok: Boolean?, detail: String? = null) {
  val (mark, color) =
    when (ok) {
      true -> "✓" to MaterialTheme.colorScheme.primary
      false -> "✗" to MaterialTheme.colorScheme.error
      null -> "–" to MaterialTheme.colorScheme.onSurfaceVariant
    }
  Column {
    Text("$mark  $label", color = color, style = MaterialTheme.typography.bodyMedium)
    if (detail != null && ok != true) {
      Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
  }
}

@Composable
private fun StoredDataCard(count: Int, onDelete: () -> Unit) {
  Card(Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Text(
        if (count == 0) stringResource(R.string.passport_nothing_stored)
        else stringResource(R.string.passport_stored_count, count),
        style = MaterialTheme.typography.bodyMedium,
      )
      OutlinedButton(onClick = onDelete, enabled = count > 0) { Text(stringResource(R.string.passport_delete)) }
    }
  }
}
