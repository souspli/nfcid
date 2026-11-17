package com.example.nfcid.ui.main

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.nfcid.R
import com.example.nfcid.nfc.TagDetails
import com.example.nfcid.ui.theme.NFCIDTheme
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val timeFormatter: DateTimeFormatter =
  DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
  state: NfcUiState,
  onOpenNfcSettings: () -> Unit,
  onClear: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Scaffold(
    modifier = modifier,
    topBar = {
      CenterAlignedTopAppBar(
        title = { Text(stringResource(R.string.app_name)) },
        actions = {
          if (state.tags.isNotEmpty()) {
            TextButton(onClick = onClear) { Text(stringResource(R.string.clear)) }
          }
        },
        colors =
          TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            titleContentColor = MaterialTheme.colorScheme.primary,
          ),
      )
    },
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier.fillMaxSize(),
      contentPadding =
        PaddingValues(
          start = 16.dp,
          end = 16.dp,
          top = innerPadding.calculateTopPadding() + 16.dp,
          bottom = innerPadding.calculateBottomPadding() + 16.dp,
        ),
      verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
      item { StatusCard(state.status, onOpenNfcSettings) }
      items(state.tags) { TagCard(it) }
    }
  }
}

@Composable
private fun StatusCard(status: NfcStatus, onOpenNfcSettings: () -> Unit) {
  val containerColor =
    when (status) {
      NfcStatus.Ready -> MaterialTheme.colorScheme.secondaryContainer
      NfcStatus.Disabled,
      NfcStatus.Unsupported -> MaterialTheme.colorScheme.errorContainer
    }
  Card(
    modifier = Modifier.fillMaxWidth(),
    colors = CardDefaults.cardColors(containerColor = containerColor),
  ) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      val message =
        when (status) {
          NfcStatus.Ready -> R.string.status_ready
          NfcStatus.Disabled -> R.string.status_disabled
          NfcStatus.Unsupported -> R.string.status_unsupported
        }
      Text(stringResource(message), style = MaterialTheme.typography.bodyLarge)
      if (status == NfcStatus.Disabled) {
        Button(onClick = onOpenNfcSettings) { Text(stringResource(R.string.open_nfc_settings)) }
      }
    }
  }
}

@Composable
private fun TagCard(tag: TagDetails) {
  Card(modifier = Modifier.fillMaxWidth()) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
      Text(
        text = timeFormatter.format(Instant.ofEpochMilli(tag.scannedAtMillis)),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
      SelectionContainer {
        Text(
          text = tag.uid.ifEmpty { stringResource(R.string.no_uid) },
          style = MaterialTheme.typography.titleLarge,
          fontFamily = FontFamily.Monospace,
          fontWeight = FontWeight.SemiBold,
        )
      }
      Text(text = tag.techs.joinToString(" · "), style = MaterialTheme.typography.bodyMedium)

      if (tag.properties.isNotEmpty()) {
        HorizontalDivider(Modifier.padding(vertical = 4.dp))
        tag.properties.forEach { (label, value) -> PropertyRow(label, value) }
      }
      if (tag.applications.isNotEmpty()) {
        HorizontalDivider(Modifier.padding(vertical = 4.dp))
        Text(stringResource(R.string.applications), style = MaterialTheme.typography.labelLarge)
        tag.applications.forEach {
          SelectionContainer { Text(it, style = MaterialTheme.typography.bodyMedium) }
        }
      }
      if (tag.ndefRecords.isNotEmpty()) {
        HorizontalDivider(Modifier.padding(vertical = 4.dp))
        Text(stringResource(R.string.ndef_records), style = MaterialTheme.typography.labelLarge)
        tag.ndefRecords.forEach {
          SelectionContainer { Text(it, style = MaterialTheme.typography.bodyMedium) }
        }
      }
    }
  }
}

@Composable
private fun PropertyRow(label: String, value: String) {
  Row {
    Text(
      text = label,
      modifier = Modifier.width(140.dp),
      style = MaterialTheme.typography.bodyMedium,
      color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    SelectionContainer {
      Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
    }
  }
}

@Preview(showBackground = true, showSystemUi = true)
@Composable
private fun MainScreenPreview() {
  NFCIDTheme {
    MainScreen(
      state =
        NfcUiState(
          status = NfcStatus.Ready,
          tags =
            listOf(
              TagDetails(
                uid = "04:A2:3B:1C:5D:80:00",
                techs = listOf("NfcA", "MifareUltralight", "Ndef"),
                properties =
                  listOf("ATQA" to "44:00", "SAK" to "0x00", "NDEF capacity" to "137 bytes"),
                ndefRecords = listOf("URI: https://example.com"),
                scannedAtMillis = 0L,
                applications = listOf("Payment: Visa \"VISA CREDIT\" (AID A0000000031010)"),
              )
            ),
        ),
      onOpenNfcSettings = {},
      onClear = {},
    )
  }
}
