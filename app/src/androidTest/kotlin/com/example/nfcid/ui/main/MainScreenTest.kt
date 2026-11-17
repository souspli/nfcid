package com.example.nfcid.ui.main

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.example.nfcid.nfc.TagDetails
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** UI tests for [MainScreen], driven with fake state (no real NFC needed). */
class MainScreenTest {

  @get:Rule val composeTestRule = createAndroidComposeRule<ComponentActivity>()

  @Test
  fun showsScannedTag() {
    val tag =
      TagDetails(
        uid = "04:A2:3B:1C",
        techs = listOf("NfcA", "Ndef"),
        properties = listOf("SAK" to "0x00"),
        ndefRecords = listOf("URI: https://example.com"),
        scannedAtMillis = 0L,
      )
    composeTestRule.setContent {
      MainScreen(NfcUiState(NfcStatus.Ready, listOf(tag)), onOpenNfcSettings = {}, onClear = {})
    }
    composeTestRule.onNodeWithText("04:A2:3B:1C").assertExists()
    composeTestRule.onNodeWithText("NfcA · Ndef").assertExists()
    composeTestRule.onNodeWithText("URI: https://example.com").assertExists()
    composeTestRule.onNodeWithText("Clear").assertExists()
  }

  @Test
  fun disabledShowsSettingsButton() {
    var opened = false
    composeTestRule.setContent {
      MainScreen(NfcUiState(NfcStatus.Disabled), onOpenNfcSettings = { opened = true }, onClear = {})
    }
    composeTestRule.onNodeWithText("NFC is turned off.").assertExists()
    composeTestRule.onNodeWithText("Open NFC settings").performClick()
    assertTrue(opened)
  }
}
