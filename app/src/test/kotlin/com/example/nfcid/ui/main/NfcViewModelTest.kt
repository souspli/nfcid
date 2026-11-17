package com.example.nfcid.ui.main

import com.example.nfcid.nfc.TagDetails
import org.junit.Assert.assertEquals
import org.junit.Test

class NfcViewModelTest {

  private fun tag(n: Int) = TagDetails("UID$n", listOf("NfcA"), emptyList(), emptyList(), n.toLong())

  @Test
  fun newestTagFirst() {
    val vm = NfcViewModel()
    vm.onTagRead(tag(1))
    vm.onTagRead(tag(2))
    assertEquals(listOf("UID2", "UID1"), vm.uiState.value.tags.map { it.uid })
  }

  @Test
  fun historyIsCapped() {
    val vm = NfcViewModel()
    repeat(NfcViewModel.MAX_HISTORY + 5) { vm.onTagRead(tag(it)) }
    val tags = vm.uiState.value.tags
    assertEquals(NfcViewModel.MAX_HISTORY, tags.size)
    assertEquals("UID${NfcViewModel.MAX_HISTORY + 4}", tags.first().uid)
  }

  @Test
  fun clearKeepsStatus() {
    val vm = NfcViewModel()
    vm.setStatus(NfcStatus.Disabled)
    vm.onTagRead(tag(1))
    vm.clear()
    assertEquals(NfcUiState(status = NfcStatus.Disabled), vm.uiState.value)
  }
}
