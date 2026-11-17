package com.example.nfcid.nfc.passport

/**
 * The three MRZ fields that derive the BAC/PACE access key.
 *
 * Holds sensitive data: [toString] is masked so it can never leak into logs or crash reports.
 */
class MrzKey private constructor(
  /** Upper-case, padded with `<` to 9 characters as the MRZ does. */
  val documentNumber: String,
  /** YYMMDD */
  val dateOfBirth: String,
  /** YYMMDD */
  val dateOfExpiry: String,
) {
  override fun toString() = "MrzKey(***)"

  enum class Field { DocumentNumber, DateOfBirth, DateOfExpiry }

  sealed interface Result {
    data class Valid(val key: MrzKey) : Result

    data class Invalid(val errors: Map<Field, String>) : Result
  }

  companion object {
    private const val MAX_DOCUMENT_NUMBER = 9

    /** Validates raw user input. Spaces are ignored and letters upper-cased. */
    fun parse(documentNumber: String, dateOfBirth: String, dateOfExpiry: String): Result {
      val doc = documentNumber.filterNot { it.isWhitespace() }.uppercase()
      val dob = dateOfBirth.filterNot { it.isWhitespace() }
      val exp = dateOfExpiry.filterNot { it.isWhitespace() }

      val errors = buildMap {
        when {
          doc.isEmpty() -> put(Field.DocumentNumber, "Required")
          doc.length > MAX_DOCUMENT_NUMBER -> put(Field.DocumentNumber, "At most 9 characters")
          !doc.all { it in 'A'..'Z' || it in '0'..'9' || it == '<' } ->
            put(Field.DocumentNumber, "Letters and digits only")
        }
        dateError(dob)?.let { put(Field.DateOfBirth, it) }
        dateError(exp)?.let { put(Field.DateOfExpiry, it) }
      }
      if (errors.isNotEmpty()) return Result.Invalid(errors)
      return Result.Valid(MrzKey(doc.padEnd(MAX_DOCUMENT_NUMBER, '<'), dob, exp))
    }

    /** YYMMDD with a real month and a day that exists in that month (Feb 29 allowed). */
    private fun dateError(value: String): String? {
      if (value.isEmpty()) return "Required"
      if (value.length != 6 || !value.all { it.isDigit() }) return "Use YYMMDD, e.g. 740812"
      val month = value.substring(2, 4).toInt()
      val day = value.substring(4, 6).toInt()
      if (month !in 1..12) return "Month must be 01-12"
      val maxDay =
        when (month) {
          2 -> 29
          4, 6, 9, 11 -> 30
          else -> 31
        }
      if (day !in 1..maxDay) return "Day must be 01-$maxDay"
      return null
    }
  }
}
