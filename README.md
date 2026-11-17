# NFC ID

Android app (minSdk 36) for experimenting with the NFC reader.

- **Scanner tab:** shows each tag's UID, technologies, tech-specific properties and NDEF records. ISO-DEP cards are also probed with read-only SELECTs: payment directory, e-passport, HID Seos, NDEF, PIV, OpenPGP, FIDO, Calypso, plus DESFire GetVersion.
- **Passport tab:** unlocks an ICAO eMRTD with PACE (falling back to BAC) from the typed MRZ key and reads EF.COM, EF.SOD, DG1, and DG14/DG15 if present. It checks the chip is genuine (Chip or Active Authentication) and runs passive authentication: data-group hashes plus the SOD signature against the embedded Document Signer certificate. CSCA chain validation is not done in the app.

## Build

```
./gradlew testDebugUnitTest installDebug
```

Needs JDK 21 and an Android SDK with `platforms/android-37.0`.

## Passport exports

Each successful passport read is saved as JSON in app-private storage (`files/passport/`), never in shared storage or logs. Cloud backup is disabled. To copy exports to a PC (debug builds only):

```
mkdir -p ~/nfcid-private && chmod 700 ~/nfcid-private
adb shell run-as com.example.nfcid ls files/passport
adb exec-out run-as com.example.nfcid cat files/passport/<file>.json > ~/nfcid-private/<file>.json
```

The JSON contains full passport data (DG1 includes the name and document number). Keep it out of this repository.

## Third-party licenses

- [JMRTD](https://jmrtd.org) (eMRTD protocols and parsing): **LGPL-3.0-or-later**
- SCUBA (smart-card abstraction): LGPL-3.0-or-later
- [Bouncy Castle](https://www.bouncycastle.org): MIT-style license
