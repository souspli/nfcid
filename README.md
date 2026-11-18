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

## Binding a read to a Souspli key

The Passport tab has an optional **Souspli address** field. With it filled in, and on a chip that supports Active Authentication, the chip signs a challenge derived from that address instead of a random one:

```
challenge = SHA-256("souspli-passport-bind-v1:" ‖ 20 address bytes)[0..8]
```

The export records the address as `chipAuth.aaBoundAddressHex`. Souspli's Passport letter type reads the export, and Souspli's header then reports that the chip signed that key. Active Authentication signs exactly 8 bytes, so the binding is 64 bits of a hash. A chip with only Chip Authentication cannot sign an address; the result card says so.

For zero-knowledge proofs bound to a Souspli address, see [`zk/`](zk/README.md).

## Third-party licenses

- [JMRTD](https://jmrtd.org) (eMRTD protocols and parsing): **LGPL-3.0-or-later**
- SCUBA (smart-card abstraction): LGPL-3.0-or-later
- [Bouncy Castle](https://www.bouncycastle.org): MIT-style license
