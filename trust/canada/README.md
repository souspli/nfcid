# Canada CSCA certificates

Country Signing CA certificates for Canadian ePassports (`CN=csca-canada, OU=pptc, O=gc, C=CA`). These are public trust anchors for verifying Document Signer certificates (DSCs).

All five keys are **RSA-4096**, and every certificate is signed with **RSA-PSS** (SHA-256).

| File | Kind | Key (SKI) | Signed by (AKI) | Certificate validity | Key used to sign until |
|---|---|---|---|---|---|
| `csca-canada-2012.pem` | Self-signed CSCA | `8C:8E:97:69…` | itself | 2012-12-05 → 2028-06-05 | 2017-11-21 |
| `csca-canada-2017.pem` | Self-signed CSCA | `CA:A7:05:CF…` | itself | 2017-09-12 → 2033-03-12 | 2022-08-28 |
| `csca-canada-2022.pem` | Self-signed CSCA | `96:57:CF:85…` | itself | 2022-08-30 → 2038-02-28 | 2027-08-16 |
| `link-2012-to-2017.pem` | Link certificate | `CA:A7:05:CF…` (2017 key) | 2012 key | 2017-09-12 → 2033-03-12 | 2022-08-28 |
| `link-2017-to-2022.pem` | Link certificate | `96:57:CF:85…` (2022 key) | 2017 key | 2022-08-30 → 2038-02-28 | 2027-08-16 |

The "used to sign until" date is the end of the Private Key Usage Period: the last day that key could sign DSCs or CRLs. The certificate stays valid for verification long after that.

## SHA-256 fingerprints

```
csca-canada-2012   7C2AAD9DAE87EED6935E84BC450AAB4FAC57CFFB5324DBD06DC494569B294863
csca-canada-2017   FCDF2A36374E1CC25E75C5BFC216A53A611DEE813B687DB0962D75B330A12031
csca-canada-2022   F462638ADEDE314AE0F4CD7689441DD393601A3F51BF271BBDC2BF1815977D71
link-2012-to-2017  2B4A778C08909A2F13CB736F19FA577D3803735B3312EEF883BE9DB670E799ED
link-2017-to-2022  EEF7E623B97E4024C738DAE14F1F3489696BF2B6A9B6EE49E9F8B76171BE6056
```

`sha256sum -c SHA256SUMS` checks the files themselves. Those hashes are of the PEM files, not the certificate fingerprints above.

## Provenance

Extracted on 2026-11-17 from the **German CSCA Master List** issued 2026-10-01 (`DE_ML_2026-10-01-11-50-52.ml`), downloaded from [BSI](https://bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html). That ZIP's SHA-256 is `a0d2b448d8a2ef383c66991897c970ab2f0494173d33ef0d55195127dae08a6a`.

Checks done:
1. **Master list:** its CMS signature verifies against `CN=CSCA Master List Signer`. That signer's ECDSA-SHA512 signature verifies against the German CSCA (`2084AED7…ADA8`, 10/24) and its link certificate (`5F28CB69…20BD`). Both fingerprints match the values BSI publishes on its [root certificate page](https://bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Public-Key-Infrastrukturen/CSCA/Root_Cert_Germany/Root_Certificate_node.html).
2. **Canadian certificates:**
   - Every CSCA's self-signature verifies.
   - Each link certificate verifies against the previous CSCA and carries the same public key as the next one.
3. **A real DSC:** a Canadian passport's DSC (`CN=DS06`, serial `4942D23A`, RSA-PSS 2048) verifies against `csca-canada-2017` and fails against the 2012 and 2022 keys. It is not listed in the ICAO PKD CRL for Canada ([`CAN.crl`](https://pkddownload1.icao.int/CRLs/CAN.crl), 2026-10-22, signed by the 2022 key).

Trust in these certificates rests on BSI having collected and checked them. For stronger assurance, compare the fingerprints against a second source such as the ICAO PKD master list.

## Notes for tooling

- **CRLs and key rollover:** CRLs are signed by the CSCA key that is current at the time, currently the 2022 key, even for DSCs issued under older keys. OpenSSL's `-crl_check` therefore can't match the CRL to a DSC from the 2017 key ("unable to get certificate CRL"). Check the CRL signature and the DSC's serial separately.
- **Verifying a DSC:** `openssl verify -no-CApath -CAfile csca-canada-2017.pem dsc.pem`
