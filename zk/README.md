# Zero-knowledge proofs from a passport export

These scripts turn a Passport-tab export (see the top-level README) into zero-knowledge proofs with [zkPassport's Noir circuits](https://github.com/zkpassport/circuits): signature checks up to the CSCA, then age and nationality claims.

```
zk/run.sh ~/nfcid-private/passport-<timestamp>.json      # outputs go to ~/nfcid-private/zk
```

To build a proof package for Souspli, bound to one Souspli address:

```
zk/package.sh ~/nfcid-private/passport-<timestamp>.json ~/nfcid-private/souspli/proof.json \
    --address 0x<souspli address> --scope souspli:group:<group hash> --min-age 18 --nationality CAN
```

Both scripts share `setup.sh`. `run.sh` does the following:
1. Checks the toolchain: **nargo 1.0.0**, **bb 6.0.0** (the versions zkPassport's CI pins), and Node.
2. Uses a zkPassport checkout at `$ZKP_DIR` (default `~/zk/zkpassport-circuits`).
   - If there's no checkout, it fetches commit `4d90f1f` (release 0.23.0).
   - It refuses to touch an existing checkout at a different commit.
3. Runs `npm ci --ignore-scripts` there if needed.
4. Copies the `.ts` scripts into the checkout's git-excluded `nfcid-local/` folder. They import zkPassport's test helper and `node_modules`, so they have to run from inside that repo.
5. Compiles the circuits the scripts name, skipping any already built.
6. Generates witnesses with zkPassport's own input builders. The CSCA certificate registry is built from `trust/canada/`.
7. Proves and verifies each witness with `bb`, printing gates, prove time and peak memory.

## The proof chain

| Step | Circuit | Proves |
|---|---|---|
| `dsc` | `sig_check_dsc_tbs_1000_rsa_pss_4096_sha256` | A CSCA in the registry signed the DSC (RSA-PSS 4096) |
| `id_data` | `sig_check_id_data_tbs_1000_rsa_pss_2048_sha256` | The DSC signed the SOD (RSA-PSS 2048), and the DSC key is in its certificate |
| `integrity` | `data_check_integrity_sa_sha256_dg_sha256` | DG1 hashes to the value in the signed SOD |
| `age_gte_18` | `compare_age` | Age ≥ 18 today |
| `nationality_in_*` | `inclusion_check_nationality` | Nationality is in a country list, and the document isn't expired |

Each step's `comm_in` must equal the output commitment of the step it chains from; `witness.ts` checks this. `nationality_in_USA_GBR_FRA` is a **negative control**: it must be refused, or the run fails.

**The circuit choice is specific to this passport.** It's a Canadian passport: RSA-PSS with SHA-256, salt 32, a 922-byte DSC certificate body (hence `tbs_1000`), and a 4096-bit CSCA key. Other passports need different `sig_check_*` and `integrity` variants. Change the `circuit:` names in `witness.ts` and `package.ts`; `setup.sh` reads those lists.

## Proof packages for Souspli

`package.sh` runs `package.ts`, which proves in-process with bb.js (the library a verifier uses too), so no witness is written to disk. A package holds six proofs: `dsc`, `id_data`, `integrity`, the claims asked for (`age`, `nationality`), and `bind`.

- **Bound to an address.** The `bind` circuit commits to the Souspli address, and all disclosure proofs share one integrity commitment, so the claims belong to that address.
- **Scope decides the nullifier.** One passport gives one nullifier per `--scope` (plus `--subscope`). Use a group's or a ballot's hash to allow one membership or one vote per passport.
- **Fresh salts every run.** Two packages from the same passport share no public value except the nullifier when they share a scope (checked 2026-11-18). The benchmark script above uses fixed salts and its outputs are not safe to publish.
- **`--pins <file>`** writes what a verifier must pin: the certificate registry root and each circuit's verification key. The root is reproducible because `common.ts` fixes the registry timestamp (`TRUST_SET_TIMESTAMP`).

A package is about 120 KB and takes about 15 s to build on 16 threads. Before writing it, the tool makes the same checks a verifier makes: every proof verifies, the commitments chain, and the scope, date, parameters and nullifier agree across the proofs.

Public inputs, in order:

| Proof | Public inputs |
|---|---|
| `dsc` | registry root, commitment out |
| `id_data` | commitment in, commitment out |
| `integrity` | commitment in, commitment out, verification method (100 = chip signatures) |
| `age`, `nationality`, `bind` | commitment in, date, scope, subscope, parameter commitment, nullifier type, nullifier, OPRF key hash |

### Test fixtures without a real passport

`fixture.sh <dir> <name> --address 0x… --scope <text> [options] [-- <name> …]` makes a synthetic passport (a made-up person under a made-up state certificate, built with zkPassport's generator) and proof packages from it. The first run in a directory writes `export.json` and `trust/csca.pem`; later runs reuse them, so packages share one passport and its nullifiers. Souspli's tests are built from these. A different directory is a different passport.

## Measured (2026-11-17, 16 threads)

| Circuit | Gates | Prove | Peak memory |
|---|---|---|---|
| DSC, RSA-PSS 4096 | 309k | 1.6 s | 499 MB |
| SOD, RSA-PSS 2048 | 187k | 1.1 s | 316 MB |
| Integrity | 78k | 0.5 s | 153 MB |
| Age | 80k | 0.5 s | 188 MB |
| Nationality | 84k | 0.5 s | 194 MB |

Each proof is 14 KB and verifies in under 20 ms. The DSC proof takes 8.6 s on 1 thread and 2.9 s on 4.

## Caveats

- **The verifier must check the claim parameters.** A disclosure proof's first output is `param_commitment`, a commitment to the claim's parameters (for example the country list). Recompute it from the list you asked for and compare; otherwise the prover could have used a different list.
- **`run.sh`'s test proofs are linkable and use fixed salts.** They all use `service_scope = 0`. Use `package.sh` for anything that leaves this machine.
- **Anyone holding DG1 and the SOD can make these proofs**: the issuing state, and anyone who has read the chip. The circuits prove possession of the signed data, not of the chip.
- **These are separate proofs.** zkPassport normally wraps the chain into one recursive proof (`main/outer`); that isn't done here.
- **The registry is Canada only, and revocation inputs are empty.**

## Privacy

Witnesses contain DG1 (name, document number, date of birth). `run.sh` writes everything with umask 077 into an owner-only directory, and `witness.ts` prints only commitment hashes and circuit assertion messages. Keep the output directory out of this repository.
