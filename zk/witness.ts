/**
 * Turns an NFC ID passport export into witnesses for zkPassport's circuits, using zkPassport's own
 * input builders so the formats are exactly what the circuits expect.
 *
 * Normally run through `zk/run.sh`, which copies this file into a zkPassport circuits checkout
 * (it imports that repo's test helper and node_modules) and runs it from there:
 *
 *   npx tsx nfcid-local/witness.ts <export.json> <trust-dir-with-CSCA-pems> <out-dir>
 *
 * Writes <out-dir>/<label>.gz (gzipped witnesses: these contain passport data) plus
 * <out-dir>/witnesses.json mapping each label to its circuit. Checks that each step's comm_in is
 * the output commitment of the step it chains from, and that negative controls are refused.
 * Prints only commitment hashes and circuit assertion messages, never passport data.
 */
import fs from "fs"
import path from "path"
import { Noir } from "@noir-lang/noir_js"
import { getAgeCircuitInputs, getNationalityInclusionCircuitInputs, getNowTimestamp } from "@zkpassport/utils"
import { loadPassport, short } from "./common"

const [exportPath, trustDir, outDir] = process.argv.slice(2)
if (!exportPath || !trustDir || !outDir) {
  console.error("usage: witness.ts <export.json> <trust-dir> <out-dir>")
  process.exit(2)
}

const asBig = (v: unknown) => BigInt(v as string)

async function main() {
  const { helper, certs } = await loadPassport(exportPath, trustDir)
  console.log(`certificate registry: ${certs.certificates.length} CSCA certs, root ${short(certs.root)}`)

  // Same disclosure salts the helper uses for the integrity circuit (it commits to them).
  const salts = { dg1Salt: 3n, expiryDateSalt: 3n, dg2HashSalt: 3n, privateNullifierSalt: 3n }
  const now = getNowTimestamp()

  const nationalityIn = (countries: string[]) => () =>
    getNationalityInclusionCircuitInputs(helper.passport as any, { nationality: { in: countries as any } }, salts, 0n, 0n, 0n, now)

  type Step = {
    /** Witness file name and label. */
    label: string
    circuit: string
    makeInputs: () => Promise<any>
    /** Label of the step whose first output must equal this step's comm_in. */
    chainFrom?: string
    /** Negative control: the circuit must refuse this witness. */
    expectFailure?: boolean
  }
  const steps: Step[] = [
    { label: "dsc", circuit: "sig_check_dsc_tbs_1000_rsa_pss_4096_sha256", makeInputs: () => helper.generateCircuitInputs("dsc") },
    { label: "id_data", circuit: "sig_check_id_data_tbs_1000_rsa_pss_2048_sha256", makeInputs: () => helper.generateCircuitInputs("id"), chainFrom: "dsc" },
    { label: "integrity", circuit: "data_check_integrity_sa_sha256_dg_sha256", makeInputs: () => helper.generateCircuitInputs("integrity"), chainFrom: "id_data" },
    { label: "age_gte_18", circuit: "compare_age", makeInputs: () => getAgeCircuitInputs(helper.passport as any, { age: { gte: 18 } }, salts, 0n, 0n, 0n, now), chainFrom: "integrity" },
    { label: "nationality_in_CAN", circuit: "inclusion_check_nationality", makeInputs: nationalityIn(["CAN"]), chainFrom: "integrity" },
    { label: "nationality_in_USA_CAN_FRA_GBR", circuit: "inclusion_check_nationality", makeInputs: nationalityIn(["USA", "CAN", "FRA", "GBR"]), chainFrom: "integrity" },
    { label: "nationality_in_USA_GBR_FRA", circuit: "inclusion_check_nationality", makeInputs: nationalityIn(["USA", "GBR", "FRA"]), chainFrom: "integrity", expectFailure: true },
  ]
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 })
  const outputs = new Map<string, bigint>()
  const manifest: { label: string; circuit: string }[] = []
  let failures = 0
  for (const step of steps) {
    const inputs = await step.makeInputs()
    if (!inputs) throw new Error(`could not build inputs for ${step.label}`)
    const program = JSON.parse(fs.readFileSync(`target/${step.circuit}.json`, "utf8"))
    const started = Date.now()
    let result: { witness: Uint8Array; returnValue: any }
    try {
      result = await new Noir(program).execute(inputs)
    } catch (e: any) {
      // Report only the circuit's assertion message, never the inputs.
      const reason = String(e?.message ?? e).split("\n")[0].slice(0, 120)
      if (step.expectFailure) {
        console.log(`${step.label}: refused by the circuit as expected ✓ (${reason})`)
      } else {
        failures++
        console.log(`${step.label}: FAILED ✗ (${reason})`)
      }
      continue
    }
    if (step.expectFailure) {
      failures++
      console.log(`${step.label}: UNEXPECTEDLY SATISFIED ✗`)
      continue
    }
    fs.writeFileSync(path.join(outDir, `${step.label}.gz`), result.witness, { mode: 0o600 })
    manifest.push({ label: step.label, circuit: step.circuit })

    const commIn = inputs.comm_in !== undefined ? asBig(inputs.comm_in) : undefined
    const chained =
      step.chainFrom === undefined
        ? "(first)"
        : commIn === outputs.get(step.chainFrom)
          ? `comm_in = ${step.chainFrom} output ✓`
          : `comm_in ≠ ${step.chainFrom} output ✗`
    if (chained.includes("✗")) failures++
    const out = Array.isArray(result.returnValue) ? result.returnValue : [result.returnValue]
    console.log(`${step.label}: witness in ${Date.now() - started} ms, ${chained}, returns [${out.map(short).join(", ")}]`)
    outputs.set(step.label, asBig(out[0]))
  }
  fs.writeFileSync(path.join(outDir, "witnesses.json"), JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600 })
  if (failures > 0) {
    console.error(`${failures} step(s) did not behave as expected`)
    process.exit(1)
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
