/**
 * Builds a Souspli passport-proof package from an NFC ID passport export: a chain of zkPassport
 * proofs up to the CSCA, the requested claims, and a `bind` proof tying it all to one Souspli
 * address. Proves in-process with bb.js, so no witness (which holds passport data) touches disk.
 *
 * Normally run through `zk/package.sh`. From inside the zkPassport checkout:
 *
 *   npx tsx nfcid-local/package.ts <export.json> <trust-dir> <out.json> --address 0x… --scope <text>
 *       [--subscope <text>] [--min-age N] [--nationality CAN,USA] [--pins <pins.json>]
 *       [--dsc-circuit <name>] [--id-circuit <name>] [--integrity-circuit <name>]
 *
 * Every run uses fresh random salts, so two packages from the same passport share no public value
 * unless they share a scope (then they share the nullifier, by design). The package holds proofs
 * and public inputs only. --pins writes what a verifier must pin: the registry root and each
 * circuit's verification key. Prints hashes and timings, never passport data.
 */
import crypto from "crypto"
import fs from "fs"
import os from "os"
import { Barretenberg, UltraHonkBackend, UltraHonkVerifierBackend } from "@aztec-foundation/bb.js"
import { Noir } from "@noir-lang/noir_js"
import {
  ProofType,
  formatBoundData,
  getAgeCircuitInputs,
  getAgeParameterCommitment,
  getBindCircuitInputs,
  getBindParameterCommitment,
  getCountryParameterCommitment,
  getDSCCircuitInputs,
  getIDDataCircuitInputs,
  getIntegrityCheckCircuitInputs,
  getNationalityInclusionCircuitInputs,
  getNowTimestamp,
  getServiceScopeHash,
  getServiceSubscopeHash,
} from "@zkpassport/utils"
import { loadPassport, short } from "./common"

export const PACKAGE_FORMAT = "souspli-passport-proof/1"
/** bb's proof flavour: zero-knowledge, and the one zkPassport's recursive outer circuit takes. */
const TARGET = { verifierTarget: "noir-recursive" } as const

const argv = process.argv.slice(2)
const positional = argv.filter((a, i) => !a.startsWith("--") && !argv[i - 1]?.startsWith("--"))
const flag = (name: string) => {
  const i = argv.indexOf(`--${name}`)
  return i >= 0 ? argv[i + 1] : undefined
}
const [exportPath, trustDir, outPath] = positional
const address = flag("address")
const scope = flag("scope")
const subscope = flag("subscope") ?? ""
const minAge = flag("min-age") ? Number(flag("min-age")) : undefined
const nationalityIn = flag("nationality")?.split(",").map((c) => c.trim().toUpperCase())
const pinsPath = flag("pins")
// The signature circuits depend on the passport's algorithms and key sizes. The defaults fit a
// Canadian passport: RSA-PSS with SHA-256, a 4096-bit CSCA and a 2048-bit document signer.
const dscCircuit = flag("dsc-circuit") ?? "sig_check_dsc_tbs_1000_rsa_pss_4096_sha256"
const idCircuit = flag("id-circuit") ?? "sig_check_id_data_tbs_1000_rsa_pss_2048_sha256"
const integrityCircuit = flag("integrity-circuit") ?? "data_check_integrity_sa_sha256_dg_sha256"
if (!exportPath || !trustDir || !outPath || !address || !scope) {
  console.error("usage: package.ts <export.json> <trust-dir> <out.json> --address 0x… --scope <text> [--subscope <text>] [--min-age N] [--nationality CAN,USA] [--pins <file>]")
  process.exit(2)
}
if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error("--address must be 0x and 40 hex characters")
if (minAge !== undefined && !(Number.isInteger(minAge) && minAge > 0 && minAge < 150)) throw new Error("--min-age must be a whole number")
if (nationalityIn?.some((c) => !/^[A-Z]{3}$/.test(c))) throw new Error("--nationality takes 3-letter country codes")

/** A random field element (248 bits, below the BN254 modulus). */
const salt = () => BigInt("0x" + crypto.randomBytes(31).toString("hex"))
const field = (v: string) => BigInt(v)

async function main() {
  const { helper, certs } = await loadPassport(exportPath, trustDir)
  const passport = helper.passport as any
  console.log(`certificate registry: ${certs.certificates.length} CSCA certs, root ${short(certs.root)}`)

  const dscSalt = salt()
  const idSalt = salt()
  const salts = { dg1Salt: salt(), expiryDateSalt: salt(), dg2HashSalt: salt(), privateNullifierSalt: salt() }
  const now = getNowTimestamp()
  const scopeHash = getServiceScopeHash(scope!)
  const subscopeHash = subscope ? getServiceSubscopeHash(subscope) : 0n
  // nullifierSecret 0: the plain nullifier, one per passport per scope.
  const disclosure = [salts, 0n, scopeHash, subscopeHash, now] as const

  type Step = { name: string; circuit: string; inputs: () => Promise<any>; expectParam?: () => Promise<bigint> }
  const steps: Step[] = [
    { name: "dsc", circuit: dscCircuit, inputs: () => getDSCCircuitInputs(passport, dscSalt, certs) },
    { name: "id_data", circuit: idCircuit, inputs: () => getIDDataCircuitInputs(passport, dscSalt, idSalt) },
    { name: "integrity", circuit: integrityCircuit, inputs: () => getIntegrityCheckCircuitInputs(passport, idSalt, salts) },
  ]
  if (minAge !== undefined) {
    steps.push({
      name: "age",
      circuit: "compare_age",
      inputs: () => getAgeCircuitInputs(passport, { age: { gte: minAge } }, ...disclosure),
      expectParam: () => getAgeParameterCommitment(minAge, 0),
    })
  }
  if (nationalityIn) {
    steps.push({
      name: "nationality",
      circuit: "inclusion_check_nationality",
      inputs: () => getNationalityInclusionCircuitInputs(passport, { nationality: { in: nationalityIn as any } }, ...disclosure),
      expectParam: () => getCountryParameterCommitment(ProofType.NATIONALITY_INCLUSION, nationalityIn as any),
    })
  }
  steps.push({
    name: "bind",
    circuit: "bind",
    inputs: () => getBindCircuitInputs(passport, { bind: { user_address: address } }, ...disclosure),
    expectParam: () => getBindParameterCommitment(formatBoundData({ user_address: address })),
  })

  const api = await Barretenberg.new({ threads: Math.min(os.cpus().length, 16) })
  const verifier = new UltraHonkVerifierBackend(api)
  const proofs: { name: string; circuit: string; vkHash: string; publicInputs: string[]; proof: string }[] = []
  const vkeys: Record<string, string> = {}
  try {
    for (const step of steps) {
      const inputs = await step.inputs()
      if (!inputs) throw new Error(`could not build inputs for ${step.name}`)
      const program = JSON.parse(fs.readFileSync(`target/${step.circuit}.json`, "utf8"))
      const started = Date.now()
      const { witness } = await new Noir(program).execute(inputs)
      const backend = new UltraHonkBackend(program.bytecode, api)
      const proof = await backend.generateProof(witness, TARGET)
      const vk = await backend.getVerificationKey(TARGET)
      if (!(await verifier.verifyProof({ ...proof, verificationKey: vk }, TARGET))) throw new Error(`${step.name}: proof does not verify`)
      vkeys[step.circuit] = Buffer.from(vk).toString("base64")
      proofs.push({
        name: step.name,
        circuit: step.circuit,
        vkHash: crypto.createHash("sha256").update(vk).digest("hex"),
        publicInputs: proof.publicInputs,
        proof: Buffer.from(proof.proof).toString("base64"),
      })
      console.log(`${step.name}: proved and verified in ${((Date.now() - started) / 1000).toFixed(1)} s, ${proof.proof.length} B, ${proof.publicInputs.length} public inputs`)
    }
  } finally {
    await api.destroy()
  }

  // The same checks a verifier makes on the public inputs. Layouts:
  //   dsc        [registry root, comm_out]
  //   id_data    [comm_in, comm_out]
  //   integrity  [comm_in, comm_out, verification method]
  //   disclosure [comm_in, date, scope, subscope, param commitment, nullifier type, nullifier, oprf key hash]
  const byName = Object.fromEntries(proofs.map((p) => [p.name, p.publicInputs.map(field)]))
  const check = (ok: boolean, what: string) => {
    if (!ok) throw new Error(`self-check failed: ${what}`)
  }
  check(byName.dsc[0] === BigInt(certs.root), "dsc proof uses the registry root")
  check(byName.id_data[0] === byName.dsc[1], "id_data chains from dsc")
  check(byName.integrity[0] === byName.id_data[1], "integrity chains from id_data")
  const nullifier = byName.bind[6]
  for (const step of steps.filter((s) => s.expectParam)) {
    const pi = byName[step.name]
    check(pi.length === 8, `${step.name} has 8 public inputs`)
    check(pi[0] === byName.integrity[1], `${step.name} chains from integrity`)
    check(pi[1] === BigInt(now), `${step.name} carries the proof date`)
    check(pi[2] === scopeHash && pi[3] === subscopeHash, `${step.name} carries the scope`)
    check(pi[4] === (await step.expectParam!()), `${step.name} commits to the requested parameters`)
    check(pi[5] === byName.bind[5] && pi[6] === nullifier && pi[7] === 0n, `${step.name} shares the nullifier`)
  }

  const pkg = {
    format: PACKAGE_FORMAT,
    address: address!.toLowerCase(),
    scope,
    subscope,
    claims: { ...(minAge !== undefined ? { minAge } : {}), ...(nationalityIn ? { nationalityIn } : {}) },
    proofs,
  }
  fs.writeFileSync(outPath, JSON.stringify(pkg) + "\n", { mode: 0o600 })
  if (pinsPath) {
    const pins = { registryRoot: "0x" + byName.dsc[0].toString(16).padStart(64, "0"), target: TARGET.verifierTarget, vkeys }
    fs.writeFileSync(pinsPath, JSON.stringify(pins, null, 2) + "\n")
  }
  console.log(`registry root ${short(byName.dsc[0])}, integrity method ${byName.integrity[2]}, nullifier type ${byName.bind[5]}, nullifier ${short(nullifier)}`)
  console.log(`package: ${outPath} (${fs.statSync(outPath).size} B)`)
}

main().catch((e) => {
  // Only the message: a stack or an inputs dump could carry passport data.
  console.error(`error: ${String(e?.message ?? e).split("\n")[0].slice(0, 200)}`)
  process.exit(1)
})
