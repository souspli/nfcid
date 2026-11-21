/**
 * Prints what a verifier of format-2 packages pins that does not depend on any passport: the root
 * of zkPassport's circuit registry for this release and the verification keys of the outer
 * circuits. Run through `zk/outer-pins.sh`. From inside the zkPassport checkout:
 *
 *   npx tsx nfcid-local/outer-pins.ts > pins-outer.json
 *
 * Each key is checked against the registry's own list before it is printed, so a circuit compiled
 * differently from the release stops this rather than producing a key nobody else has.
 */
import fs from "fs"
import { Barretenberg, UltraHonkBackend } from "@aztec-foundation/bb.js"
import { poseidon2HashAsync } from "@zkpassport/poseidon2"
import circuitManifest from "../src/ts/tests/fixtures/circuit-manifest.json"
import { OUTER } from "./outer-circuits"

const TARGET = { verifierTarget: "noir-recursive" } as const

async function main() {
  const api = await Barretenberg.new({ threads: 4 })
  const vkeys: Record<string, string> = {}
  try {
    for (const { circuit } of OUTER) {
      const program = JSON.parse(fs.readFileSync(`target/${circuit}.json`, "utf8"))
      const vk = await new UltraHonkBackend(program.bytecode, api).getVerificationKey(TARGET)
      const fields = Buffer.from(vk).toString("hex").match(/.{1,64}/g)!.map((x) => BigInt("0x" + x))
      if ((await poseidon2HashAsync(fields)) !== BigInt((circuitManifest as any).circuits[circuit].hash)) {
        throw new Error(`${circuit}: its key is not the one in zkPassport's circuit registry ${circuitManifest.version}`)
      }
      vkeys[circuit] = Buffer.from(vk).toString("base64")
    }
  } finally {
    await api.destroy()
  }
  const root = "0x" + BigInt(circuitManifest.root).toString(16).padStart(64, "0")
  console.log(JSON.stringify({ circuitRoot: root, circuits: circuitManifest.version, target: TARGET.verifierTarget, vkeys }, null, 2))
}

main().catch((e) => {
  console.error(`error: ${String(e?.message ?? e).split("\n")[0].slice(0, 200)}`)
  process.exit(1)
})
