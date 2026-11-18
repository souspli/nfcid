/**
 * Makes a synthetic passport for tests: a made-up person under a made-up state certificate, built
 * with zkPassport's own passport generator. Writes, into <out-dir>:
 *
 *   export.json     the same shape the NFC ID app exports (DG1 and EF.SOD)
 *   trust/csca.pem  the made-up state certificate, a trust directory for package.ts
 *
 * Nothing here comes from a real passport, so the outputs (and proofs made from them) are safe
 * to commit as test fixtures. The certificates are RSA PKCS#1 v1.5 with SHA-256, CSCA 4096 bits
 * and document signer 2048 bits, which needs these circuits in place of the Canadian ones:
 *
 *   circuit: "sig_check_dsc_tbs_700_rsa_pkcs_4096_sha256"
 *   circuit: "sig_check_id_data_tbs_700_rsa_pkcs_2048_sha256"
 *
 *   npx tsx nfcid-local/fixture.ts <out-dir>
 */
import fs from "fs"
import path from "path"
import { AlgorithmIdentifier } from "@peculiar/asn1-x509"
import { id_sha256WithRSAEncryption } from "@peculiar/asn1-rsa"
import { Binary } from "@zkpassport/utils"
import { generateSigningCertificates, generateSod, signSod, wrapSodInContentInfo } from "@zkpassport/utils/passport-generator"
import { serializeAsn } from "../src/ts/utils"

const outDir = process.argv[2]
if (!outDir) {
  console.error("usage: fixture.ts <out-dir>")
  process.exit(2)
}

// TD3, two lines of 44. Born 1988-11-12, expires 2040-01-01, citizen of Australia.
const MRZ = "P<AUSSILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<" + "PA12345673AUS8811125M4001013<<<<<<<<<<<<<<02"

function wrap77(contentInfo: Uint8Array): Buffer {
  const n = contentInfo.length
  if (n < 0x100 || n > 0xffff) throw new Error("unexpected SOD size")
  return Buffer.concat([Buffer.from([0x77, 0x82, n >> 8, n & 0xff]), contentInfo])
}

async function main() {
  if (MRZ.length !== 88) throw new Error("MRZ must be 88 characters")
  const dg1 = Binary.fromHex("615B5F1F58").concat(Binary.from(MRZ))
  const { cscPem, dsc, dscKeys } = await generateSigningCertificates({
    cscSigningHashAlgorithm: "SHA-256",
    cscKeyType: "RSA",
    cscKeySize: 4096,
    dscSigningHashAlgorithm: "SHA-256",
    dscKeyType: "RSA",
    dscKeySize: 2048,
  } as any)
  const { sod } = await generateSod(dg1, [dsc], "SHA-256", new AlgorithmIdentifier({ algorithm: id_sha256WithRSAEncryption }))
  const { sod: signedSod } = await signSod(sod, dscKeys, "SHA-256")
  const contentInfo = new Uint8Array(serializeAsn(wrapSodInContentInfo(signedSod)))

  fs.mkdirSync(path.join(outDir, "trust"), { recursive: true })
  const exp = { synthetic: true, files: { DG1: Buffer.from(dg1.toUInt8Array()).toString("base64"), "EF.SOD": wrap77(contentInfo).toString("base64") } }
  fs.writeFileSync(path.join(outDir, "export.json"), JSON.stringify(exp, null, 2) + "\n")
  fs.writeFileSync(path.join(outDir, "trust", "csca.pem"), cscPem)
  console.log(`synthetic passport written to ${outDir}`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
