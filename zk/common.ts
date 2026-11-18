/**
 * Shared by witness.ts and package.ts: loads an NFC ID passport export and the CSCA trust
 * directory into the shapes zkPassport's input builders take. Runs from inside a zkPassport
 * circuits checkout (see setup.sh). Never prints passport data.
 */
import fs from "fs"
import path from "path"
import { Binary, calculatePackagedCertificatesRoot, type PackagedCertificatesFile } from "@zkpassport/utils"
import { TestHelper, convertPemToPackagedCertificateV1 } from "../src/ts/test-helper"

/** EF.SOD is `77 len ContentInfo`; zkPassport's reader wants the bare ContentInfo. */
function unwrapSod(b: Buffer): Buffer {
  if (b[0] !== 0x77) throw new Error("EF.SOD must start with tag 77")
  let i = 1
  let len = b[i++]
  if (len & 0x80) {
    const n = len & 0x7f
    len = 0
    for (let k = 0; k < n; k++) len = (len << 8) | b[i++]
  }
  return b.subarray(i, i + len)
}

/**
 * zkPassport's registry root covers a timestamp as well as the certificates. A verifier can only
 * pin a root that is reproducible, so the trust set carries a fixed one: the day it was checked
 * against the German master list (2026-11-17 00:00 UTC). Change it when trust/ changes.
 */
export const TRUST_SET_TIMESTAMP = 1794873600

/** Shortens a hash for logging. */
export const short = (v: unknown) => {
  const s = typeof v === "bigint" ? "0x" + v.toString(16) : String(v)
  return s.length > 18 ? s.slice(0, 10) + "…" + s.slice(-6) : s
}

/** The passport from an export, in a TestHelper whose certificate registry is `trustDir`'s PEMs. */
export async function loadPassport(exportPath: string, trustDir: string) {
  const exp = JSON.parse(fs.readFileSync(exportPath, "utf8"))
  const dg1 = Binary.from(new Uint8Array(Buffer.from(exp.files["DG1"], "base64")))
  const sod = Binary.from(new Uint8Array(unwrapSod(Buffer.from(exp.files["EF.SOD"], "base64"))))

  const helper = new TestHelper()
  await helper.loadPassport(dg1, sod)

  const certs: PackagedCertificatesFile = {
    version: 1,
    timestamp: TRUST_SET_TIMESTAMP,
    root: "",
    certificates: [],
    masterlists: [],
    revocations: [],
  }
  for (const f of fs.readdirSync(trustDir).filter((f) => f.endsWith(".pem")).sort()) {
    certs.certificates.push(await convertPemToPackagedCertificateV1(fs.readFileSync(path.join(trustDir, f), "utf8")))
  }
  certs.root = await calculatePackagedCertificatesRoot(certs)
  helper.setCertificates(certs)
  return { helper, certs }
}
