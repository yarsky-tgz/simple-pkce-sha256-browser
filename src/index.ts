import { HMAC, Hash } from 'fast-sha256'
import { createPKCEHelper as originalCreatePKCEHelper, PKCEHelper } from 'abstract-pkce'

export type { PKCEHelper, PKCEChallenge } from 'abstract-pkce'

export type PKCEHelperLegacyBrowser = PKCEHelper<string>

const windowsCrypto: Crypto | undefined = ((window as unknown) as { msCrypto: Crypto }).msCrypto
const standardCrypto: Crypto | undefined = window.crypto
const dummyCrypto: Pick<Crypto, 'getRandomValues'> = {
  getRandomValues: <
    T extends
    | Int8Array
    | Int16Array
    | Int32Array
    | Uint8Array
    | Uint16Array
    | Uint32Array
    | Uint8ClampedArray
    | Float32Array
    | Float64Array
    | DataView
    | null
    >(
    array: T,
  ) => (array as Uint8Array)?.map(() => Math.floor(Math.random() * 255)) as T,
}
const crypto: Crypto | Pick<Crypto, 'getRandomValues'> = standardCrypto
  || windowsCrypto
  || dummyCrypto
const bufferToBase64: (input: ArrayBuffer) => string = (input) => window
  .btoa(String.fromCharCode(...Array.from(new Uint8Array(input))))

export const createPKCEHelper: (isHMAC?: boolean) => PKCEHelperLegacyBrowser = (
  isHMAC = true,
) => originalCreatePKCEHelper<string>({
  getChallenge: isHMAC
    ? (verifier: string) => bufferToBase64(new HMAC(new TextEncoder().encode(verifier)).digest())
    : (verifier: string) => bufferToBase64(new Hash().update(new TextEncoder().encode(verifier)).digest()),
  buildVerifier: (
    length: number, possibleCharsCount: number, getPossibleChar: (position: number) => string,
  ): string => crypto
    .getRandomValues(new Uint8Array(length))
    .reduce(
      (previous, randomValue) => `${previous}${getPossibleChar(randomValue % possibleCharsCount)}`,
      '',
    ),
})
