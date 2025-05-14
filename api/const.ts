import { importJWK } from "jose"


export const BOT_PUB_JWK = { "crv": "Ed25519", "x": "Qh7WxBLCKdow-GYZMl0nwbHbLdkZecL1YtfDcDajiW0", "kty": "OKP", "alg": "EdDSA", "use": "sig", "kid": "TrUYWGFXBWKMUiZMxQvNHLAlutiH0T7i6rL06IpiBL0" }
export const ISS_PRIV_JWK : CryptoKey = await importJWK(JSON.parse(process.env.ISS_PRIV_JWK!)) as CryptoKey
export const ISS_DID = Buffer.from(process.env.ISS_PUB_JWK || '').toString('base64url')