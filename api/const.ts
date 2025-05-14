export const ISS_PRIV_JWK = JSON.parse(process.env.ISS_PRIV_JWK!)
export const ISS_DID = Buffer.from(process.env.ISS_PUB_JWK || '').toString('base64url')