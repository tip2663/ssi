import * as jose from 'jose';

const BOT_JWK = { "crv": "Ed25519", "x": "Qh7WxBLCKdow-GYZMl0nwbHbLdkZecL1YtfDcDajiW0", "kty": "OKP", "alg": "EdDSA", "use": "sig", "kid": "TrUYWGFXBWKMUiZMxQvNHLAlutiH0T7i6rL06IpiBL0" }
const ISS_PRIV_JWK = JSON.parse(process.env.ISS_PRIV_JWK!)
const ISS_PUB_JWK = process.env.ISS_PUB_JWK

export async function GET(request: Request) {
    return new Response('hello')
}
export async function POST(request: Request) {
    console.log(request)
    const formData = await request.formData()
    if (formData.get('grant_type') === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
        const authcode = formData.get('pre-authorized_code')?.toString()
        if (authcode) {
            const { payload } = await jose.jwtVerify(authcode, BOT_JWK)
            const priv_jwk = await jose.importJWK(ISS_PRIV_JWK)
            const access_token = await new jose.SignJWT({ payload }).setIssuer(`did:jwk:${btoa(ISS_PUB_JWK||'')}`).setExpirationTime('5 minutes').setProtectedHeader({ 'alg': 'EdDSA' }).sign(priv_jwk)
            return new Response(JSON.stringify({
                access_token,
                token_type: "bearer",
                expires_in: 60 * 5,
                //authorization_details: [{
                //    type: 'openid_credential',
                //    credential_configuration_id: "SubredditMemberships",
                //    credential_identifiers: ["SubredditMembership_jwt_vc_json"]
                //}]
            }), { headers: { "cache-control": "no-store", "content-type": "application/json" } })
        }
    }
    return new Response(JSON.stringify({ "error": "invalid_grant" }), { status: 400, headers: { "cache-control": "no-store", "content-type": "application/json" } })
}