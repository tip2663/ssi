import * as jose from 'jose';

const BOT_JWK = { "crv": "Ed25519", "x": "Qh7WxBLCKdow-GYZMl0nwbHbLdkZecL1YtfDcDajiW0", "kty": "OKP", "alg": "EdDSA", "use": "sig", "kid": "TrUYWGFXBWKMUiZMxQvNHLAlutiH0T7i6rL06IpiBL0" }

export async function POST(request: Request) {
    const formData = await request.formData()
    const authcode = formData.get('authorization_code')?.toString()
    if (authcode) {
        const {payload} = await jose.jwtVerify(authcode, BOT_JWK)
        console.log(payload)
        return new Response('Hello')
    }
    return new Response('Hello')
}