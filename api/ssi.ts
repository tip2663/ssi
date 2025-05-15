import * as jose from 'jose';
import { BOT_PUB_JWK, ISS_DID, ISS_PRIV_JWK } from './const.js';

export async function POST(request: Request) {
    const formData = await request.formData()
    if (formData.get('grant_type') === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
        const authcode = formData.get('pre-authorized_code')?.toString()
        if (authcode) {
            const { payload } = await jose.jwtVerify(authcode, BOT_PUB_JWK)
            const access_token = await new jose.SignJWT({ payload }).setIssuer(ISS_DID).setExpirationTime('5 minutes').setProtectedHeader({ 'alg': 'EdDSA' }).sign(ISS_PRIV_JWK)
            return new Response(JSON.stringify({
                access_token,
                token_type: "bearer",
                expires_in: 60 * 5,
            }), { headers: { "cache-control": "no-store", "content-type": "application/json" } })
        }
    }
    return new Response(JSON.stringify({ "error": "invalid_grant" }), { status: 400, headers: { "cache-control": "no-store", "content-type": "application/json" } })
}