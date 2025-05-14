import * as jose from 'jose';
import { createVerifiableCredentialJwt, JwtCredentialPayload } from 'did-jwt-vc'
import { ISS_DID, ISS_PRIV_JWK } from './const.js';

const issue = (payload: JwtCredentialPayload) => createVerifiableCredentialJwt(payload, {
    did: ISS_DID,
    signer: async (data) => {
        const buffersource: BufferSource = typeof data !== 'string' ? Buffer.from(data) : new TextEncoder().encode(data)
        const sig = await crypto.subtle.sign(
            'EdDSA',
            ISS_PRIV_JWK,
            buffersource
        );
        return Buffer.from(sig).toString('base64url');
    },
    alg: 'EdDSA'
}, { header: { 'kid': ISS_DID } })

export async function POST(r: Request) {
    console.log('request: ', r)
    const jsonBodyPayload = await r.json()
    console.log('body: ', jsonBodyPayload)
    if (jsonBodyPayload['proof'] && jsonBodyPayload['proof']['proof_type'] === 'jwt') {

        // verify ssi wallet sender
        const decodedHeader = jose.decodeProtectedHeader(jsonBodyPayload.proof.jwt)
        console.log(decodedHeader)
        const alg: string = decodedHeader.alg!
        const walletdid: string = decodedHeader.kid!
        const didjwk = await jose.importJWK({ ...JSON.parse(decodeURIComponent(atob((walletdid).split('did:jwk:', 2)[1]))), alg })
        await jose.jwtVerify(jsonBodyPayload.proof.jwt, didjwk)
        const credential = await issue({
            iat: Date.now(),
            sub: walletdid,
            vc: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential', 'SubredditMembership'],
                issuer: {
                    id: ISS_DID,
                    name: "Reddit VC"
                },
                credentialSubject: {
                    id: walletdid,
                    somenumber: Math.round(Math.random() * 10)
                },
                issuanceDate: new Date().toISOString()
            }
        })
        console.log(credential)
        return new Response(JSON.stringify({ credential }), { headers: { 'cache-control': 'no-store', 'content-type': 'application/json' } })

    }
    return new Response('no proof')
}