import * as jose from 'jose';
import { JwtCredentialPayload } from 'did-jwt-vc'
import { ISS_DID, ISS_PRIV_JWK, ISS_PUB_JWK } from './const.js';
import * as uuid from 'uuid'

// const issue = (payload: JwtCredentialPayload) => createVerifiableCredentialJwt(payload, {
//     did: ISS_DID,
//     signer: async (data) => {
//         const buffersource: BufferSource = typeof data !== 'string' ? Buffer.from(data) : new TextEncoder().encode(data)
//         const sig = await crypto.subtle.sign(
//             'EdDSA',
//             ISS_PRIV_JWK,
//             buffersource
//         );
//         return Buffer.from(sig).toString('base64url');
//     },
//     alg: 'EdDSA'
// }, { header: { 'kid': ISS_DID } })
const issue = async (payload: JwtCredentialPayload) => new jose.SignJWT({...payload,iss:ISS_DID}).setProtectedHeader({alg:'EdDSA',kid:ISS_DID,typ:'JWT'}).sign(ISS_PRIV_JWK)
//  createVerifiableCredentialJwt(payload, {
//     did: ISS_DID,
//     signer: async (data) => {
//         const buffersource = typeof data !== 'string' ? data : new TextEncoder().encode(data);
//         return (await (await new jose.GeneralSign(buffersource).addSignature(ISS_PRIV_JWK)).sign()).signatures[0].signature
//     },
//     alg: 'EdDSA'  // Specify EdDSA as the algorithm
// }, { header: { 'kid': ISS_DID } });

export async function POST(r: Request) {
    const jsonBodyPayload = await r.json()

    const jwt = await jose.jwtVerify(r.headers.get('Authorization')?.split('Bearer ',2)[1]!, ISS_PUB_JWK);
    console.log(jwt.payload)

    if (jsonBodyPayload['proof'] && jsonBodyPayload['proof']['proof_type'] === 'jwt') {

        // verify ssi wallet sender
        const decodedHeader = jose.decodeProtectedHeader(jsonBodyPayload.proof.jwt)
        console.log(decodedHeader)
        const alg: string = decodedHeader.alg!
        const walletdid: string = decodedHeader.kid!
        const didjwk = await jose.importJWK({ ...JSON.parse(decodeURIComponent(atob((walletdid).split('did:jwk:', 2)[1]))), alg })
        await jose.jwtVerify(jsonBodyPayload.proof.jwt, didjwk)
        const now = Date.now()
        const credential = await issue({
            iat: now,
            nbf: now,
            sub: walletdid,
            vc: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential', 'SubredditMembership'],
                issuer: {
                    id: ISS_DID,
                    name: "u/devvit-vc"
                },
                credentialSubject: {
                    id: walletdid,
                    somenumber: Math.round(Math.random() * 10)
                },
                issuanceDate: new Date().toISOString()
            },
            jti:`urn:uuid:${uuid.v4()}`
        })
        console.log(credential)
        return new Response(JSON.stringify({ credential }), { headers: { 'cache-control': 'no-store', 'content-type': 'application/json' } })

    }
    return new Response('no proof')
}