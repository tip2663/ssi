import * as jose from 'jose';

const ISS_PRIV_JWK = JSON.parse(process.env.ISS_PRIV_JWK!)
const ISS_PUB_JWK = process.env.ISS_PUB_JWK

// const issue = (payload: JwtCredentialPayload) => createVerifiableCredentialJwt(payload, {
//     did: 'did:web:waltid-qr-demo.vercel.app',
//     signer: async (data) => {
//         const key = await importJWK(JSON.parse(process.env.PRIV_JWK!), 'ES256') as CryptoKey;
//         const sig = await crypto.subtle.sign(
//             { name: 'ECDSA', hash: 'SHA-256' },
//             key,
//             typeof data !== 'string' ? data : new TextEncoder().encode(data)
//         );
//         return Buffer.from(sig).toString('base64url');
//     },
//     alg: 'ES256'
// }, { header: { 'kid': 'did:web:waltid-qr-demo.vercel.app#key-1' } })

export async function POST(r: Request) {
    console.log('request: ', r)
    const jsonBodyPayload = await r.json()
    console.log('body: ', jsonBodyPayload)
    if (jsonBodyPayload['proof'] && jsonBodyPayload['proof']['proof_type'] === 'jwt') {

        // verify ssi wallet sender
        const decodedHeader = jose.decodeProtectedHeader(jsonBodyPayload.proof.jwt)
        console.log(decodedHeader)
        const alg : string = decodedHeader.alg!
        const walletdid : string = decodedHeader.kid!
        const didjwk = await jose.importJWK({...JSON.parse(decodeURIComponent(atob((walletdid).split('did:jwk:',2)[1]))),alg})
        await jose.jwtVerify(jsonBodyPayload.proof.jwt, didjwk)
        
        console.log(didjwk)

    //     const subjectId = decodedHeader.kid || '';
    //     console.log('subjectId: ', { subjectId })

    //     const credential = await issue({
    //         iat: Date.now(),
    //         sub: subjectId,
    //         vc: {
    //             '@context': ['https://www.w3.org/2018/credentials/v1'],
    //             type: ['VerifiableCredential', 'MyCredential'],
    //             issuer: {
    //                 id: "did:web:waltid-qr-demo.vercel.app",
    //                 name: "qr demo app"
    //             },
    //             credentialSubject: {
    //                 id: subjectId,
    //                 somenumber: Math.round(Math.random() * 10)
    //             },
    //             issuanceDate: new Date().toISOString()
    //         }
    //     })
    //     console.log(credential)
    //     return new Response(JSON.stringify({ credential }), { headers: { 'content-type': 'application/json' } })

    }
    return new Response('no proof')
}