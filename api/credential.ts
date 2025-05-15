import * as jose from 'jose';
import { JwtCredentialPayload } from 'did-jwt-vc'
import { ISS_DID, ISS_PRIV_JWK, ISS_PUB_JWK } from './const.js';
import * as uuid from 'uuid'

const issue = async (payload: JwtCredentialPayload) => new jose.SignJWT({...payload,iss:ISS_DID}).setProtectedHeader({alg:'EdDSA',kid:`${ISS_DID}#0`,typ:'JWT'}).sign(ISS_PRIV_JWK)
export async function POST(r: Request) {
    const jsonBodyPayload = await r.json()

    const {payload:{payload:{subreddit,username,linkKarma,commentKarma,createdAt,sub:userId}}} = (await jose.jwtVerify(r.headers.get('Authorization')?.split('Bearer ',2)[1]!, ISS_PUB_JWK) as any);

    if (jsonBodyPayload['proof'] && jsonBodyPayload['proof']['proof_type'] === 'jwt') {

        // verify ssi wallet sender
        const decodedHeader = jose.decodeProtectedHeader(jsonBodyPayload.proof.jwt)
        const alg: string = decodedHeader.alg!
        const walletdid: string = decodedHeader.kid!
        const didjwk = await jose.importJWK({ ...JSON.parse(decodeURIComponent(atob((walletdid).split('did:jwk:', 2)[1].replace(/#0$/,'')))), alg })
        await jose.jwtVerify(jsonBodyPayload.proof.jwt, didjwk)
        const now = Math.floor(Date.now() / 1000)
        const oneYearInSeconds = 31536000;

        const credential = await issue({
            iat: now,
            nbf: now,
            sub: walletdid,
            exp: now + oneYearInSeconds,
            vc: {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential', 'SubredditMembership'],
                issuer: {
                    id: ISS_DID,
                    name: "u/devvit-vc"
                },
                credentialSubject: {
                    id: walletdid,
                    userId,
                    username,
                    subreddit,
                    linkKarma,
                    commentKarma,
                    createdAt
                },
                issuanceDate: new Date(now * 1000).toISOString()
            },
            jti:`urn:uuid:${uuid.v4()}`
        })
        return new Response(JSON.stringify({ credential }), { headers: { 'cache-control': 'no-store', 'content-type': 'application/json' } })

    }
    return new Response('no proof')
}