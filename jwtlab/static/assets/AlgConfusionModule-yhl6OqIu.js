import{j as e,u as g,m as k}from"./motion-7MZJb9m0.js";import{r as t}from"./vendor-E29-3-uS.js";import{M as f,A as v,E as x}from"./ExercisePanel-Diwgwwj0.js";import"./index-CSy6_zec.js";const S=[{title:"Attacker Obtains RS256 Public Key",client:`GET /.well-known/jwks.json
(lab endpoint: /api/v1/attack/alg-confusion/public-key)

Response:
{"publicKeyPem": "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0B...\\n-----END PUBLIC KEY-----\\n"}`,server:`Public key is intentionally exposed
(as is common — public keys are, by definition, public)

Key size: 2048-bit RSA`,description:"The server's RS256 public key is retrieved. Public keys are often exposed in JWKS endpoints or documentation. This is not a vulnerability by itself."},{title:"Attacker Forges HS256 Token Signed with Public Key Bytes",client:`Take public key PEM bytes as HMAC secret:

  header: {"alg":"HS256","typ":"JWT"}
  payload: {"sub":"user","role":"admin"}
  signature: HMAC-SHA256(pubkey_bytes, header.payload)`,server:`Attacker re-encodes the token with alg=HS256
and signs it using the public key bytes as the HMAC secret.

This produces a valid HMAC signature under HS256.`,description:'The attacker changes alg to "HS256" and signs the token using the RS256 public key bytes as the HMAC secret — a key the server already has!',highlight:!0},{title:"Vulnerable Server Verifies HS256 with Public Key",client:`POST /api/v1/attack/alg-confusion/verify
{"token": "eyJhbGciOiJIUzI1NiJ9.<admin-payload>.<sig>"}`,server:`Vulnerable library sees alg=HS256 from token header.
Looks up symmetric key: uses the stored public key bytes.
HMAC verification succeeds — signature matches!

HTTP 200: {"valid":true,"role":"admin"}`,description:"The vulnerable server trusts the alg field from the token header. It uses the same public key bytes (which the attacker also has) to verify the HS256 signature. It passes!",highlight:!0},{title:"Patched: Algorithm Pinned Server-Side",client:`POST /api/v1/attack/alg-confusion/verify
{"token": "eyJhbGciOiJIUzI1NiJ9.<admin-payload>.<sig>"}`,server:`Patched server ignores token's alg header.
Forces algorithm = RS256 before verification.

HTTP 401: {"valid":false,"message":"Algorithm not permitted."}`,description:"The patched endpoint pins the algorithm to RS256 explicitly, independent of what the token header claims. The attacker's HS256 token is rejected."}],w=`
<span class="callout-term-danger">Algorithm Confusion</span> (also called <span class="callout-term">Key Confusion</span>) exploits JWT libraries that derive the
verification algorithm from the token header rather than from server-side configuration.

The attack vector: RS256 uses two keys — a private key to sign, and a public key to verify.
If a vulnerable library sees <strong>alg=HS256</strong> in the header, it switches to symmetric
(HMAC) mode and uses whatever "key" is configured — which in an RS256 setup is the <em>public key</em>.

The attacker can obtain the public key (often published in a <span class="callout-term">JWKS endpoint</span>), use it as an
HMAC secret, and forge a perfectly valid HS256 signature. The server's own public key becomes
the attacker's signing key.

<strong>CVE-2016-10555</strong> documented this flaw in multiple popular JWT libraries.
`,j=`
**Fix:** Pin the algorithm explicitly at the verification call site — never read it from the token.

\`\`\`python
# Vulnerable: algorithm derived from header
jwt.decode(token, public_key, algorithms=jwt.get_unverified_header(token)["alg"])

# Patched: algorithm pinned server-side
jwt.decode(token, public_key, algorithms=["RS256"])  # ← explicit, from config
\`\`\`

Additionally, use separate key objects for signing and verification — some libraries detect
and reject algorithm mismatch automatically when key types differ.
`;function P({slug:a,onKeyFetched:i}){const[n,c]=t.useState(""),[r,o]=t.useState(!1),[d,h]=t.useState(""),l=g(),u=async()=>{o(!0);try{const s=(await(await fetch("/api/v1/attack/alg-confusion/public-key")).json()).publicKeyPem??"";c(s),i(s);const p=s.replace(/-----[^-]+-----\n?/g,"").replace(/\n/g,""),m=atob(p),y=Array.from(m.slice(0,32)).map(b=>b.charCodeAt(0).toString(16).padStart(2,"0")).join(" ");h(y+"…")}finally{o(!1)}};return e.jsxs("div",{className:"space-y-4",children:[e.jsx("div",{children:e.jsx("button",{onClick:u,disabled:r,className:"btn-secondary py-1.5 h-9 px-4 text-small","aria-label":"Fetch public key from server",children:r?"Fetching…":"🔑 Fetch Public Key"})}),n&&e.jsxs(k.div,{initial:{opacity:0,y:l?0:8},animate:{opacity:1,y:0},transition:{duration:l?0:.2},className:"grid grid-cols-2 gap-4",children:[e.jsxs("div",{children:[e.jsx("div",{className:"text-small text-text-muted mb-1 font-medium",children:"PEM Format"}),e.jsx("pre",{className:"code-block text-xs whitespace-pre-wrap max-h-48 overflow-y-auto",children:n})]}),e.jsxs("div",{children:[e.jsx("div",{className:"text-small text-text-muted mb-1 font-medium",children:"Raw Bytes (hex, first 32)"}),e.jsx("pre",{className:"code-block text-xs whitespace-pre-wrap font-mono break-all",children:d}),e.jsx("div",{className:"mt-2 p-2 bg-warning/10 border border-warning/30 rounded text-xs text-warning",children:"⚠ These bytes become the HMAC secret in algorithm confusion. The attacker uses this public key as the symmetric signing key."})]})]})]})}function N(){const[a,i]=t.useState("");return e.jsxs(f,{slug:"alg-confusion",title:"Algorithm Confusion (RS256 → HS256)",severity:"Critical",cve:"CVE-2016-10555",narrative:w,mitigation:j,children:[e.jsx(v,{steps:S}),e.jsxs("section",{className:"mb-6",children:[e.jsx("h2",{className:"font-display text-h3 text-text-primary mb-3",children:"Public Key Inspector"}),e.jsxs("p",{className:"text-text-muted text-small mb-3",children:["Fetch the server's RS256 public key. In a real attack, this is available via",e.jsx("code",{className:"mx-1 px-1 bg-surface-alt rounded text-xs",children:"/api/v1/attack/alg-confusion/public-key"}),"or a JWKS endpoint. The attacker uses these exact bytes as the HMAC secret."]}),e.jsx(P,{slug:"alg-confusion",onKeyFetched:i})]}),e.jsx(x,{slug:"alg-confusion",description:"Switch the Forge to HS256, paste the public key PEM bytes as the secret, and fire the token. The vulnerable endpoint will accept it because it uses the same public key bytes to verify.",defaultMutation:"flip-hs256-embedded",initialSecret:a||void 0})]})}export{N as default};
