import{j as e,u as p,A as o,m as a}from"./motion-7MZJb9m0.js";import{r as n}from"./vendor-E29-3-uS.js";import{M as h,A as c,E as d}from"./ExercisePanel-Diwgwwj0.js";import"./index-CSy6_zec.js";const u=[{title:"User Receives Short-lived Token",client:`POST /api/v1/attack/exp-bypass/login
{"username":"user","password":"password"}`,server:`HTTP 200
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
    eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNzAwMDAwMDAwfQ.
    <sig>"
}
// exp: 1700000000 (in the past)`,description:'The server issues a JWT with a short expiration. The HMAC secret "expsecret" is intentionally disclosed — this is the educational point: even knowing it, the server should reject expired tokens.'},{title:"Token Expires",client:`Time passes... token's exp timestamp is now in the past.

Attacker knows secret: "expsecret" (intentionally published here).

Attacker forges new token with exp in the future:
  payload.exp = Date.now()/1000 + 3600`,server:`With "expsecret" the attacker can:
  1. Decode the expired token
  2. Modify exp to a future timestamp
  3. Re-sign with the same secret

The server's vulnerability: it checks the
signature but NOT the exp claim.`,description:'The secret "expsecret" is intentionally disclosed. An attacker who knows this secret can re-sign any token with a modified expiry. The vulnerability is that signature verification alone is insufficient.',highlight:!0},{title:"Attacker Fires Re-signed Expired→Valid Token",client:`POST /api/v1/attack/exp-bypass/verify
{"token": "<re-signed with future exp>"}`,server:`Vulnerable server checks: signature valid? YES.
Vulnerable server: skips exp check!

HTTP 200 {"valid":true,"message":"Token accepted (signature verified; exp not checked — tab-1 mode)."}`,description:"The re-signed token passes because the server only checks the signature, not the expiration. An attacker who knows the secret can extend any token's lifetime indefinitely.",highlight:!0},{title:"Patched: Verify Signature AND exp",client:`POST /api/v1/attack/exp-bypass/verify
{"token": "<expired token, valid sig>"}`,server:`Patched: verifies signature AND checks exp.

HTTP 401 {"valid":false,"message":"Token expired."}

// Even valid-sig expired tokens are rejected`,description:"The patched endpoint checks both the signature and the exp claim. An expired token is rejected regardless of signature validity."}],x=[{title:"Attacker Obtains Any Valid Token",client:`POST /api/v1/attack/exp-bypass/login
{"username":"user","password":"password"}`,server:`HTTP 200 {"token": "<valid JWT signed with expsecret>"}

Known secret: expsecret`,description:"The attacker obtains any valid token. In tab-2 mode, they'll mutate the payload without re-signing — the server doesn't check the signature at all."},{title:"Mutate Claims Without Re-signing",client:`Take any JWT.
Modify payload: role → admin, exp → past/future

DO NOT re-sign — leave original signature or strip it.

?mode=nosig endpoint skips ALL verification.`,server:`In tab-2 mode (POST /verify?mode=nosig):
→ No signature check
→ No exp check
→ Accept any token with any claims`,description:"Tab-2 demonstrates the most severe failure: a server that performs no verification at all. The attacker can submit any base64url-encoded JSON payload and have it accepted.",highlight:!0},{title:"Fire Mutated Token with ?mode=nosig",client:`POST /api/v1/attack/exp-bypass/verify?mode=nosig
{"token": "<mutated-unsigned-token>"}`,server:`HTTP 200 {"valid":true,"message":"Token accepted (no signature or exp check — tab-2 mode)."}

Any payload, any signature, any exp — all accepted.`,description:"The ?mode=nosig endpoint accepts the mutated token unconditionally. This represents a critical misconfiguration where a server verifies neither signature nor expiry.",highlight:!0},{title:"Patched: Enforces Signature + exp in All Modes",client:`POST /api/v1/attack/exp-bypass/verify?mode=nosig
{"token": "<mutated-token>"}`,server:`Patched: toggle-patch enables strict verification.

HTTP 401 {"valid":false,"message":"Invalid signature."}

// Patched mode ignores ?mode=nosig`,description:"The patched endpoint enforces strict verification regardless of query parameters. The mode=nosig bypass is disabled when the patch is active."}],m=`
JWT expiration (<code>exp</code>) is only one of several claims that must be verified.
Two distinct failure modes are demonstrated here:

<strong>Tab 1 — Signature checked, exp ignored:</strong>
The server verifies the HMAC signature but forgets to check whether the token has expired.
Since the secret is known ("expsecret" — intentionally disclosed for this exercise), an attacker
can re-sign any token with an arbitrary <code>exp</code>. A server that doesn't check exp accepts
both the original and the extended token.

<strong>Tab 2 — Neither checked:</strong>
The most catastrophic failure: the server performs no <span class="callout-term-danger">cryptographic verification</span> at all.
An attacker can submit any base64url payload with arbitrary claims and have it accepted.
This often happens when developers use <code>verify_signature=False</code> in production code
that was meant only for debugging.

Both modes share the root cause: <span class="callout-term-danger">partial JWT validation</span>.
`,g=`
**Fix:** Always verify BOTH signature AND exp. Most JWT libraries check both by default.

\`\`\`python
# Vulnerable — skips exp check
claims = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_exp": False})

# Also vulnerable — skips signature entirely
claims = jwt.decode(token, options={"verify_signature": False}, algorithms=["none", "HS256"])

# Patched — default library behavior, no options override needed
claims = jwt.decode(token, secret, algorithms=["HS256"])
# ↑ This verifies signature AND checks exp by default
\`\`\`

**Key principle:** Never disable security checks in production code.
Use test-only flags like \`verify_signature=False\` only in unit tests, never in request handlers.

**Also validate nbf and iat:**
- \`nbf\` (Not Before): reject tokens presented before their valid window opens — prevents tokens from being used prematurely after theft
- \`iat\` (Issued At): flag tokens with an implausibly old issue time — signals replay of a long-stolen token

**Issue short-lived tokens:**
\`\`\`python
# Short-lived access token + refresh token pattern
access_token = jwt.encode(
    {"sub": user_id, "exp": now + 900},   # 15 minutes
    secret, algorithm="HS256"
)
# Refresh tokens live longer but can be revoked server-side
\`\`\`

A 15-minute window drastically limits what an attacker can do with a stolen token — even one
with a valid signature and future \`exp\`.
`;function y(){const[t,i]=n.useState("past"),s=p();return n.useEffect(()=>{const r=()=>{i("jumping"),setTimeout(()=>i("future"),400),setTimeout(()=>{i("past"),setTimeout(r,1200)},1600)},l=setTimeout(r,800);return()=>clearTimeout(l)},[]),e.jsxs("div",{className:"mb-6 flex items-center gap-6 bg-surface-alt border border-border rounded-card p-4",children:[e.jsx("div",{className:"text-4xl select-none","aria-hidden":"true",children:"🕐"}),e.jsxs("div",{className:"flex items-center gap-4",children:[e.jsx("div",{className:`rounded px-3 py-1.5 border font-mono text-small transition-all ${t==="past"?"bg-error/20 border-error text-error":"bg-surface border-border text-text-muted opacity-50"}`,children:"exp: PAST (expired)"}),e.jsx(o,{children:t==="jumping"&&e.jsx(a.span,{initial:{x:s?0:-8,opacity:0},animate:{x:0,opacity:1},exit:{x:s?0:8,opacity:0},transition:{duration:s?0:.2},className:"text-primary text-lg font-bold","aria-hidden":"true",children:"→"})}),t!=="jumping"&&e.jsx("span",{className:"text-text-muted",children:"→"}),e.jsx(o,{mode:"wait",children:t==="future"?e.jsx(a.div,{initial:{scale:s?1:.8,opacity:0},animate:{scale:1,opacity:1},exit:{scale:s?1:.8,opacity:0},transition:{duration:s?0:.22},className:"rounded px-3 py-1.5 border bg-primary/20 border-primary text-primary font-mono text-small font-bold",children:"exp: 2099 ✓ accepted"},"future"):e.jsx(a.div,{initial:{opacity:0},animate:{opacity:1},className:"rounded px-3 py-1.5 border border-border text-text-muted font-mono text-small opacity-50",children:"exp: 2099"},"waiting")})]}),e.jsx("div",{className:"text-xs text-text-muted ml-auto",children:"Attacker re-signs expired token with future exp"})]})}function T(){const[t,i]=n.useState("tab1");return e.jsxs(h,{slug:"exp-bypass",title:"Expired Token Extension (exp bypass)",severity:"High",cve:null,narrative:m,mitigation:g,children:[e.jsxs("div",{className:"mb-4 p-3 bg-warning/10 border border-warning/30 rounded-card",children:[e.jsx("span",{className:"text-warning text-small font-medium",children:"Intentionally Published Secret: "}),e.jsx("code",{className:"font-mono text-warning bg-warning/10 px-1 rounded",children:"expsecret"}),e.jsx("span",{className:"text-text-muted text-xs ml-2",children:"— used for tab-1 re-signing exercise"})]}),e.jsxs("div",{className:"flex gap-2 mb-6",role:"tablist",children:[e.jsx("button",{onClick:()=>i("tab1"),className:`px-4 py-2 rounded text-small font-medium transition-colors
            ${t==="tab1"?"bg-primary text-surface border border-primary":"btn-secondary"}`,"aria-selected":t==="tab1",role:"tab",children:"Tab 1: sig checked, exp ignored"}),e.jsx("button",{onClick:()=>i("tab2"),className:`px-4 py-2 rounded text-small font-medium transition-colors
            ${t==="tab2"?"bg-primary text-surface border border-primary":"btn-secondary"}`,"aria-selected":t==="tab2",role:"tab",children:"Tab 2: no sig, no exp check"})]}),t==="tab1"?e.jsxs(e.Fragment,{children:[e.jsx(c,{steps:u}),e.jsx(y,{}),e.jsx(d,{slug:"exp-bypass",description:"Tab 1: Use the 'Set exp to past' shortcut, then enter 'expsecret' as the HMAC secret and fire. The vulnerable endpoint accepts re-signed tokens regardless of expiry. The patched endpoint rejects them with 'Token expired.'",defaultMutation:"set-exp-past"})]}):e.jsxs(e.Fragment,{children:[e.jsx(c,{steps:x}),e.jsx(d,{slug:"exp-bypass",description:"Tab 2: Click 'Set alg to none' to produce an unsigned token. Fire at POST /api/v1/attack/exp-bypass/verify?mode=nosig — the vulnerable endpoint accepts any token regardless of signature or expiry. Toggle patch to enable strict verification.",defaultMutation:"alg-none",verifyUrl:"/api/v1/attack/exp-bypass/verify?mode=nosig"})]})]})}export{T as default};
