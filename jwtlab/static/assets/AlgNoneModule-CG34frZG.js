import{j as e}from"./motion-7MZJb9m0.js";import{M as t,A as a,E as i}from"./ExercisePanel-Diwgwwj0.js";import"./vendor-E29-3-uS.js";import"./index-CSy6_zec.js";const r=[{title:"Legitimate HS256 Token Issued",client:`POST /login
{"username":"user","password":"password"}`,server:`HTTP 200
{"token": "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.<sig>"}`,description:"The server issues a valid HS256-signed JWT to the authenticated user."},{title:"Attacker Decodes Header",client:`Decode Base64url header:
{"alg":"HS256","typ":"JWT"}`,server:'Attacker reads: alg = "HS256"',description:"The attacker decodes the JWT header. The algorithm is set by the server but visible to anyone."},{title:'Attacker Changes alg to "none" and Promotes Role',client:`New header: {"alg":"none","typ":"JWT"}
Payload: {"role":"admin"}`,server:`Token assembled without signature:
eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.`,description:"The attacker re-encodes the header with alg=none, sets role to admin, and strips the signature (trailing dot).",highlight:!0},{title:"Vulnerable Server Accepts Token",client:`POST /verify
Authorization: Bearer eyJhbGciOiJub25lIn0...`,server:`HTTP 200
{"valid":true,"role":"admin","message":"Token accepted"}`,description:"The vulnerable server trusts the algorithm claim from the header and skips verification — the attacker gains admin access."}],n=`
The "none" algorithm (<span class="callout-term">RFC 7518 §3.6</span>) signals that no signature is expected.
Historically, many JWT libraries accepted a token's own claim that no verification was needed —
the server would skip signature checking entirely if <span class="callout-term-danger">alg=none</span> appeared in the header.

<strong>CVE-2015-9235</strong> documented this in the popular node-jsonwebtoken library.
The root cause: the verification algorithm was selected from the token header rather than
pinned server-side — allowing any bearer to <span class="callout-term-danger">bypass authentication</span> with a crafted token.
`,s='\n**Fix:** Enforce a server-side algorithm allowlist before calling the JWT verifier.\nNever use the token\'s own `alg` header to determine how to verify it.\n```python\n# Patched: algorithm pinned at the library call site\njwt.decode(token, secret, algorithms=["HS256"])  # ← list is explicit, from config\n```\n';function h(){return e.jsxs(t,{slug:"alg-none",title:"alg=none Bypass",severity:"Critical",cve:"CVE-2015-9235",narrative:n,mitigation:s,children:[e.jsx(a,{steps:r}),e.jsx(i,{slug:"alg-none",description:"Use the 'Set alg to none' shortcut to strip the signature and promote your role to admin."})]})}export{h as default};
