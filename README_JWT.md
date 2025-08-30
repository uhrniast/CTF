# JWT Security Research Report
*Author:* DGPL CTF Candidate  
*Date:* 2025-08-29  
--------------------------------------------------------------------------------------------------------------------------------------
## Executive Summary
JSON Web Tokens (JWTs) are widely used for stateless authentication in modern web applications and APIs. 
While convenient, misconfigurations and insecure implementations can lead to severe security vulnerabilities.
This report highlights the most common JWT-related issues, real-world CVEs, and recommended mitigations.
----------------------------------------------------------------------------------------------------------------------------------------
## Common Vulnerabilities
### 1. **alg=none Vulnerability**
- Some JWT libraries or misconfigured applications allow tokens with alg=none to bypass signature verification.
- Attackers can forge tokens with arbitrary claims (e.g., isAdmin: true).

*Example CVE:*  
- *CVE-2018-1000539* – Libraries accepting alg=none without validation.
------------------------------------------------------------------------------------------------------------------------------------------
### 2. *Weak HS256 Secrets*
- JWTs signed with HMAC using short or guessable secrets (e.g., "password123") can be brute-forced.
- Attackers who recover the secret can sign their own tokens.

*Example CVE:*  
- *CVE-2022-23529* – Weak JWT secret allowed attackers to forge tokens.
---------------------------------------------------------------------------------------------------------------------------------
### 3. *Key Confusion (RS256 ↔ HS256)*
- Occurs when servers incorrectly trust the algorithm provided in the token header.
- Attackers can trick the server into using the *public key* as an HMAC secret.
----------------------------------------------------------------------------------------------------------------------------------
### 4. *Replay Attacks*
- Tokens without proper expiration or replay protection can be reused indefinitely if stolen.
- Risk is higher with long-lived access tokens.
------------------------------------------------------------------------------------------------------------------------------------
## Mitigations
- *Enforce Algorithm Whitelist*: Specify allowed algorithms in the verification function, e.g. algorithms=['RS256'].
- *Prefer Asymmetric Signing (RS256)*:
  - Protect private keys using secure storage (HSM/KMS).
  - Rotate keys periodically.
- *Strong Secrets for HS256*:
  - Use at least 32 bytes of random data for HMAC keys.
- *Validate Claims*:
  - Check iss, aud, exp, nbf, and set short expiration times (e.g., 15 minutes).
- *Replay Protection*:
  - Use refresh tokens securely stored in HTTP-only cookies.
- *Always Use HTTPS*:
  - Prevent token interception.
----------------------------------------------------------------------------------------------------------------------------
## Real-World Impact & CVEs
- *CVE-2015-9235*: jwt-simple allowed tokens with alg=none to bypass verification.
- *CVE-2022-23529*: JWT verification bypass due to weak secret keys.
- *CVE-2018-1000539*: Improper JWT validation in certain libraries.
----------------------------------------------------------------------------------------------------------------------------
## PoC Summary
The provided PoC demonstrates:
- alg=none attack: Forging tokens without any signature.
- Weak HS256 secret brute-force: Recovering a weak secret key using a small dictionary.
-----------------------------------------------------------------------------------------------------------------------------
## References
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [NVD CVE Database](https://nvd.nist.gov/)
- [PyJWT Documentation](https://pypi.org/project/PyJWT/)
- [jsonwebtoken (Node.js)](https://www.npmjs.com/package/jsonwebtoken)
------------------------------------------------------------------------------------------------------------------------------
## Conclusion
JWT is a powerful authentication mechanism but highly sensitive to misconfiguration. 
By enforcing strict algorithm checks, using strong secrets, validating claims, and employing key management best practices, 
organizations can significantly reduce the attack surface.
