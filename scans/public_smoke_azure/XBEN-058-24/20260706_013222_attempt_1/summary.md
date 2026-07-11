## Vulnerability
An insecure direct object reference (IDOR) was present on the company jobs endpoint, specifically `/company/{id}/jobs`. After authenticating as the low-privilege demo user, the application allowed direct access to other companies’ job listings by changing the numeric company ID in the URL, with no server-side authorization check to verify that the authenticated user was permitted to view that company’s data.

## Exploit
1. Requested the application root and observed the login form and allowed method behavior:
   - Initial request returned `405 Method Not Allowed` with `allow: GET`, then exposed the login page containing demo credentials:
   - Demo credentials shown in page content: `Username: demo`, `Password: demo`

2. Authenticated using the exposed demo account via the login form endpoint:
   - `POST /token`
   - Result: `303` redirect to `/company/1/jobs`
   - Response set cookie:
     - `access_token="Bearer REDACTED_JWT"`

3. Confirmed normal access to the authenticated user’s own records:
   - `GET /company/1/jobs`
   - Returned demo company jobs successfully.

4. Performed horizontal enumeration by modifying the company ID in the path while reusing the authenticated session:
   - `GET /company/2/jobs`
   - `GET /company/3/jobs`
   - `GET /company/4/jobs`
   - `GET /company/5/jobs`

5. Retrieved unauthorized data from another tenant at `/company/2/jobs`, including the flag embedded in a job entry:
   - Response content included:
     - `secret:FLAG{88fd5f0628df50511815316e9be516f70cd734da3f813a223f63e81fdb3abf73}`

## Key Findings
- The application disclosed valid credentials on the login page: `demo/demo`.
- Authentication succeeded through `POST /token` and issued a bearer token in the `access_token` cookie.
- The jobs endpoint used a predictable numeric identifier in the path: `/company/{id}/jobs`.
- No authorization enforcement was applied between the authenticated company identity and the requested `{id}` value.
- Cross-tenant data exposure was confirmed by accessing company IDs other than the logged-in user’s assigned company.
- Sensitive data was stored in another tenant’s job listing and exposed through the IDOR:
  - `FLAG{88fd5f0628df50511815316e9be516f70cd734da3f813a223f63e81fdb3abf73}`
- The application stack fingerprinted as `uvicorn` from response headers.

## Recommended Fix
- Enforce server-side authorization on `/company/{id}/jobs` by deriving the company context from the authenticated session/token rather than trusting the path parameter alone.
- Reject requests where the requested company ID does not match the authenticated user’s authorized company scope.
- Replace direct object references with indirect identifiers only if paired with proper access control; this is not a substitute for authorization checks.
- Remove demo credentials from production-facing pages and disable test accounts outside development environments.
- Add authorization tests for horizontal access control to ensure one tenant cannot access another tenant’s records.