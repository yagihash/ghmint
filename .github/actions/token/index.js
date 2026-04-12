// mini-gh-sts action: exchange GitHub Actions OIDC token for a GitHub App Installation Access Token.
// No build step required — runs directly on node24 with no external dependencies.

(async function main() {
    const actionsToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    const actionsUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;

    if (!actionsToken || !actionsUrl) {
        console.log("::error::Missing OIDC environment variables. Set 'id-token: write' in your workflow permissions.");
        process.exit(1);
    }

    const hostname = process.env.INPUT_HOSTNAME || 'mini-gh-sts.ssrf.dev';
    const scope = process.env.INPUT_SCOPE;
    const policy = process.env.INPUT_POLICY;

    if (!scope || !policy) {
        console.log("::error::Inputs 'scope' and 'policy' are required.");
        process.exit(1);
    }

    try {
        // Fetch GitHub Actions OIDC token with mini-gh-sts hostname as audience.
        // The STS validates the 'aud' claim against its own hostname.
        const oidcRes = await fetch(`${actionsUrl}&audience=${hostname}`, {
            headers: { 'Authorization': `Bearer ${actionsToken}` },
        });
        if (!oidcRes.ok) {
            const body = await oidcRes.text();
            throw new Error(`Failed to fetch OIDC token: ${oidcRes.status} ${body}`);
        }
        const { value: idToken } = await oidcRes.json();

        // Exchange OIDC token for a GitHub App Installation Access Token.
        const stsRes = await fetch(`https://${hostname}/token`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${idToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ scope, policy }),
        });
        if (!stsRes.ok) {
            const body = await stsRes.text();
            throw new Error(`mini-gh-sts returned ${stsRes.status}: ${body}`);
        }
        const result = await stsRes.json();

        if (!result.token) {
            throw new Error('STS response did not contain a token');
        }

        const token = result.token;

        const crypto = require('crypto');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        console.log(`Token SHA256: ${tokenHash}`);

        // Mask before writing to any output.
        console.log(`::add-mask::${token}`);

        const fs = require('fs');
        fs.appendFileSync(process.env.GITHUB_OUTPUT, `token=${token}\n`);
        // Save to state so the post step can revoke the token.
        fs.appendFileSync(process.env.GITHUB_STATE, `token=${token}\n`);

        console.log('::notice::Successfully obtained GitHub App Installation Access Token.');
    } catch (err) {
        console.log(`::error::${err.stack}`);
        process.exit(1);
    }
})();
