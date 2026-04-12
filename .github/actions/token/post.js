// mini-gh-sts action post step: revoke the GitHub App Installation Access Token.

const token = process.env.STATE_token;

if (!token) {
    console.log('::warning::Token not found in state; nothing to revoke.');
    process.exit(0);
}

(async function main() {
    try {
        const res = await fetch('https://api.github.com/installation/token', {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2026-03-10',
            },
        });

        if (res.status === 204) {
            console.log('Token was revoked.');
        } else {
            console.log(`::error::Failed to revoke token: ${res.status} ${res.statusText}`);
        }
    } catch (err) {
        console.log(`::error::${err.stack}`);
    }
})();
