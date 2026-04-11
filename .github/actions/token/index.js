import * as core from "@actions/core";
import { HttpClient } from "@actions/http-client";
import { BearerCredentialHandler } from "@actions/http-client/lib/auth";

async function run() {
  const hostname = core.getInput("hostname", { required: true });
  const scope = core.getInput("scope") || process.env.GITHUB_REPOSITORY_OWNER || "";
  const policy = core.getInput("policy") || "";

  core.info(`Requesting OIDC token for audience: ${hostname}`);
  const idToken = await core.getIDToken(hostname);

  const client = new HttpClient("mini-gh-sts-action", [
    new BearerCredentialHandler(idToken),
  ]);

  const res = await client.postJson(`https://${hostname}/token`, { scope, policy });
  if (res.statusCode !== 200) {
    throw new Error(
      `STS returned ${res.statusCode}: ${JSON.stringify(res.result)}`
    );
  }

  const token = res.result?.token;
  if (!token) {
    throw new Error("STS response did not contain a token");
  }

  core.setSecret(token);
  core.setOutput("token", token);
  core.info("Successfully obtained GitHub App token");
}

run().catch((err) => {
  core.setFailed(err.message);
});
