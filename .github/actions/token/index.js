import * as core from "@actions/core";
import { HttpClient } from "@actions/http-client";
import { BearerCredentialHandler } from "@actions/http-client/lib/auth";

async function run() {
  const stsUrl = core.getInput("sts_url", { required: true });

  core.info(`Requesting OIDC token for audience: ${stsUrl}`);
  const idToken = await core.getIDToken(stsUrl);

  const client = new HttpClient("mini-gh-sts-action", [
    new BearerCredentialHandler(idToken),
  ]);

  const res = await client.postJson(`${stsUrl}/token`, {});
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
