import * as jose from "jose";
import fs from "fs";

{
  const { privateKey } = await jose.generateKeyPair("ES384", {
    extractable: true,
  });
  fs.writeFileSync(
    "./ec-pri-valid-p384.json",
    JSON.stringify(await jose.exportJWK(privateKey), null, 4)
  );
}
{
  const { privateKey } = await jose.generateKeyPair("ES512", {
    extractable: true,
  });
  fs.writeFileSync(
    "./ec-pri-valid-p521.json",
    JSON.stringify(await jose.exportJWK(privateKey), null, 4)
  );
}
