import crypto from "node:crypto";
import cryptoJS from "crypto-js";

class OpenAuth {
  static generateToken() {
    return crypto
      .createHash("sha512")
      .update(Date.now().toString())
      .digest("base64");
  }

  generateClientIdAndSecret(secret: string) {
    const timestamp = Date.now().toString();
    const token = crypto
      .createHmac("sha256", secret)
      .update(timestamp)
      .digest("hex");
    const clientId = token.slice(0, 20);
    let clientSecret = token.slice(20, token.length);
    const encryptedTime = cryptoJS.AES.encrypt(timestamp, secret).toString();
    clientSecret += encryptedTime;

    return {
      clientId: clientId,
      clientSecret: clientSecret,
    };
  }

  verifyClient(clientId: string, clientSecret: string, secret: string) {
    let timestamp = clientSecret.slice(
      clientSecret.length - 44,
      clientSecret.length
    );
    timestamp = cryptoJS.AES.decrypt(timestamp, secret).toString(
      cryptoJS.enc.Utf8
    );
    const token = crypto
      .createHmac("sha256", secret)
      .update(timestamp)
      .digest("hex");

    clientSecret = clientId + clientSecret.slice(0, clientSecret.length - 44);
    if (token === clientSecret) {
      return OpenAuth.generateToken();
    }
    throw new Error("Authentication failed");
  }
}

module.exports = OpenAuth;
