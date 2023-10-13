import { createClientIdAndSecret, createToken, verifyClientId, verifyClientSecret } from './lib/auth';
import { GenerateClientIdAndSecretResponse } from './lib/types';

class OpenAuth {
  secret: string;

  constructor(secret: string) {
    if (secret.length < 8 || secret.length > 32) {
      throw Error('Length of secret should be between 8 - 32');
    }
    this.secret = secret;
  }
  private static generateToken(secret: string): string {
    return createToken(secret);
  }

  generateClientIdAndSecret(): GenerateClientIdAndSecretResponse {
    return createClientIdAndSecret(this.secret);
  }

  verifyClient(clientId: string, clientSecret: string): string | Error {
    if (typeof clientId !== 'string') throw Error('clientId should be string');

    const timestamp = clientSecret.slice(clientSecret.length - 44, clientSecret.length);
    const token = verifyClientId(timestamp, this.secret);
    const ClientSecretData = verifyClientSecret(clientId, clientSecret);
    if (token === ClientSecretData) {
      return OpenAuth.generateToken(this.secret);
    }
    throw new Error('Authentication failed');
  }

  verifyToken(token: string): boolean | Error {
    if (typeof token !== 'string') throw Error('token should be string');

    const generateToken = createToken(this.secret);
    if (generateToken === token) return true;
    return false;
  }
}

export default OpenAuth;
