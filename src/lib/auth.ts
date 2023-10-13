import crypto from 'node:crypto';
import cryptoJS from 'crypto-js';
import { GenerateClientIdAndSecretResponse } from './types';

export const createToken = (secret: string): string => {
  return crypto.createHash('sha512').update(secret).digest('base64');
};

export const createClientIdAndSecret = (secret: string): GenerateClientIdAndSecretResponse => {
  const timestamp = Date.now().toString();
  const token = crypto.createHmac('sha256', secret).update(timestamp).digest('hex');
  const clientId = token.slice(0, 20);
  let clientSecret = token.slice(20, token.length);
  const encryptedTime = cryptoJS.AES.encrypt(timestamp, secret).toString();
  clientSecret += encryptedTime;

  return { clientId, clientSecret };
};

export const verifyClientId = (timestamp: string, secret: string): string => {
  timestamp = cryptoJS.AES.decrypt(timestamp, secret).toString(cryptoJS.enc.Utf8);
  const token = crypto.createHmac('sha256', secret).update(timestamp).digest('hex');

  return token;
};

export const verifyClientSecret = (clientId: string, clientSecret: string): string => {
  return clientId + clientSecret.slice(0, clientSecret.length - 44);
};
