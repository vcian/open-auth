import {
	createClientIdAndSecret,
	createToken,
	verifyClientId,
	verifyClientSecret,
} from "./lib/auth";
import { IClientIdAndSecret } from "./lib/types";

function CheckParameterTypes(expectedParamTypes: string[]) {
	return function (
		target: object,
		methodName: string,
		descriptor: PropertyDescriptor
	) {
		const originalMethod = descriptor.value;

		descriptor.value = function (...args: unknown[]) {
			for (let i = 0; i < expectedParamTypes.length; i++) {
				const expectedType = expectedParamTypes[i];
				const actualType = typeof args[i];

				if (expectedType !== actualType) {
					throw new Error(
						`Parameter type mismatch for parameter ${++i} in ${methodName}. Expected ${expectedType}, but got ${actualType}.`
					);
				}
			}

			return originalMethod.apply(this, args);
		};
	};
}

class OpenAuth {
	secret: string;

	constructor(secret: string) {
		if (secret.length < 8 || secret.length > 30)
			throw Error("Length of secret should be between 8 - 30");
		this.secret = secret;
	}
	private static generateToken(secret: string): string {
		return createToken(secret);
	}

	generateClientIdAndSecret(): IClientIdAndSecret {
		return createClientIdAndSecret(this.secret);
	}

	verifyClient(clientId: string, clientSecret: string): string | Error {
		if (typeof clientId !== "string") throw Error("clientId should be string");

		const timestamp = clientSecret.slice(
			clientSecret.length - 44,
			clientSecret.length
		);
		const token = verifyClientId(timestamp, this.secret);
		const ClientSecretData = verifyClientSecret(clientId, clientSecret);
		if (token === ClientSecretData) {
			return OpenAuth.generateToken(this.secret);
		}
		throw new Error("Authentication failed");
	}

	verifyToken(token: string): boolean | Error {
		if (typeof token !== "string") throw Error("token should be string");

		const generateToken = createToken(this.secret);
		if (generateToken === token) return true;
		return false;
	}
}

export default OpenAuth;
