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
	private static generateToken(secret: string): string {
		return createToken(secret);
	}

	@CheckParameterTypes(["string"])
	generateClientIdAndSecret(secret: string): IClientIdAndSecret {
		return createClientIdAndSecret(secret);
	}

	@CheckParameterTypes(["string", "string", "string"])
	verifyClient(
		clientId: string,
		clientSecret: string,
		secret: string
	): string | Error {
		const timestamp = clientSecret.slice(
			clientSecret.length - 44,
			clientSecret.length
		);
		const token = verifyClientId(timestamp, secret);
		const ClientSecretData = verifyClientSecret(clientId, clientSecret);
		if (token === ClientSecretData) {
			return OpenAuth.generateToken(secret);
		}
		throw new Error("Authentication failed");
	}

	@CheckParameterTypes(["string", "string"])
	verifyToken(token: string, secret: string): boolean {
		const generateToken = createToken(secret);
		if (generateToken === token) return true;
		return false;
	}
}

export default OpenAuth;
