'use strict';

const crypto = require('crypto');
const base64url = require('base64url');
const msgpack = require('msgpackr');

function convertPublicKeyToPEM(publicKey) {
	const base64PublicKey = base64url.toBase64(publicKey);

	return `-----BEGIN PUBLIC KEY-----
${base64PublicKey.replace(/(.{64})/g, '$1')}
-----END PUBLIC KEY-----`;
}
// This function takes a session token buffer and unpacks its values to extract the most significant and least significant bits
function getSessionFromTokenBuffer(sessionTokenBuffer) {
	const unpackedValues = msgpack.unpackMultiple(sessionTokenBuffer);
	const [mostSignificantBits, leastSignificantBits] = unpackedValues;
	return uuidFrom(mostSignificantBits, leastSignificantBits);
}

// This function takes the most significant and least significant bits as input and returns a UUID string
function uuidFrom(mostSig, leastSig) {
	// Convert the most and least significant bits to unsigned 64-bit integers using BigInt.asUintN
	mostSig = BigInt.asUintN(64, mostSig);
	leastSig = BigInt.asUintN(64, leastSig);
	// Call the toHexDigits function with different bitshifts to create the different parts of the UUID
	// Join the different parts of the UUID into a single string with hyphens
	return [
		toHexDigits(mostSig >> 32n, 8),
		toHexDigits(mostSig >> 16n, 4),
		toHexDigits(mostSig, 4),
		toHexDigits(leastSig >> 48n, 4),
		toHexDigits(leastSig, 12),
	].join('-');
}

// This function takes a value and a number of digits as input and returns a hexadecimal string with the specified number of digits
function toHexDigits(val, digits) {
	// Calculate the highest possible value based on the number of digits
	const hi = 1n << BigInt(digits * 4);
	// Convert the value to a hexadecimal string and substring it to get the required number of digits
	// If the value is less than the highest possible value, the first digit will be a zero
	return (hi | (val & (hi - 1n))).toString(16).substring(1);
}



class SessionDecoder {
	constructor(publicKey) {
		if (!publicKey) {
			throw new Error('missing public key in session token decoder constructor');
		}
		this.publicKey = convertPublicKeyToPEM(publicKey);
		this.verifier = crypto.createVerify('RSA-SHA256');
	}

	decode(sessionValue) {
		const [base64EncodedToken, base64EncodedSignature] = sessionValue.split('.');
		if (!base64EncodedToken || !base64EncodedSignature) {
			throw new Error('Invalid session - incorrect format');
		}
		const sessionTokenBuffer = Buffer.from(base64EncodedToken, 'base64');
		const verifier = crypto.createVerify('SHA256');

		verifier.update(sessionTokenBuffer);

		const verified = verifier.verify(this.publicKey, base64EncodedSignature, 'base64');
		if (verified) {
			return getSessionFromTokenBuffer(sessionTokenBuffer);
		} else {
			throw new Error('Invalid session - signature verification failed');

		}

	}
}


module.exports = SessionDecoder;
