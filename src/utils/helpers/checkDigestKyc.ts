import { createHmac } from 'crypto';

export async function checkDigest(req: any, appSecretKey) {
	const algoHeader = req.headers['x-payload-digest-alg'];
	const digestHeader = req.headers['x-payload-digest'];

	if (!algoHeader || !digestHeader) {
		console.log('Missing required headers', algoHeader, digestHeader);
		return false;
	}

	const algorithm = {
		HMAC_SHA1_HEX: 'sha1',
		HMAC_SHA256_HEX: 'sha256',
		HMAC_SHA512_HEX: 'sha512',
	}[algoHeader];

	if (!algorithm) {
		console.log('Unsupported algorithm', algorithm);
		return false;
	}

	console.log('req?.rawBody', req?.rawBody);

	const calculatedDigest = createHmac(algorithm, appSecretKey)
		.update(req?.rawBody)
		.digest('hex');

	console.log('calculatedDigest', calculatedDigest, digestHeader);

	return calculatedDigest === digestHeader;
}
