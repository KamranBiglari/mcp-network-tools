import * as forge from 'node-forge';

export function generateSelfSignedCertificate(
    commonName: string,
    organization: string = "My Organization",
    validityDays: number = 365,
    country: string = "US"
): { certificate: string; privateKey: string; publicKey: string } {
    try {
        // Generate a key pair
        const keys = forge.pki.rsa.generateKeyPair(2048);

        // Create a certificate
        const cert = forge.pki.createCertificate();
        cert.publicKey = keys.publicKey;

        // Set certificate fields
        cert.serialNumber = '01' + Math.floor(Math.random() * 1000000).toString();
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + validityDays);

        // Set subject and issuer (same for self-signed)
        const attrs = [
            { name: 'commonName', value: commonName },
            { name: 'organizationName', value: organization },
            { name: 'countryName', value: country }
        ];
        cert.setSubject(attrs);
        cert.setIssuer(attrs);

        // Set extensions
        cert.setExtensions([
            {
                name: 'basicConstraints',
                cA: false
            },
            {
                name: 'keyUsage',
                keyCertSign: false,
                digitalSignature: true,
                nonRepudiation: true,
                keyEncipherment: true,
                dataEncipherment: true
            },
            {
                name: 'extKeyUsage',
                serverAuth: true,
                clientAuth: true,
                codeSigning: false,
                emailProtection: false,
                timeStamping: false
            },
            {
                name: 'subjectAltName',
                altNames: [
                    {
                        type: 2, // DNS name
                        value: commonName
                    }
                ]
            }
        ]);

        // Self-sign certificate
        cert.sign(keys.privateKey, forge.md.sha256.create());

        // Convert to PEM format
        const certificatePem = forge.pki.certificateToPem(cert);
        const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
        const publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);

        return {
            certificate: certificatePem,
            privateKey: privateKeyPem,
            publicKey: publicKeyPem
        };

    } catch (error) {
        throw new Error(`Failed to generate certificate: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}
