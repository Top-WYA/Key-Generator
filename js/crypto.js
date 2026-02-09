window.wya = {
    sign: async function (jwkJson, dataPayload) {
        try {
            // console.log("WYA Crypto: Starting signing process...");

            // 1. Parse JWK
            const jwk = JSON.parse(jwkJson);

            // 2. Import Key
            // Algorithm: RSASSA-PKCS1-v1_5 with SHA-256
            const privateKey = await window.crypto.subtle.importKey(
                "jwk",
                jwk,
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: { name: "SHA-256" },
                },
                false,
                ["sign"]
            );

            // console.log("WYA Crypto: Key imported successfully.");

            // 3. Decode Data payload (Base64 -> Uint8Array)
            // The payload is passed as a Base64 string from C#
            const binaryString = atob(dataPayload);
            const len = binaryString.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            // 4. Sign Data
            const signature = await window.crypto.subtle.sign(
                "RSASSA-PKCS1-v1_5",
                privateKey,
                bytes
            );

            // console.log("WYA Crypto: Signing complete.");

            // 5. Convert Signature (ArrayBuffer) to Base64
            let binary = '';
            const outputBytes = new Uint8Array(signature);
            const outputLen = outputBytes.byteLength;
            for (let i = 0; i < outputLen; i++) {
                binary += String.fromCharCode(outputBytes[i]);
            }
            return btoa(binary);

        } catch (e) {
            // console.error("WYA Crypto Error:", e);
            throw e.toString();
        }
    },

    decrypt: async function (encryptedBase64, password) {
        try {
            // console.log("WYA Crypto: Starting decryption...");

            const enc = new TextEncoder();
            const fixedSalt = enc.encode("WYA_FIXED_SALT_FOR_KEY_DERIVATION");

            // 1. Import Password
            const keyMaterial = await window.crypto.subtle.importKey(
                "raw",
                enc.encode(password),
                "PBKDF2",
                false,
                ["deriveBits"]
            );

            // 2. Derive Bits (48 bytes: 32 Key + 16 IV)
            // Matches C#: Rfc2898DeriveBytes(password, salt, 10000, SHA256)
            const derivedBits = await window.crypto.subtle.deriveBits(
                {
                    name: "PBKDF2",
                    salt: fixedSalt,
                    iterations: 10000,
                    hash: "SHA-256"
                },
                keyMaterial,
                384 // 48 bytes * 8 bits
            );

            const derivedBytes = new Uint8Array(derivedBits);
            const keyBytes = derivedBytes.slice(0, 32);
            const ivBytes = derivedBytes.slice(32, 48);

            // 3. Import AES Key
            const aesKey = await window.crypto.subtle.importKey(
                "raw",
                keyBytes,
                "AES-CBC",
                false,
                ["decrypt"]
            );

            // 4. Decode Ciphertext (Base64 -> Uint8Array)
            const binaryString = atob(encryptedBase64);
            const len = binaryString.length;
            const ciphertext = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                ciphertext[i] = binaryString.charCodeAt(i);
            }

            // 5. Decrypt
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                {
                    name: "AES-CBC",
                    iv: ivBytes
                },
                aesKey,
                ciphertext
            );

            // 6. Decode Result (Uint8Array -> String)
            const dec = new TextDecoder();
            return dec.decode(decryptedBuffer);

        } catch (e) {
            // console.error("WYA Crypto Decrypt Error:", e);
            throw e.toString();
        }
    }
};
