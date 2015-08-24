/// <reference path="typings/es6-promise.d.ts" />
/// <reference path="base64.ts" />
/// <reference path="typings/webcrypto.d.ts" />

class WebCryptoSupplements {
    static ecies_encrypt(deriveAlgo: any, public_key: CryptoKey, data: ArrayBuffer|ArrayBufferView): Promise<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            if (deriveAlgo.name != 'ECDH') {
                reject('invalid deriveAlgo.name');
                return;
            }
            var key_bits = WebCryptoSupplements._recommended_aes_key_bits(deriveAlgo.namedCurve);
            if (!key_bits) {
                reject('invalid deriveAlgo.namedCurve');
                return;
            }
            window.crypto.subtle.generateKey(deriveAlgo, true, ['deriveBits']).then((ephemeral_key) => {
                window.crypto.subtle.exportKey('jwk', ephemeral_key.publicKey).then((ephemeral_pubkey) => {
                    var algo = {
                        name: deriveAlgo.name,
                        namedCurve: deriveAlgo.namedCurve,
                        public: public_key
                    };
                    var key_len = key_bits / 8;
                    var iv_len = 12;
                    var R = WebCryptoSupplements._ecc_point_to_bytes(
                        algo.namedCurve,
                        Base64URL.decode(ephemeral_pubkey.x),
                        Base64URL.decode(ephemeral_pubkey.y));
                    window.crypto.subtle.deriveBits(algo, ephemeral_key.privateKey, (key_len + iv_len) * 8).then((key_and_iv) => {
                        var key_jwt = {
                            alg: 'A' + (key_len * 8) + 'GCM',
                            ext: true,
                            k: Base64URL.encode(new Uint8Array(key_and_iv, 0, key_len)),
                            key_ops: ['encrypt'],
                            kty: 'oct',
                        };
                        var encryptAlgo = {
                            name: 'AES-GCM',
                            length: key_bits,
                            iv: new Uint8Array(key_and_iv, key_len, iv_len)
                        };
                        window.crypto.subtle.importKey('jwk', key_jwt, encryptAlgo, false, ['encrypt']).then((key) => {
                            window.crypto.subtle.encrypt(encryptAlgo, key, data).then((encrypted) => {
                                var output = new ArrayBuffer(R.byteLength + encrypted.byteLength);
                                var view = new Uint8Array(output);
                                view.set(new Uint8Array(R), 0);
                                view.set(new Uint8Array(encrypted), R.byteLength);
                                resolve(output);
                            }, reject);
                        }, reject);
                    }, reject);
                }, reject);
            }, reject);
        });
    }

    static ecies_decrypt(deriveAlgo: any, private_key: CryptoKey, data: ArrayBuffer|ArrayBufferView): Promise<ArrayBuffer> {
        return new Promise((resolve, reject) => {
            if (deriveAlgo.name != 'ECDH') {
                reject('invalid deriveAlgo.name');
                return;
            }
            var key_bits = WebCryptoSupplements._recommended_aes_key_bits(deriveAlgo.namedCurve);
            if (!key_bits) {
                reject('invalid deriveAlgo.namedCurve');
                return;
            }
            var pubkey_and_cipher = WebCryptoSupplements._ecc_bytes_to_point(deriveAlgo.namedCurve, data);
            var cipher = pubkey_and_cipher[2];
            var ephemeral_jwt = {
                crv: deriveAlgo.namedCurve,
                ext: true,
                kty: 'EC',
                x: Base64URL.encode(pubkey_and_cipher[0]),
                y: Base64URL.encode(pubkey_and_cipher[1])
            };
            window.crypto.subtle.importKey('jwk', ephemeral_jwt, deriveAlgo, false, ['deriveBits']).then((public_key) => {
                var algo = {
                    name: deriveAlgo.name,
                    namedCurve: deriveAlgo.namedCurve,
                    public: public_key
                };
                var key_len = key_bits / 8;
                var iv_len = 12;
                window.crypto.subtle.deriveBits(algo, private_key, (key_len + iv_len) * 8).then((key_and_iv) => {
                    var key_jwt = {
                        alg: 'A' + (key_len * 8) + 'GCM',
                        ext: true,
                        k: Base64URL.encode(new Uint8Array(key_and_iv, 0, key_len)),
                        key_ops: ['decrypt'],
                        kty: 'oct',
                    };
                    var encryptAlgo = {
                        name: 'AES-GCM',
                        length: key_bits,
                        iv: new Uint8Array(key_and_iv, key_len, iv_len)
                    };
                    window.crypto.subtle.importKey('jwk', key_jwt, encryptAlgo, false, ['decrypt']).then((key) => {
                        window.crypto.subtle.decrypt(encryptAlgo, key, cipher).then((plaintext) => {
                            resolve(plaintext);
                        }, reject);
                    }, reject);
                }, reject);
            }, reject);
        });
    }

    static _recommended_aes_key_bits(curveName: string) {
        return {
            'P-256': 128,
            'P-384': 192,
            'P-521': 256
        }[curveName];
    }

    static _ecc_point_to_bytes(curveName: string, x: ArrayBuffer, y: ArrayBuffer): ArrayBuffer {
        var len = Math.ceil(parseInt(curveName.slice(2)) / 8);
        var out = new ArrayBuffer(len * 2 + 1);
        var view = new Uint8Array(out);
        view[0] = 4; // 点圧縮は常に利用しない
        view.set(new Uint8Array(x), 1 + (len - x.byteLength));
        view.set(new Uint8Array(y), 1 + len + (len - y.byteLength));
        return out;
    }

    static _ecc_bytes_to_point(curveName: string, data: ArrayBuffer|ArrayBufferView): Array<ArrayBuffer|Uint8Array> {
        var len = Math.ceil(parseInt(curveName.slice(2)) / 8);
        var view = data instanceof ArrayBuffer ? new Uint8Array(<ArrayBuffer>data)
            : new Uint8Array((<ArrayBufferView>data).buffer,
                             (<ArrayBufferView>data).byteOffset,
                             (<ArrayBufferView>data).byteLength);
        var x = new ArrayBuffer(len);
        var y = new ArrayBuffer(len);
        if (view[0] != 4 || view.length < 1 + len * 2)
            throw new Error('invalid data');
        new Uint8Array(x).set(view.subarray(1, 1 + len));
        new Uint8Array(y).set(view.subarray(1 + len, 1 + len * 2));
        return [x, y, view.subarray(1 + len * 2)];
    }
}
