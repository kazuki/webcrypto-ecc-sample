interface SubtleCrypto {
    // jwk
    importKey(format: string, keyData: any, algorithm: Algorithm, extractable: boolean, keyUsages: string[]): any;

    // ArrayBuffer
    encrypt(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer|ArrayBufferView): any;
    decrypt(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer|ArrayBufferView): any;
    sign(algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer): any;
    verify(algorithm: Algorithm, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): any;
}
