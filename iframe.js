class _Base64 {
    static encode(chars, pad, data) {
        var view = (data instanceof ArrayBuffer ? new Uint8Array(data) :
            new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
        var out = '';
        var i = 0;
        for (; i < view.length - 2; i += 3) {
            out += chars[view[i] >> 2];
            out += chars[((view[i] & 0x3) << 4) | (view[i + 1] >> 4)];
            out += chars[((view[i + 1] & 0xf) << 2) | (view[i + 2] >> 6)];
            out += chars[view[i + 2] & 0x3f];
        }
        if (view.length % 3) {
            out += chars[view[i] >> 2];
            if ((view.length % 3) == 2) {
                out += chars[((view[i] & 0x3) << 4) | (view[i + 1] >> 4)];
                out += chars[(view[i + 1] & 0xf) << 2];
                if (pad)
                    out += pad;
            }
            else {
                out += chars[(view[i] & 0x3) << 4];
                if (pad)
                    out += pad + pad;
            }
        }
        return out;
    }
    static decode(chars, pad, data) {
        if (pad) {
            var pos = data.indexOf(pad);
            if (pos >= 0)
                data = data.slice(0, pos);
        }
        var buf = new ArrayBuffer((data.length * 3) >> 2);
        var view = new Uint8Array(buf);
        var i = 0, j = 0;
        for (; i < data.length - 3; i += 4, j += 3) {
            var x0 = chars.indexOf(data[i]);
            var x1 = chars.indexOf(data[i + 1]);
            var x2 = chars.indexOf(data[i + 2]);
            var x3 = chars.indexOf(data[i + 3]);
            view[j] = (x0 << 2) | (x1 >> 4);
            view[j + 1] = ((x1 & 0xf) << 4) | (x2 >> 2);
            view[j + 2] = ((x2 & 0x3) << 6) | x3;
        }
        if (data.length % 4) {
            var x0 = chars.indexOf(data[i]);
            var x1 = chars.indexOf(data[i + 1]);
            view[j++] = (x0 << 2) | (x1 >> 4);
            if (i + 2 < data.length) {
                var x2 = chars.indexOf(data[i + 2]);
                view[j++] = ((x1 & 0xf) << 4) | (x2 >> 2);
            }
        }
        return buf;
    }
}
class Base64 {
    static encode(data) {
        return _Base64.encode(Base64.CHARS, '=', data);
    }
    static decode(data) {
        return _Base64.decode(Base64.CHARS, '=', data);
    }
}
Base64.CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
class Base64URL {
    static encode(data) {
        return _Base64.encode(Base64URL.CHARS, null, data);
    }
    static decode(data) {
        return _Base64.decode(Base64URL.CHARS, null, data);
    }
}
Base64URL.CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/*
 * KeyStore
 *
 * IndexedDBの"keystore"オブジェクトストアに署名作成・署名検証・鍵交換に必要な鍵を保持する．
 * 現在は楕円曲線暗号にのみ対応しており，署名・鍵交換には同じ鍵を利用する．
 * KeyStoreに保管される鍵情報はすべて同じアルゴリズム・同じ鍵長．
 *
 * オブジェクトストアに格納される情報(秘密鍵有り)
 * {
 *   id: "<鍵を識別するユニークなID>",
 *   private: 秘密鍵(d),
 *   public: 公開鍵(x,y)
 * }
 *
 * KeyStoreから返却される鍵情報(秘密鍵有り)
 * {
 *   id: "<鍵を識別するユニークなID>",
 *   is_private: true,
 *   sign_key: 署名作成に利用する秘密鍵(CryptoKey),
 *   verify_key: 署名検証に利用する公開鍵(CryptoKey),
 *   derive_key: 鍵交換に利用する秘密鍵(CryptoKey),
 *   private_key: 秘密鍵(JSON),
 *   public_key: 公開鍵(JSON),
 * }
 *
 * オブジェクトストアに格納される情報(公開鍵のみ)
 * {
 *   id: "<鍵を識別するユニークなID>",
 *   public: 署名検証に利用する公開鍵(x,y),
 * }
 *
 * KeyStoreから返却される鍵情報(公開鍵のみ)
 * {
 *   id: "<鍵を識別するユニークなID>",
 *   is_private: false,
 *   verify_key: 署名検証に利用する公開鍵(CryptoKey),
 *   derive_key: 鍵交換に利用する公開鍵(CryptoKey),
 *   public_key: 公開鍵(JSON),
 *   private_key: undefined,
 *   sign_key: undefined,
 * }
 */
class KeyStore {
    constructor(namedCurve = 'P-256') {
        this.db = null;
        this.store_name = 'keystore';
        this.signAlgo = null;
        this.deriveAlgo = null;
        var hashAlgo = {
            'P-256': 'SHA-256',
            'P-384': 'SHA-384',
            'P-521': 'SHA-512',
        }[namedCurve];
        if (!hashAlgo)
            throw new Error('invalid curve name \"' + namedCurve + '\"');
        this.signAlgo = {
            name: 'ECDSA',
            hash: 'SHA-256',
            namedCurve: namedCurve
        };
        this.deriveAlgo = {
            name: 'ECDH',
            namedCurve: namedCurve
        };
    }
    open(db_name, store_name) {
        if (store_name)
            this.store_name = store_name;
        var req = window.indexedDB.open(db_name, 1);
        req.onupgradeneeded = () => {
            var db = req.result;
            db.createObjectStore(this.store_name, {
                keyPath: 'id',
                autoIncrement: false
            });
        };
        return new Promise((resolve, reject) => {
            req.onsuccess = () => {
                this.db = req.result;
                resolve(this);
            };
            req.onerror = (ev) => {
                reject(ev);
            };
        });
    }
    // 秘密鍵を作成し指定したidをキーとして保存する
    generate(id) {
        // WebCryptographyAPIが残念な出来なので，アルゴリズム的には可能なのだが
        // sign/verify/deriveKey全てに対応する鍵を作成できない．
        // そこでECDSA(sign/verify)の鍵を生成後，一度秘密鍵をエクスポートして
        // ECDH(deriveKey)用の鍵を生成する．
        // また，IndexedDBのObjectStoreにはexportableではないCryptoKeyを保管できないので
        // IndexedDBを使う限りは結局のところ秘密鍵に対してexportable属性を付与しなければならない
        // (Firefox 43.0a1, 2015-08-21)
        return new Promise((resolve, reject) => {
            window.crypto.subtle.generateKey(this.signAlgo, true, ['sign', 'verify']).then((ecdsa_key) => {
                window.crypto.subtle.exportKey('jwk', ecdsa_key.privateKey).then((ecdsa_priv) => {
                    var value = {
                        'id': id,
                        'private': ecdsa_priv.d,
                        'public': {
                            'x': ecdsa_priv.x,
                            'y': ecdsa_priv.y
                        }
                    };
                    var transaction = this.db.transaction([this.store_name], 'readwrite');
                    var store = transaction.objectStore(this.store_name);
                    var req = store.add(value);
                    req.onsuccess = () => {
                        this._to_cryptokey(value).then(resolve, reject);
                    };
                    req.onerror = reject;
                }, reject);
            }, reject);
        });
    }
    find(id) {
        var transaction = this.db.transaction([this.store_name]);
        var store = transaction.objectStore(this.store_name);
        var req = store.get(id);
        return new Promise((resolve, reject) => {
            req.onsuccess = () => {
                if (req.result) {
                    this._to_cryptokey(req.result).then(resolve, reject);
                }
                else {
                    reject(undefined);
                }
            };
            req.onerror = reject;
        });
    }
    delete(id) {
        var transaction = this.db.transaction([this.store_name], 'readwrite');
        var store = transaction.objectStore(this.store_name);
        var req = store.delete(id);
        return new Promise((resolve, reject) => {
            req.onsuccess = () => {
                resolve();
            };
            req.onerror = (ev) => {
                reject(ev);
            };
        });
    }
    ;
    clear() {
        var transaction = this.db.transaction([this.store_name], 'readwrite');
        var store = transaction.objectStore(this.store_name);
        var req = store.clear();
        return new Promise((resolve, reject) => {
            req.onsuccess = () => {
                resolve();
            };
            req.onerror = (ev) => {
                reject(ev);
            };
        });
    }
    ;
    import(id, publicKey) {
        var pub = {
            crv: this.signAlgo.namedCurve,
            ext: true,
            kty: 'EC',
            x: publicKey.x,
            y: publicKey.y
        };
        return new Promise((resolve, reject) => {
            window.crypto.subtle.importKey('jwk', pub, this.signAlgo, false, ['verify']).then((key) => {
                var value = {
                    'id': id,
                    'public': {
                        'x': pub.x,
                        'y': pub.y
                    }
                };
                if (id === null) {
                    this._to_cryptokey(value).then(resolve, reject);
                    return;
                }
                var transaction = this.db.transaction([this.store_name], 'readwrite');
                var store = transaction.objectStore(this.store_name);
                var req = store.add(value);
                req.onsuccess = () => {
                    this._to_cryptokey(value).then(resolve, reject);
                };
                req.onerror = reject;
            }, reject);
        });
    }
    list() {
        var transaction = this.db.transaction([this.store_name]);
        var store = transaction.objectStore(this.store_name);
        var req = store.openCursor();
        var ret = [];
        return new Promise((resolve, reject) => {
            req.onsuccess = () => {
                var cursor = req.result;
                if (cursor) {
                    ret.push(this._to_cryptokey(cursor.value));
                    cursor.continue();
                }
                else {
                    Promise.all(ret).then(resolve, reject);
                }
            };
            req.onerror = reject;
        });
    }
    // ObjectStoreに格納している最低限の情報からCryptoKeyを復元する
    _to_cryptokey(stored_data) {
        var x = stored_data.public.x;
        var y = stored_data.public.y;
        var d = stored_data.private;
        return new Promise((resolve, reject) => {
            var pub = {
                crv: this.signAlgo.namedCurve,
                ext: true,
                kty: 'EC',
                x: x,
                y: y
            };
            var ret = [];
            ret.push(window.crypto.subtle.importKey('jwk', pub, this.signAlgo, false, ['verify']));
            ret.push(window.crypto.subtle.importKey('jwk', pub, this.deriveAlgo, false, []));
            if (d) {
                var priv = {
                    crv: this.signAlgo.namedCurve,
                    ext: true,
                    kty: 'EC',
                    x: x,
                    y: y,
                    d: d,
                };
                ret.push(window.crypto.subtle.importKey('jwk', priv, this.signAlgo, false, ['sign']));
                ret.push(window.crypto.subtle.importKey('jwk', priv, this.deriveAlgo, false, ['deriveKey', 'deriveBits']));
            }
            Promise.all(ret).then((values) => {
                var ki = ret.length == 2 ?
                    new PublicKeyInfo(stored_data.id, values[0], values[1], { x: x, y: y }) :
                    new PrivateKeyInfo(stored_data.id, values[2], values[0], values[3], { x: x, y: y, d: d }, { x: x, y: y });
                resolve(ki);
            }, reject);
        });
    }
}
class KeyInfo {
    constructor(id, is_private) {
        this.id = id;
        this.is_private = is_private;
    }
}
class PublicKeyInfo extends KeyInfo {
    constructor(id, verify_key, derive_key, public_key) {
        super(id, false);
        this.verify_key = verify_key;
        this.derive_key = derive_key;
        this.public_key = public_key;
        this.sign_key = undefined;
        this.private_key = undefined;
    }
}
class PrivateKeyInfo extends KeyInfo {
    constructor(id, sign_key, verify_key, derive_key, private_key, public_key) {
        super(id, true);
        this.sign_key = sign_key;
        this.verify_key = verify_key;
        this.derive_key = derive_key;
        this.public_key = public_key;
        this.private_key = private_key;
    }
}
/// <reference path="base64.ts" />
class WebCryptoSupplements {
    static ecies_encrypt(deriveAlgo, public_key, data) {
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
                    var R = WebCryptoSupplements._ecc_point_to_bytes(algo.namedCurve, Base64URL.decode(ephemeral_pubkey.x), Base64URL.decode(ephemeral_pubkey.y));
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
    static ecies_decrypt(deriveAlgo, private_key, data) {
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
            window.crypto.subtle.importKey('jwk', ephemeral_jwt, deriveAlgo, false, []).then((public_key) => {
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
    static _recommended_aes_key_bits(curveName) {
        return {
            'P-256': 128,
            'P-384': 192,
            'P-521': 256
        }[curveName];
    }
    static _ecc_point_to_bytes(curveName, x, y) {
        var len = Math.ceil(parseInt(curveName.slice(2)) / 8);
        var out = new ArrayBuffer(len * 2 + 1);
        var view = new Uint8Array(out);
        view[0] = 4; // 点圧縮は常に利用しない
        view.set(new Uint8Array(x), 1 + (len - x.byteLength));
        view.set(new Uint8Array(y), 1 + len + (len - y.byteLength));
        return out;
    }
    static _ecc_bytes_to_point(curveName, data) {
        var len = Math.ceil(parseInt(curveName.slice(2)) / 8);
        var view = data instanceof ArrayBuffer ? new Uint8Array(data)
            : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        var x = new ArrayBuffer(len);
        var y = new ArrayBuffer(len);
        if (view[0] != 4 || view.length < 1 + len * 2)
            throw new Error('invalid data');
        new Uint8Array(x).set(view.subarray(1, 1 + len));
        new Uint8Array(y).set(view.subarray(1 + len, 1 + len * 2));
        return [x, y, view.subarray(1 + len * 2)];
    }
}
/// <reference path="base64.ts" />
/// <reference path="keystore.ts" />
/// <reference path="webcrypto_supplements.ts" />
class State {
    constructor() {
        this.key = null;
        this.pubKey = null;
        document.addEventListener('DOMContentLoaded', () => {
            this.contents = document.getElementById('contents');
        });
        this.store = new KeyStore();
        this.store.open('default').then(() => {
            this.store.find('default').then((key) => {
                this.key = key;
                this._init();
            }, () => {
                this.store.generate('default').then((key) => {
                    this.key = key;
                    this._init();
                }, (e) => {
                    console.error('failed: keypair generation', e);
                });
            });
        }, (e) => {
            console.error('failed: init IndexedDB', e);
        });
    }
    _init() {
        this.store.import(null, this.key.public_key).then((key) => {
            this.pubKey = key;
        });
        window.addEventListener('message', (e) => {
            var m = e.data.method;
            var id = e.data.id;
            var post = (msg) => {
                if (e.origin && e.origin !== 'null') {
                    e.source.postMessage(msg, e.origin);
                }
                else {
                    e.source.postMessage(msg);
                }
            };
            if (m === 'get_public_key') {
                post({ 'id': id, 'data': this.key.public_key });
            }
            else if (m === 'encrypt') {
                // テキストのみ。バイナリ対応させるときはArrayBuffer/Base64で転送とかする
                var buf = new Uint16Array([].map.call(e.data.data, (c) => c.charCodeAt(0))).buffer;
                WebCryptoSupplements.ecies_encrypt(this.store.deriveAlgo, this.pubKey.derive_key, buf).then((encrypted) => {
                    post({ 'id': id, 'result': 'ok', 'data': Base64URL.encode(encrypted) });
                }, (err) => {
                    console.error(err);
                    post({ 'id': id, 'error': 'error' });
                });
            }
            else if (m === 'decrypt') {
                WebCryptoSupplements.ecies_decrypt(this.store.deriveAlgo, this.key.derive_key, Base64URL.decode(e.data.data)).then((plain) => {
                    this.contents.innerText = String.fromCharCode.apply("", new Uint16Array(plain));
                    post({ 'id': id, 'result': 'ok' });
                }, (err) => {
                    console.error(err);
                    post({ 'id': id, 'result': 'error' });
                });
            }
        });
    }
}
new State();
