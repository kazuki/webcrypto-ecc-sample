/// <reference path="typings/es6-promise.d.ts" />
/// <reference path="typings/webcrypto.d.ts" />

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
    db = null;
    store_name = 'keystore';
    signAlgo = null;
    deriveAlgo = null;

    constructor(namedCurve = 'P-256') {
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

    open(db_name: string, store_name?: string): Promise<KeyStore> {
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
    generate(id: string): Promise<KeyInfo> {
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
                        this._to_cryptokey(value).then((key) => {
                            resolve(key);
                        }).catch((ev) => {
                            reject(ev);
                        });
                    };
                    req.onerror = (ev) => {
                        reject(ev);
                    };
                }).catch((ev) => {
                    reject(ev);
                });
            }).catch((ev) => {
                reject(ev);
            });
        });
    }

    find(id: string): Promise<KeyInfo> {
        var transaction = this.db.transaction([this.store_name]);
        var store = transaction.objectStore(this.store_name);
        var req = store.get(id);
        return new Promise((resolve, reject) => {
            req.onsuccess = () => {
                if (req.result) {
                    this._to_cryptokey(req.result).then((key) => {
                        resolve(key);
                    }).catch((ev) => {
                        reject(ev);
                    });
                } else {
                    reject(undefined);
                }
            };
            req.onerror = (ev) => {
                reject(ev);
            };
        });
    }

    delete(id: string): Promise<any> {
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
    };

    clear(): Promise<any> {
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
    };

    import(id: string, publicKey): Promise<KeyInfo> {
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
                var transaction = this.db.transaction([this.store_name], 'readwrite');
                var store = transaction.objectStore(this.store_name);
                var req = store.add(value);
                req.onsuccess = () => {
                    this._to_cryptokey(value).then((key) => {
                        resolve(key);
                    }).catch((ev) => {
                        reject(ev);
                    });
                };
                req.onerror = (ev) => {
                    reject(ev);
                };
            }).catch((ev) => {
                reject(ev);
            });
        });
    }

    list(): Promise<Array<KeyInfo>> {
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
                } else {
                    Promise.all(ret).then((values) => {
                        resolve(values);
                    }).catch((ev) => {
                        reject(ev);
                    });
                }
            };
            req.onerror = (ev) => {
                reject(ev);
            };
        });
    }

    // ObjectStoreに格納している最低限の情報からCryptoKeyを復元する
    _to_cryptokey(stored_data): Promise<KeyInfo> {
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
                    new PublicKeyInfo(stored_data.id, values[0], values[1], {x: x, y: y}) :
                    new PrivateKeyInfo(stored_data.id, values[2], values[0], values[3], {x: x, y: y, d: d}, {x: x, y: y});
                resolve(ki);
            }).catch((ev) => {
                reject(ev);
            });
        });
    }
}

class KeyInfo {
    id: string;
    is_private: boolean;
    sign_key: CryptoKey;
    verify_key: CryptoKey;
    derive_key: CryptoKey;
    private_key: any;
    public_key: any;

    constructor(id: string, is_private: boolean) {
        this.id = id;
        this.is_private = is_private;
    }
}
class PublicKeyInfo extends KeyInfo {
    constructor(id: string, verify_key: CryptoKey, derive_key: CryptoKey, public_key: any) {
        super(id, false);
        this.verify_key = verify_key;
        this.derive_key = derive_key;
        this.public_key = public_key;
        this.sign_key = undefined;
        this.private_key = undefined;
    }
}
class PrivateKeyInfo extends KeyInfo {
    constructor(id: string, sign_key: CryptoKey, verify_key: CryptoKey, derive_key: CryptoKey, private_key: any, public_key: any) {
        super(id, true);
        this.sign_key = sign_key;
        this.verify_key = verify_key;
        this.derive_key = derive_key;
        this.public_key = public_key;
        this.private_key = private_key;
    }
}
