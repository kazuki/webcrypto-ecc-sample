/// <reference path="typings/es6-promise.d.ts" />

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
 * }
 */
class KeyStore {
    db = null;
    signAlgo = null;
    deriveAlgo = null;

    constructor() {
        var namedCurve = 'P-256';
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

    open(db_name: string) {
        var req = window.indexedDB.open(db_name, 1);
        req.onupgradeneeded = () => {
            var db = req.result;
            db.createObjectStore('keystore', {
                keyPath: 'id',
                autoIncrement: false
            });
        };
        return new Promise((resolve, reject) => {
            req.onsuccess = () => {
                this.db = req.result;
                resolve(this.db);
            };
            req.onerror = (ev) => {
                reject(ev);
            };
        });
    }

    // 秘密鍵を作成し指定したidをキーとして保存する
    generate(id: string): Promise<any> {
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
                    var transaction = this.db.transaction(['keystore'], 'readwrite');
                    var store = transaction.objectStore('keystore');
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

    find(id: string): Promise<any> {
        var transaction = this.db.transaction(['keystore']);
        var store = transaction.objectStore('keystore');
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
        var transaction = this.db.transaction(['keystore'], 'readwrite');
        var store = transaction.objectStore('keystore');
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

    import(id: string, publicKey): Promise<any> {
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
                var transaction = this.db.transaction(['keystore'], 'readwrite');
                var store = transaction.objectStore('keystore');
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

    list(): Promise<Array<any>> {
        var transaction = this.db.transaction(['keystore']);
        var store = transaction.objectStore('keystore');
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
            ret.push(window.crypto.subtle.importKey('jwk', pub, this.deriveAlgo, false, ['deriveKey']));
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
                ret.push(window.crypto.subtle.importKey('jwk', priv, this.deriveAlgo, false, ['deriveKey']));
            }
            Promise.all(ret).then((values) => {
                var ki = {
                    id: stored_data.id,
                    is_private: false,
                    verify_key: values[0],
                    derive_key: values[1],
                    public_key: {x: x, y: y},
                    sign_key: undefined,
                    private_key: undefined,
                };
                if (ret.length == 4) {
                    ki.is_private = true;
                    ki.sign_key = values[2];
                    ki.derive_key = values[3];
                    ki.private_key = {
                        d: d,
                        x: x,
                        y: y
                    };
                }
                resolve(ki);
            }).catch((ev) => {
                reject(ev);
            });
        });
    }
}

function buf_to_base64(buf: ArrayBuffer): string {
    return base64js.fromByteArray(new Uint8Array(buf));
}
function base64_to_buf(str: string): ArrayBuffer {
    return base64js.toByteArray(str).buffer;
}
function buf_to_base64url(buf: ArrayBuffer): string {
    return base64js.fromByteArray(new Uint8Array(buf))
        .replace(/\+/g, '-').replace('/\//g', '_').replace('/=/g', '');
}
function base64url_to_buf(str: string): ArrayBuffer {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4 != 0)
        str += '=';
    return base64js.toByteArray(str).buffer;
}
function join_buf(bufs: Array<any>): ArrayBuffer {
    var total_bytes = 0;
    for (var i = 0; i < bufs.length; ++i) {
        if (!bufs[i].byteLength)
            bufs[i] = bufs[i].buffer;
        total_bytes += bufs[i].byteLength;
    }
    var buf = new ArrayBuffer(total_bytes);
    var view = new Uint8Array(buf);
    var off = 0;
    for (var i = 0; i < bufs.length; ++i) {
        var tmp = new Uint8Array(bufs[i]);
        view.set(tmp, off);
        off += tmp.length;
    }
    return buf;
}

function webcrypto_suppl_ecies_encrypt(deriveAlgo, encryptAlgo, public_key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // ECIESっぽいもので暗号化(仕様書見てないので厳密には準拠していない)
    return new Promise((resolve, reject) => {
        window.crypto.subtle.generateKey(deriveAlgo, true, ['deriveKey']).then((ephemeral_key) => {
            window.crypto.subtle.exportKey('jwk', ephemeral_key.publicKey).then((ephemeral_pubkey) => {
                var algo = {
                    name: deriveAlgo.name,
                    namedCurve: deriveAlgo.namedCurve,
                    public: public_key
                };
                var x_buf = base64url_to_buf(ephemeral_pubkey.x);
                var y_buf = base64url_to_buf(ephemeral_pubkey.y);
                window.crypto.subtle.deriveKey(algo, ephemeral_key.privateKey, encryptAlgo, false, ['encrypt']).then((key) => {
                    var iv = window.crypto.getRandomValues(new Uint8Array(12));
                    encryptAlgo.iv = iv;
                    window.crypto.subtle.encrypt(encryptAlgo, key, data).then((encrypted) => {
                        var header = new Uint8Array(3);
                        header[0] = x_buf.byteLength;
                        header[1] = y_buf.byteLength;
                        header[2] = iv.byteLength;
                        var buf = join_buf([header, x_buf, y_buf, iv, encrypted]);
                        resolve(buf);
                    }, (ev) => {
                        reject(ev);
                    });
                }, (ev) => {
                    reject(ev);
                });
            }, (ev) => {
                reject(ev);
            });
        }, (ev) => {
            reject(ev);
        });
    });
}

function webcrypto_suppl_ecies_decrypt(deriveAlgo, encryptAlgo, private_key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    // ECIESっぽいもので復号(仕様書見てないので厳密には準拠していない)
    var data8 = new Uint8Array(data);
    var x_len = data8[0];
    var y_len = data8[1];
    var iv_len = data8[2];
    var iv = new Uint8Array(data8.subarray(3 + x_len + y_len, 3 + x_len + y_len + iv_len)).buffer;
    var ephemeral_jwt = {
        crv: deriveAlgo.namedCurve,
        ext: true,
        kty: 'EC',
        x: buf_to_base64url(new Uint8Array(data8.subarray(3, 3 + x_len)).buffer),
        y: buf_to_base64url(new Uint8Array(data8.subarray(3 + x_len, 3 + x_len + y_len)).buffer)
    };
    data8 = data8.subarray(3 + x_len + y_len + iv_len);
    return new Promise((resolve, reject) => {
        window.crypto.subtle.importKey('jwk', ephemeral_jwt, deriveAlgo, false, ['deriveKey']).then((public_key) => {
            var algo = {
                name: deriveAlgo.name,
                namedCurve: deriveAlgo.namedCurve,
                public: public_key
            };
            window.crypto.subtle.deriveKey(algo, private_key, encryptAlgo, false, ['decrypt']).then((key) => {
                encryptAlgo.iv = iv;
                window.crypto.subtle.decrypt(encryptAlgo, key, data8).then((decrypted) => {
                    resolve(decrypted);
                }, (ev) => {
                    reject(ev);
                });
            }, (ev) => {
                reject(ev);
            });
        }, (ev) => {
            reject(ev);
        });
    });
}

function main() {
    var keyStore = new KeyStore();
    var priv_list = document.getElementById('private_keys');
    var pub_list = document.getElementById('public_keys');

    var change_button_enables = (enabled) => {
        var buttons = document.querySelectorAll('button');
        for (var i = 0; i < buttons.length; ++i) {
            if (enabled) {
                buttons[i].removeAttribute('disabled');
            } else {
                buttons[i].setAttribute('disabled', 'disabled');
            }
        };
    };
    var refresh_key_list = () => {
        keyStore.list().then((keys) => {
            while (priv_list.firstChild) priv_list.removeChild(priv_list.firstChild);
            while (pub_list.firstChild) pub_list.removeChild(pub_list.firstChild);
            keys.forEach((key) => {
                var list = pub_list;
                if (key.is_private)
                    list = priv_list;
                var opt = document.createElement('option');
                opt.text = key.id;
                list.appendChild(opt);
            });
        });
    };
    var get_active_key_id = (list) => {
        if (list.selectedIndex < 0)
            return null;
        return list.options[list.selectedIndex].text;
    };
    var get_active_private_key_id = () => {
        return get_active_key_id(priv_list);
    };
    var get_active_public_key_id = () => {
        return get_active_key_id(pub_list);
    };
    var delete_key = (key_id) => {
        keyStore.delete(key_id).then(() => {
            refresh_key_list();
        }, (ev) => {
            alert(ev);
        });
    };
    var export_key = (key_id, is_private) => {
        keyStore.find(key_id).then((key) => {
            if (is_private && key.is_private) {
                prompt('private-key', JSON.stringify(key.private_key));
            } else if (!is_private) {
                prompt('public-key', JSON.stringify(key.public_key));
            }
        }, (ev) => {
            alert(ev);
        });
    };
    var str_to_buf = (str: string): ArrayBuffer => {
        // utf16
        var buf = new ArrayBuffer(str.length * 2);
        var view = new Uint16Array(buf);
        for (var i = 0; i < str.length; ++i) {
            view[i] = str.charCodeAt(i);
        }
        return buf;
    };
    var buf_to_str = (buf: ArrayBuffer): string => {
        var out = '';
        var view = new Uint16Array(buf);
        for (var i = 0; i < view.length; ++i)
            out += String.fromCharCode(view[i]);
        return out;
    };
    document.getElementById('private_key_generate').addEventListener('click', () => {
        var name = prompt('input unique key name');
        if (name) {
            keyStore.generate(name).then(() => {
                alert('success!');
                refresh_key_list();
            }, (ev) => {
                alert(ev);
            });
        }
    });
    document.getElementById('private_key_delete').addEventListener('click', () => {
        var key_id = get_active_private_key_id();
        if (key_id && confirm('"' + key_id + '": delete ok?')) {
            delete_key(key_id);
        }
    });
    document.getElementById('private_key_export_public').addEventListener('click', () => {
        var key_id = get_active_private_key_id();
        if (key_id)
            export_key(key_id, false);
    });
    document.getElementById('private_key_export_private').addEventListener('click', () => {
        var key_id = get_active_private_key_id();
        if (key_id)
            export_key(key_id, true);
    });
    document.getElementById('public_key_delete').addEventListener('click', () => {
        var key_id = get_active_public_key_id();
        if (key_id && confirm('"' + key_id + '": delete ok?')) {
            delete_key(key_id);
        }
    });
    document.getElementById('public_key_export').addEventListener('click', () => {
        var key_id = get_active_public_key_id();
        if (key_id)
            export_key(key_id, false);
    });
    document.getElementById('public_key_import').addEventListener('click', () => {
        var name = prompt('input unique key name');
        if (!name) return;
        var pub = prompt('input public key');
        try {
            pub = JSON.parse(pub);
            keyStore.import(name, pub).then(() => {
                alert('success!');
                refresh_key_list();
            }, (ev) => {
                alert(ev);
            });
        } catch (ex) {
            alert(ex);
        }
    });
    document.getElementById('sign_msg').addEventListener('click', () => {
        var key = get_active_private_key_id();
        if (!key) return;
        var data = str_to_buf(document.getElementById('msg').value);
        keyStore.find(key).then((key) => {
            window.crypto.subtle.sign(keyStore.signAlgo, key.sign_key, data).then((sign) => {
                document.getElementById('sign').value = buf_to_base64(sign);
            }, (ev) => {
                alert('sign failed: ' + ev);
            });
        }, (ev) => {
            alert(ev);
        });
    });
    document.getElementById('verify_msg').addEventListener('click', () => {
        var key = get_active_public_key_id();
        if (!key) return;
        var data = str_to_buf(document.getElementById('msg').value);
        var sign = base64_to_buf(document.getElementById('sign').value);
        keyStore.find(key).then((key) => {
            window.crypto.subtle.verify(keyStore.signAlgo, key.verify_key, sign, data).then((ret) => {
                alert(ret ? 'verify OK' : 'verify failed');
            }, (ev) => {
                alert('verify failed: ' + ev);
            });
        }, (ev) => {
            alert(ev);
        });
    });
    document.getElementById('encrypt').addEventListener('click', () => {
        var key = get_active_public_key_id();
        if (!key) return;
        var data = str_to_buf(document.getElementById('plain_text').value);
        keyStore.find(key).then((key) => {
            webcrypto_suppl_ecies_encrypt(keyStore.deriveAlgo, {name: "AES-GCM", length: 128}, key.derive_key, data).then((encrypted) => {
                document.getElementById('cipher').value = buf_to_base64(encrypted);
            }, (ev) => {
                alert(ev);
            });
        }, (ev) => {
            alert(ev);
        });
    });
    document.getElementById('decrypt').addEventListener('click', () => {
        var key = get_active_private_key_id();
        if (!key) return;
        var data = base64url_to_buf(document.getElementById('cipher').value);
        keyStore.find(key).then((key) => {
            webcrypto_suppl_ecies_decrypt(keyStore.deriveAlgo, {name: "AES-GCM", length: 128}, key.derive_key, data).then((plain) => {
                document.getElementById('plain_text').value = buf_to_str(plain);
            }, (ev) => {
                alert(ev);
            });
        }, (ev) => {
            alert(ev);
        });
    });

    change_button_enables(false);
    keyStore.open('keystore').then(() => {
        change_button_enables(true);
        refresh_key_list();
    }, (ev) => {
        alert('failed: IndexedDB initialization. ' + ev);
    });
}

function ecdsa_ecdh_roundtrip_test() {
    var signAlgo = {name: 'ECDSA', namedCurve: 'P-256'};
    var deriveAlgo = {name: 'ECDH', namedCurve: 'P-256'};

    window.crypto.subtle.generateKey(deriveAlgo, true, ['deriveKey']).then((ecdh_key) => {
        window.crypto.subtle.exportKey('jwk', ecdh_key.privateKey).then((ecdh_priv) => {
            window.crypto.subtle.importKey('jwk', ecdh_priv, deriveAlgo, false, ['deriveKey']).then((key) => {
                //console.log('ecdh-priv: round-trip ok');
            }, () => {
                alert('ECDH Private Key import not supported');
            });
        }, () => {
            alert('ECDH Private Key export not supported');
        });
        window.crypto.subtle.exportKey('jwk', ecdh_key.publicKey).then((ecdh_pub) => {
            window.crypto.subtle.importKey('jwk', ecdh_pub, deriveAlgo, false, ['deriveKey']).then((key) => {
                //console.log('ecdh-pub: round-trip ok');
            }, () => {
                alert('ECDH Public Key import not supported');
            });
        }, () => {
            alert('ECDH Public Key export not supported');
        });
    });
    window.crypto.subtle.generateKey(signAlgo, true, ['sign', 'verify']).then((ecdsa_key) => {
        window.crypto.subtle.exportKey('jwk', ecdsa_key.publicKey).then((ecdsa_pub) => {
            window.crypto.subtle.importKey('jwk', ecdsa_pub, signAlgo, false, ['verify']).then((key) => {
                //console.log('ecdsa-pub: round-trip ok');
            }, () => {
                alert('ECDSA Public Key inport not supported');
            });
        }, () => {
            alert('ECDSA Public Key export not supported');
        });
        window.crypto.subtle.exportKey('jwk', ecdsa_key.privateKey).then((ecdsa_priv) => {
            window.crypto.subtle.importKey('jwk', ecdsa_priv, signAlgo, false, ['sign']).then((key) => {
                //console.log('ecdsa-priv: round-trip ok');
            }, () => {
                alert('ECDSA Private Key import not supported');
            });
        }, () => {
            alert('ECDSA Private Key export not supported');
        });
    });
}

ecdsa_ecdh_roundtrip_test();
document.addEventListener("DOMContentLoaded", main);
