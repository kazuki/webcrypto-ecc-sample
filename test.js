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
var KeyStore = (function () {
    function KeyStore() {
        this.db = null;
        this.signAlgo = null;
        this.deriveAlgo = null;
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
    KeyStore.prototype.open = function (db_name) {
        var _this = this;
        var req = window.indexedDB.open(db_name, 1);
        req.onupgradeneeded = function () {
            var db = req.result;
            db.createObjectStore('keystore', {
                keyPath: 'id',
                autoIncrement: false
            });
        };
        return new Promise(function (resolve, reject) {
            req.onsuccess = function () {
                _this.db = req.result;
                resolve(_this.db);
            };
            req.onerror = function (ev) {
                reject(ev);
            };
        });
    };
    // 秘密鍵を作成し指定したidをキーとして保存する
    KeyStore.prototype.generate = function (id) {
        // WebCryptographyAPIが残念な出来なので，アルゴリズム的には可能なのだが
        // sign/verify/deriveKey全てに対応する鍵を作成できない．
        // そこでECDSA(sign/verify)の鍵を生成後，一度秘密鍵をエクスポートして
        // ECDH(deriveKey)用の鍵を生成する．
        // また，IndexedDBのObjectStoreにはexportableではないCryptoKeyを保管できないので
        // IndexedDBを使う限りは結局のところ秘密鍵に対してexportable属性を付与しなければならない
        // (Firefox 43.0a1, 2015-08-21)
        var _this = this;
        return new Promise(function (resolve, reject) {
            window.crypto.subtle.generateKey(_this.signAlgo, true, ['sign', 'verify']).then(function (ecdsa_key) {
                window.crypto.subtle.exportKey('jwk', ecdsa_key.privateKey).then(function (ecdsa_priv) {
                    var value = {
                        'id': id,
                        'private': ecdsa_priv.d,
                        'public': {
                            'x': ecdsa_priv.x,
                            'y': ecdsa_priv.y
                        }
                    };
                    var transaction = _this.db.transaction(['keystore'], 'readwrite');
                    var store = transaction.objectStore('keystore');
                    var req = store.add(value);
                    req.onsuccess = function () {
                        _this._to_cryptokey(value).then(function (key) {
                            resolve(key);
                        }).catch(function (ev) {
                            reject(ev);
                        });
                    };
                    req.onerror = function (ev) {
                        reject(ev);
                    };
                }).catch(function (ev) {
                    reject(ev);
                });
            }).catch(function (ev) {
                reject(ev);
            });
        });
    };
    KeyStore.prototype.find = function (id) {
        var _this = this;
        var transaction = this.db.transaction(['keystore']);
        var store = transaction.objectStore('keystore');
        var req = store.get(id);
        return new Promise(function (resolve, reject) {
            req.onsuccess = function () {
                if (req.result) {
                    _this._to_cryptokey(req.result).then(function (key) {
                        resolve(key);
                    }).catch(function (ev) {
                        reject(ev);
                    });
                }
                else {
                    reject(undefined);
                }
            };
            req.onerror = function (ev) {
                reject(ev);
            };
        });
    };
    KeyStore.prototype.delete = function (id) {
        var transaction = this.db.transaction(['keystore'], 'readwrite');
        var store = transaction.objectStore('keystore');
        var req = store.delete(id);
        return new Promise(function (resolve, reject) {
            req.onsuccess = function () {
                resolve();
            };
            req.onerror = function (ev) {
                reject(ev);
            };
        });
    };
    ;
    KeyStore.prototype.import = function (id, publicKey) {
        var _this = this;
        var pub = {
            crv: this.signAlgo.namedCurve,
            ext: true,
            kty: 'EC',
            x: publicKey.x,
            y: publicKey.y
        };
        return new Promise(function (resolve, reject) {
            window.crypto.subtle.importKey('jwk', pub, _this.signAlgo, false, ['verify']).then(function (key) {
                var value = {
                    'id': id,
                    'public': {
                        'x': pub.x,
                        'y': pub.y
                    }
                };
                var transaction = _this.db.transaction(['keystore'], 'readwrite');
                var store = transaction.objectStore('keystore');
                var req = store.add(value);
                req.onsuccess = function () {
                    _this._to_cryptokey(value).then(function (key) {
                        resolve(key);
                    }).catch(function (ev) {
                        reject(ev);
                    });
                };
                req.onerror = function (ev) {
                    reject(ev);
                };
            }).catch(function (ev) {
                reject(ev);
            });
        });
    };
    KeyStore.prototype.list = function () {
        var _this = this;
        var transaction = this.db.transaction(['keystore']);
        var store = transaction.objectStore('keystore');
        var req = store.openCursor();
        var ret = [];
        return new Promise(function (resolve, reject) {
            req.onsuccess = function () {
                var cursor = req.result;
                if (cursor) {
                    ret.push(_this._to_cryptokey(cursor.value));
                    cursor.continue();
                }
                else {
                    Promise.all(ret).then(function (values) {
                        resolve(values);
                    }).catch(function (ev) {
                        reject(ev);
                    });
                }
            };
            req.onerror = function (ev) {
                reject(ev);
            };
        });
    };
    // ObjectStoreに格納している最低限の情報からCryptoKeyを復元する
    KeyStore.prototype._to_cryptokey = function (stored_data) {
        var _this = this;
        var x = stored_data.public.x;
        var y = stored_data.public.y;
        var d = stored_data.private;
        return new Promise(function (resolve, reject) {
            var pub = {
                crv: _this.signAlgo.namedCurve,
                ext: true,
                kty: 'EC',
                x: x,
                y: y
            };
            var ret = [];
            ret.push(window.crypto.subtle.importKey('jwk', pub, _this.signAlgo, false, ['verify']));
            ret.push(window.crypto.subtle.importKey('jwk', pub, _this.deriveAlgo, false, ['deriveKey']));
            if (d) {
                var priv = {
                    crv: _this.signAlgo.namedCurve,
                    ext: true,
                    kty: 'EC',
                    x: x,
                    y: y,
                    d: d
                };
                ret.push(window.crypto.subtle.importKey('jwk', priv, _this.signAlgo, false, ['sign']));
                ret.push(window.crypto.subtle.importKey('jwk', priv, _this.deriveAlgo, false, ['deriveKey']));
            }
            Promise.all(ret).then(function (values) {
                var ki = {
                    id: stored_data.id,
                    is_private: false,
                    verify_key: values[0],
                    derive_key: values[1],
                    public_key: { x: x, y: y },
                    sign_key: undefined,
                    private_key: undefined
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
            }).catch(function (ev) {
                reject(ev);
            });
        });
    };
    return KeyStore;
})();
function buf_to_base64(buf) {
    return base64js.fromByteArray(new Uint8Array(buf));
}
function base64_to_buf(str) {
    return base64js.toByteArray(str).buffer;
}
function buf_to_base64url(buf) {
    return base64js.fromByteArray(new Uint8Array(buf))
        .replace(/\+/g, '-').replace('/\//g', '_').replace('/=/g', '');
}
function base64url_to_buf(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4 != 0)
        str += '=';
    return base64js.toByteArray(str).buffer;
}
function join_buf(bufs) {
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
function webcrypto_suppl_ecies_encrypt(deriveAlgo, encryptAlgo, public_key, data) {
    // ECIESっぽいもので暗号化(仕様書見てないので厳密には準拠していない)
    return new Promise(function (resolve, reject) {
        window.crypto.subtle.generateKey(deriveAlgo, true, ['deriveKey']).then(function (ephemeral_key) {
            window.crypto.subtle.exportKey('jwk', ephemeral_key.publicKey).then(function (ephemeral_pubkey) {
                var algo = {
                    name: deriveAlgo.name,
                    namedCurve: deriveAlgo.namedCurve,
                    public: public_key
                };
                var x_buf = base64url_to_buf(ephemeral_pubkey.x);
                var y_buf = base64url_to_buf(ephemeral_pubkey.y);
                window.crypto.subtle.deriveKey(algo, ephemeral_key.privateKey, encryptAlgo, false, ['encrypt']).then(function (key) {
                    var iv = window.crypto.getRandomValues(new Uint8Array(12));
                    encryptAlgo.iv = iv;
                    window.crypto.subtle.encrypt(encryptAlgo, key, data).then(function (encrypted) {
                        var header = new Uint8Array(3);
                        header[0] = x_buf.byteLength;
                        header[1] = y_buf.byteLength;
                        header[2] = iv.byteLength;
                        var buf = join_buf([header, x_buf, y_buf, iv, encrypted]);
                        resolve(buf);
                    }, function (ev) {
                        reject(ev);
                    });
                }, function (ev) {
                    reject(ev);
                });
            }, function (ev) {
                reject(ev);
            });
        }, function (ev) {
            reject(ev);
        });
    });
}
function webcrypto_suppl_ecies_decrypt(deriveAlgo, encryptAlgo, private_key, data) {
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
    return new Promise(function (resolve, reject) {
        window.crypto.subtle.importKey('jwk', ephemeral_jwt, deriveAlgo, false, ['deriveKey']).then(function (public_key) {
            var algo = {
                name: deriveAlgo.name,
                namedCurve: deriveAlgo.namedCurve,
                public: public_key
            };
            window.crypto.subtle.deriveKey(algo, private_key, encryptAlgo, false, ['decrypt']).then(function (key) {
                encryptAlgo.iv = iv;
                window.crypto.subtle.decrypt(encryptAlgo, key, data8).then(function (decrypted) {
                    resolve(decrypted);
                }, function (ev) {
                    reject(ev);
                });
            }, function (ev) {
                reject(ev);
            });
        }, function (ev) {
            reject(ev);
        });
    });
}
function main() {
    var keyStore = new KeyStore();
    var priv_list = document.getElementById('private_keys');
    var pub_list = document.getElementById('public_keys');
    var change_button_enables = function (enabled) {
        var buttons = document.querySelectorAll('button');
        for (var i = 0; i < buttons.length; ++i) {
            if (enabled) {
                buttons[i].removeAttribute('disabled');
            }
            else {
                buttons[i].setAttribute('disabled', 'disabled');
            }
        }
        ;
    };
    var refresh_key_list = function () {
        keyStore.list().then(function (keys) {
            while (priv_list.firstChild)
                priv_list.removeChild(priv_list.firstChild);
            while (pub_list.firstChild)
                pub_list.removeChild(pub_list.firstChild);
            keys.forEach(function (key) {
                var list = pub_list;
                if (key.is_private)
                    list = priv_list;
                var opt = document.createElement('option');
                opt.text = key.id;
                list.appendChild(opt);
            });
        });
    };
    var get_active_key_id = function (list) {
        if (list.selectedIndex < 0)
            return null;
        return list.options[list.selectedIndex].text;
    };
    var get_active_private_key_id = function () {
        return get_active_key_id(priv_list);
    };
    var get_active_public_key_id = function () {
        return get_active_key_id(pub_list);
    };
    var delete_key = function (key_id) {
        keyStore.delete(key_id).then(function () {
            refresh_key_list();
        }, function (ev) {
            alert(ev);
        });
    };
    var export_key = function (key_id, is_private) {
        keyStore.find(key_id).then(function (key) {
            if (is_private && key.is_private) {
                prompt('private-key', JSON.stringify(key.private_key));
            }
            else if (!is_private) {
                prompt('public-key', JSON.stringify(key.public_key));
            }
        }, function (ev) {
            alert(ev);
        });
    };
    var str_to_buf = function (str) {
        // utf16
        var buf = new ArrayBuffer(str.length * 2);
        var view = new Uint16Array(buf);
        for (var i = 0; i < str.length; ++i) {
            view[i] = str.charCodeAt(i);
        }
        return buf;
    };
    var buf_to_str = function (buf) {
        var out = '';
        var view = new Uint16Array(buf);
        for (var i = 0; i < view.length; ++i)
            out += String.fromCharCode(view[i]);
        return out;
    };
    document.getElementById('private_key_generate').addEventListener('click', function () {
        var name = prompt('input unique key name');
        if (name) {
            keyStore.generate(name).then(function () {
                alert('success!');
                refresh_key_list();
            }, function (ev) {
                alert(ev);
            });
        }
    });
    document.getElementById('private_key_delete').addEventListener('click', function () {
        var key_id = get_active_private_key_id();
        if (key_id && confirm('"' + key_id + '": delete ok?')) {
            delete_key(key_id);
        }
    });
    document.getElementById('private_key_export_public').addEventListener('click', function () {
        var key_id = get_active_private_key_id();
        if (key_id)
            export_key(key_id, false);
    });
    document.getElementById('private_key_export_private').addEventListener('click', function () {
        var key_id = get_active_private_key_id();
        if (key_id)
            export_key(key_id, true);
    });
    document.getElementById('public_key_delete').addEventListener('click', function () {
        var key_id = get_active_public_key_id();
        if (key_id && confirm('"' + key_id + '": delete ok?')) {
            delete_key(key_id);
        }
    });
    document.getElementById('public_key_export').addEventListener('click', function () {
        var key_id = get_active_public_key_id();
        if (key_id)
            export_key(key_id, false);
    });
    document.getElementById('public_key_import').addEventListener('click', function () {
        var name = prompt('input unique key name');
        if (!name)
            return;
        var pub = prompt('input public key');
        try {
            pub = JSON.parse(pub);
            keyStore.import(name, pub).then(function () {
                alert('success!');
                refresh_key_list();
            }, function (ev) {
                alert(ev);
            });
        }
        catch (ex) {
            alert(ex);
        }
    });
    document.getElementById('sign_msg').addEventListener('click', function () {
        var key = get_active_private_key_id();
        if (!key)
            return;
        var data = str_to_buf(document.getElementById('msg').value);
        keyStore.find(key).then(function (key) {
            window.crypto.subtle.sign(keyStore.signAlgo, key.sign_key, data).then(function (sign) {
                document.getElementById('sign').value = buf_to_base64(sign);
            }, function (ev) {
                alert('sign failed: ' + ev);
            });
        }, function (ev) {
            alert(ev);
        });
    });
    document.getElementById('verify_msg').addEventListener('click', function () {
        var key = get_active_public_key_id();
        if (!key)
            return;
        var data = str_to_buf(document.getElementById('msg').value);
        var sign = base64_to_buf(document.getElementById('sign').value);
        keyStore.find(key).then(function (key) {
            window.crypto.subtle.verify(keyStore.signAlgo, key.verify_key, sign, data).then(function (ret) {
                alert(ret ? 'verify OK' : 'verify failed');
            }, function (ev) {
                alert('verify failed: ' + ev);
            });
        }, function (ev) {
            alert(ev);
        });
    });
    document.getElementById('encrypt').addEventListener('click', function () {
        var key = get_active_public_key_id();
        if (!key)
            return;
        var data = str_to_buf(document.getElementById('plain_text').value);
        keyStore.find(key).then(function (key) {
            webcrypto_suppl_ecies_encrypt(keyStore.deriveAlgo, { name: "AES-GCM", length: 128 }, key.derive_key, data).then(function (encrypted) {
                document.getElementById('cipher').value = buf_to_base64(encrypted);
            }, function (ev) {
                alert(ev);
            });
        }, function (ev) {
            alert(ev);
        });
    });
    document.getElementById('decrypt').addEventListener('click', function () {
        var key = get_active_private_key_id();
        if (!key)
            return;
        var data = base64url_to_buf(document.getElementById('cipher').value);
        keyStore.find(key).then(function (key) {
            webcrypto_suppl_ecies_decrypt(keyStore.deriveAlgo, { name: "AES-GCM", length: 128 }, key.derive_key, data).then(function (plain) {
                document.getElementById('plain_text').value = buf_to_str(plain);
            }, function (ev) {
                alert(ev);
            });
        }, function (ev) {
            alert(ev);
        });
    });
    change_button_enables(false);
    keyStore.open('keystore').then(function () {
        change_button_enables(true);
        refresh_key_list();
    }, function (ev) {
        alert('failed: IndexedDB initialization. ' + ev);
    });
}
function ecdsa_ecdh_roundtrip_test() {
    var signAlgo = { name: 'ECDSA', namedCurve: 'P-256' };
    var deriveAlgo = { name: 'ECDH', namedCurve: 'P-256' };
    window.crypto.subtle.generateKey(deriveAlgo, true, ['deriveKey']).then(function (ecdh_key) {
        window.crypto.subtle.exportKey('jwk', ecdh_key.privateKey).then(function (ecdh_priv) {
            window.crypto.subtle.importKey('jwk', ecdh_priv, deriveAlgo, false, ['deriveKey']).then(function (key) {
                //console.log('ecdh-priv: round-trip ok');
            }, function () {
                alert('ECDH Private Key import not supported');
            });
        }, function () {
            alert('ECDH Private Key export not supported');
        });
        window.crypto.subtle.exportKey('jwk', ecdh_key.publicKey).then(function (ecdh_pub) {
            window.crypto.subtle.importKey('jwk', ecdh_pub, deriveAlgo, false, ['deriveKey']).then(function (key) {
                //console.log('ecdh-pub: round-trip ok');
            }, function () {
                alert('ECDH Public Key import not supported');
            });
        }, function () {
            alert('ECDH Public Key export not supported');
        });
    });
    window.crypto.subtle.generateKey(signAlgo, true, ['sign', 'verify']).then(function (ecdsa_key) {
        window.crypto.subtle.exportKey('jwk', ecdsa_key.publicKey).then(function (ecdsa_pub) {
            window.crypto.subtle.importKey('jwk', ecdsa_pub, signAlgo, false, ['verify']).then(function (key) {
                //console.log('ecdsa-pub: round-trip ok');
            }, function () {
                alert('ECDSA Public Key inport not supported');
            });
        }, function () {
            alert('ECDSA Public Key export not supported');
        });
        window.crypto.subtle.exportKey('jwk', ecdsa_key.privateKey).then(function (ecdsa_priv) {
            window.crypto.subtle.importKey('jwk', ecdsa_priv, signAlgo, false, ['sign']).then(function (key) {
                //console.log('ecdsa-priv: round-trip ok');
            }, function () {
                alert('ECDSA Private Key import not supported');
            });
        }, function () {
            alert('ECDSA Private Key export not supported');
        });
    });
}
ecdsa_ecdh_roundtrip_test();
document.addEventListener("DOMContentLoaded", main);
