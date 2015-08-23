/// <reference path="typings/es6-promise.d.ts" />
var __extends = (this && this.__extends) || function (d, b) {
    for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
    function __() { this.constructor = d; }
    __.prototype = b.prototype;
    d.prototype = new __();
};
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
var KeyStore = (function () {
    function KeyStore() {
        this.db = null;
        this.store_name = 'keystore';
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
    KeyStore.prototype.open = function (db_name, store_name) {
        var _this = this;
        if (store_name)
            this.store_name = store_name;
        var req = window.indexedDB.open(db_name, 1);
        req.onupgradeneeded = function () {
            var db = req.result;
            db.createObjectStore(_this.store_name, {
                keyPath: 'id',
                autoIncrement: false
            });
        };
        return new Promise(function (resolve, reject) {
            req.onsuccess = function () {
                _this.db = req.result;
                resolve(_this);
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
                    var transaction = _this.db.transaction([_this.store_name], 'readwrite');
                    var store = transaction.objectStore(_this.store_name);
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
        var transaction = this.db.transaction([this.store_name]);
        var store = transaction.objectStore(this.store_name);
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
        var transaction = this.db.transaction([this.store_name], 'readwrite');
        var store = transaction.objectStore(this.store_name);
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
                var transaction = _this.db.transaction([_this.store_name], 'readwrite');
                var store = transaction.objectStore(_this.store_name);
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
        var transaction = this.db.transaction([this.store_name]);
        var store = transaction.objectStore(this.store_name);
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
                var ki = ret.length == 2 ?
                    new PublicKeyInfo(stored_data.id, values[0], values[1], { x: x, y: y }) :
                    new PrivateKeyInfo(stored_data.id, values[2], values[0], values[3], { x: x, y: y, d: d }, { x: x, y: y });
                resolve(ki);
            }).catch(function (ev) {
                reject(ev);
            });
        });
    };
    return KeyStore;
})();
var KeyInfo = (function () {
    function KeyInfo(id, is_private) {
        this.id = id;
        this.is_private = is_private;
    }
    return KeyInfo;
})();
var PublicKeyInfo = (function (_super) {
    __extends(PublicKeyInfo, _super);
    function PublicKeyInfo(id, verify_key, derive_key, public_key) {
        _super.call(this, id, false);
        this.verify_key = verify_key;
        this.derive_key = derive_key;
        this.public_key = public_key;
        this.sign_key = undefined;
        this.private_key = undefined;
    }
    return PublicKeyInfo;
})(KeyInfo);
var PrivateKeyInfo = (function (_super) {
    __extends(PrivateKeyInfo, _super);
    function PrivateKeyInfo(id, sign_key, verify_key, derive_key, private_key, public_key) {
        _super.call(this, id, true);
        this.sign_key = sign_key;
        this.verify_key = verify_key;
        this.derive_key = derive_key;
        this.public_key = public_key;
        this.private_key = private_key;
    }
    return PrivateKeyInfo;
})(KeyInfo);
var _Base64 = (function () {
    function _Base64() {
    }
    _Base64.encode = function (chars, pad, data) {
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
    };
    _Base64.decode = function (chars, pad, data) {
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
    };
    return _Base64;
})();
var Base64 = (function () {
    function Base64() {
    }
    Base64.encode = function (data) {
        return _Base64.encode(Base64.CHARS, '=', data);
    };
    Base64.decode = function (data) {
        return _Base64.decode(Base64.CHARS, '=', data);
    };
    Base64.CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    return Base64;
})();
var Base64URL = (function () {
    function Base64URL() {
    }
    Base64URL.encode = function (data) {
        return _Base64.encode(Base64URL.CHARS, null, data);
    };
    Base64URL.decode = function (data) {
        return _Base64.decode(Base64URL.CHARS, null, data);
    };
    Base64URL.CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    return Base64URL;
})();
/// <reference path="typings/es6-promise.d.ts" />
/// <reference path="keystore.ts" />
/// <reference path="base64.ts" />
function join_buf(bufs) {
    var total_bytes = 0;
    var inputs = new Array(bufs.length);
    for (var i = 0; i < bufs.length; ++i) {
        if (bufs[i] instanceof ArrayBuffer) {
            inputs[i] = new Uint8Array(bufs[i]);
        }
        else {
            inputs[i] = new Uint8Array(bufs[i].buffer, bufs[i].byteOffset, bufs[i].byteLength);
        }
        total_bytes += inputs[i].length;
    }
    var buf = new ArrayBuffer(total_bytes);
    var view = new Uint8Array(buf);
    var off = 0;
    for (var i = 0; i < inputs.length; ++i) {
        view.set(inputs[i], off);
        off += inputs[i].length;
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
                var x_buf = Base64URL.decode(ephemeral_pubkey.x);
                var y_buf = Base64URL.decode(ephemeral_pubkey.y);
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
        x: Base64URL.encode(data8.subarray(3, 3 + x_len)),
        y: Base64URL.encode(data8.subarray(3 + x_len, 3 + x_len + y_len))
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
            var btn = buttons[i];
            if (enabled) {
                btn.removeAttribute('disabled');
            }
            else {
                btn.setAttribute('disabled', 'disabled');
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
                document.getElementById('sign').value = Base64URL.encode(sign);
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
        var sign = Base64URL.decode(document.getElementById('sign').value);
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
                document.getElementById('cipher').value = Base64URL.encode(encrypted);
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
        var data = Base64URL.decode(document.getElementById('cipher').value);
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
