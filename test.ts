/// <reference path="typings/es6-promise.d.ts" />
/// <reference path="keystore.ts" />
/// <reference path="base64.ts" />

function join_buf(bufs: Array<ArrayBuffer|ArrayBufferView>): ArrayBuffer {
    var total_bytes = 0;
    var inputs: Array<Uint8Array> = new Array(bufs.length);
    for (var i = 0; i < bufs.length; ++i) {
        if (bufs[i] instanceof ArrayBuffer) {
            inputs[i] = new Uint8Array(<ArrayBuffer>bufs[i]);
        } else {
            inputs[i] = new Uint8Array((<ArrayBufferView>bufs[i]).buffer,
                                     (<ArrayBufferView>bufs[i]).byteOffset,
                                     (<ArrayBufferView>bufs[i]).byteLength);
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
                var x_buf = Base64URL.decode(ephemeral_pubkey.x);
                var y_buf = Base64URL.decode(ephemeral_pubkey.y);
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
        x: Base64URL.encode(data8.subarray(3, 3 + x_len)),
        y: Base64URL.encode(data8.subarray(3 + x_len, 3 + x_len + y_len))
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
            var btn = <HTMLElement>buttons[i];
            if (enabled) {
                btn.removeAttribute('disabled');
            } else {
                btn.setAttribute('disabled', 'disabled');
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
        var data = str_to_buf((<HTMLInputElement>document.getElementById('msg')).value);
        keyStore.find(key).then((key) => {
            window.crypto.subtle.sign(keyStore.signAlgo, key.sign_key, data).then((sign) => {
                (<HTMLInputElement>document.getElementById('sign')).value = Base64URL.encode(sign);
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
        var data = str_to_buf((<HTMLInputElement>document.getElementById('msg')).value);
        var sign = Base64URL.decode((<HTMLInputElement>document.getElementById('sign')).value);
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
        var data = str_to_buf((<HTMLInputElement>document.getElementById('plain_text')).value);
        keyStore.find(key).then((key) => {
            webcrypto_suppl_ecies_encrypt(keyStore.deriveAlgo, {name: "AES-GCM", length: 128}, key.derive_key, data).then((encrypted) => {
                (<HTMLInputElement>document.getElementById('cipher')).value = Base64URL.encode(encrypted);
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
        var data = Base64URL.decode((<HTMLInputElement>document.getElementById('cipher')).value);
        keyStore.find(key).then((key) => {
            webcrypto_suppl_ecies_decrypt(keyStore.deriveAlgo, {name: "AES-GCM", length: 128}, key.derive_key, data).then((plain) => {
                (<HTMLInputElement>document.getElementById('plain_text')).value = buf_to_str(plain);
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
