/// <reference path="typings/es6-promise.d.ts" />
/// <reference path="keystore.ts" />
/// <reference path="base64.ts" />
/// <reference path="webcrypto_supplements.ts" />

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
        var data = str_to_buf((<HTMLTextAreaElement>document.getElementById('plain_text')).value);
        keyStore.find(key).then((key) => {
            WebCryptoSupplements.ecies_encrypt(keyStore.deriveAlgo, key.derive_key, data).then((encrypted) => {
                (<HTMLTextAreaElement>document.getElementById('cipher')).value = Base64URL.encode(encrypted);
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
        var data = Base64URL.decode((<HTMLTextAreaElement>document.getElementById('cipher')).value);
        keyStore.find(key).then((key) => {
            WebCryptoSupplements.ecies_decrypt(keyStore.deriveAlgo, key.derive_key, data).then((plain) => {
                (<HTMLTextAreaElement>document.getElementById('plain_text')).value = buf_to_str(plain);
            }, (ev) => {
                alert(ev);
            });
        }, (ev) => {
            alert(ev);
        });
    });
    document.getElementById('clear_keystore').addEventListener('click', () => {
        keyStore.clear();
        refresh_key_list();
    });

    change_button_enables(false);
    keyStore.open('keystore').then(() => {
        change_button_enables(true);
        refresh_key_list();
    }, (ev) => {
        alert('failed: IndexedDB initialization. ' + ev);
    });
}

document.addEventListener("DOMContentLoaded", main);
