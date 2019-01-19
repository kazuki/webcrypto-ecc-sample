/// <reference path="base64.ts" />
/// <reference path="keystore.ts" />
/// <reference path="webcrypto_supplements.ts" />
class State {
  store: KeyStore;
  key: KeyInfo = null;
  pubKey: KeyInfo = null;
  contents: HTMLDivElement;

  constructor() {
    document.addEventListener('DOMContentLoaded', () => {
      this.contents = <HTMLDivElement>document.getElementById('contents');
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

  private _init() {
    this.store.import(null, this.key.public_key).then((key) => {
      this.pubKey = key;
    });
    window.addEventListener('message', (e) => {
      var m = e.data.method;
      var id = e.data.id;
      var post = (msg) => {
        if (e.origin && e.origin !== 'null') {
          e.source.postMessage(msg, e.origin);
        } else {
          e.source.postMessage(msg);
        }
      };
      if (m === 'get_public_key') {
        post({'id': id, 'data': this.key.public_key});
      } else if (m === 'encrypt') {
        // テキストのみ。バイナリ対応させるときはArrayBuffer/Base64で転送とかする
        var buf = new Uint16Array([].map.call(e.data.data, (c) => c.charCodeAt(0))).buffer;
        WebCryptoSupplements.ecies_encrypt(
          this.store.deriveAlgo, this.pubKey.derive_key, buf).then((encrypted) => {
            post({'id': id, 'result': 'ok', 'data': Base64URL.encode(encrypted)});
          }, (err) => {
            console.error(err);
            post({'id': id, 'error': 'error'});
          });
      } else if (m === 'decrypt') {
        WebCryptoSupplements.ecies_decrypt(
          this.store.deriveAlgo, this.key.derive_key, Base64URL.decode(e.data.data)).then((plain) => {
            this.contents.innerText = String.fromCharCode.apply("", new Uint16Array(plain));
            post({'id': id, 'result': 'ok'});
          }, (err) => {
            console.error(err);
            post({'id': id, 'result': 'error'});
          });
      }
    });
  }
}
new State();
