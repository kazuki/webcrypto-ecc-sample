class _Base64 {
    static encode(chars: string, pad: string, data: ArrayBuffer|ArrayBufferView): string {
        var view: Uint8Array = (data instanceof ArrayBuffer ? new Uint8Array(data) :
                                new Uint8Array((<ArrayBufferView>data).buffer,
                                               (<ArrayBufferView>data).byteOffset,
                                               (<ArrayBufferView>data).byteLength));
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
            } else {
                out += chars[(view[i] & 0x3) << 4];
                if (pad)
                    out += pad + pad;
            }
        }
        return out;
    }

    static decode(chars: string, pad: string, data: string): ArrayBuffer {
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
    static CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    static encode(data: ArrayBuffer|ArrayBufferView): string {
        return _Base64.encode(Base64.CHARS, '=', data);
    }

    static decode(data: string): ArrayBuffer {
        return _Base64.decode(Base64.CHARS, '=', data);
    }
}

class Base64URL {
    static CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    static encode(data: ArrayBuffer|ArrayBufferView): string {
        return _Base64.encode(Base64URL.CHARS, null, data);
    }

    static decode(data: string): ArrayBuffer {
        return _Base64.decode(Base64URL.CHARS, null, data);
    }
}
