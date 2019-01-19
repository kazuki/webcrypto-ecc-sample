function main() {
    var iframe = document.getElementById('iframe').contentWindow;
    document.getElementById('get_public_key').addEventListener('click', () => {
        iframe.postMessage({
            id: 0,
            method: 'get_public_key',
        });
    });
    document.getElementById('encrypt').addEventListener('click', () => {
        var data = prompt('input plain text');
        iframe.postMessage({
            id: 1,
            method: 'encrypt',
            data: data,
        });
    });
    document.getElementById('decrypt').addEventListener('click', () => {
        var data = prompt('input encrypted text');
        iframe.postMessage({
            id: 2,
            method: 'decrypt',
            data: data,
        });
    });
    window.addEventListener('message', function(e) {
        console.log(e);
        if (e.data.id === 0) {
            prompt('public key', JSON.stringify(e.data.data));
        }
        if (e.data.id === 1) {
            prompt('copy encrypted text', e.data.data);
        }
    });
}
document.addEventListener('DOMContentLoaded', main);
