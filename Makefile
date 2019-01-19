all: test.js iframe.js
clean:
	rm -f test.js iframe.js

test.js: test.ts keystore.ts base64.ts webcrypto_supplements.ts
	tsc --target es2015 --out test.js test.ts

iframe.js: iframe.ts keystore.ts webcrypto_supplements.ts
	tsc --target es2015 --out iframe.js iframe.ts
