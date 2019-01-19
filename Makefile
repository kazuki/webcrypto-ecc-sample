all: test.js
clean:
	rm -f test.js

test.js: test.ts keystore.ts base64.ts webcrypto_supplements.ts
	tsc --target es2015 --out test.js test.ts
