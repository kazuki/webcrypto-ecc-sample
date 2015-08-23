all: test.js

test.js: test.ts keystore.ts base64.ts
	tsc --out test.js test.ts
