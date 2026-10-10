const { pbkdf2Sync } = require('node:crypto');

const password = 'e2e-test-password-123!';
const salt = Buffer.from('LogTriageE2ESalt01');
const iterations = 100000;
const subkey = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
const payload = Buffer.alloc(13 + salt.length + subkey.length);

payload[0] = 0x01;
payload.writeUInt32BE(1, 1);
payload.writeUInt32BE(iterations, 5);
payload.writeUInt32BE(salt.length, 9);
salt.copy(payload, 13);
subkey.copy(payload, 13 + salt.length);
process.stdout.write(payload.toString('base64'));
