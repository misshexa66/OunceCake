function packet(command, input) {
  const bytes = Buffer.alloc(256);
  bytes.writeUInt32LE(4);
  bytes.writeUInt32LE(Math.ceil((32 + input.length) / 4), 4);
  bytes.write('SFCI', 16);
  bytes.writeUInt32LE(command, 24);
  input.copy(bytes, 32);
  return bytes;
}


function titleId(value) {
  if (typeof value !== 'string' || !/^(?:0x)?[0-9a-fA-F]{16}$/.test(value)) {
    throw new Error('Title must be 16 hexadecimal digits (optional 0x prefix)');
  }

  return value.replace(/^0x/, '').toLowerCase();
}

function idBytes(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt('0x' + value));
  return bytes;
}

// put together ipc requests
function fixedOutput(command, input, address, size) {
  const bytes = packet(command, input);
  const words = bytes.readUInt32LE(4) & 0x3ff;
  const at = 8 + words * 4;

  bytes.writeUInt32LE(bytes.readUInt32LE(4) | (3 << 10), 4);
  bytes.writeUInt32LE(address >>> 0, at);
  bytes.writeUInt32LE((Math.floor(address / 2 ** 32) | (size << 16)) >>> 0, at + 4);
  return bytes;
}

function pathRequest(command, input, address, length = 0x301) {
  const bytes = packet(command, input);
  const pointer = BigInt(address);
  bytes.writeUInt32LE(4 | (1 << 16));
  bytes.writeUInt32LE(
    Number((BigInt(length) << 16n) | (((pointer >> 36n) & 7n) << 6n) | (((pointer >> 32n) & 15n) << 12n)),
    8,
  );
  bytes.writeUInt32LE(Number(pointer & 0xffffffffn), 12);
  return bytes;
}

// stole these from atmosphere, ty
// translations for what the damn error codes mean
const names = new Map([
  [0x000e05, 'ContentMetaNotFound'],
  [0x01e005, 'InvalidContentMetaKey'],
  [0x339a02, 'ProgramInfoNotFound'],
  [0x07d202, 'PartitionNotFound'],
  [0x07d802, 'NcaExternalKeyNotFound'],
  [0x1fb402, 'RomNcaHeaderSignature1VerificationFailed'],
  [0x235e02, 'InvalidNcaId'],
  [0x244802, 'PartitionSignatureVerificationFailed'],
  [0x320002, 'PermissionDenied'],
  [0x021005, 'SdCardContentMetaDatabaseNotActive'],
  [0x020a05, 'GameCardContentMetaDatabaseNotActive'],
]);

function decodeResult(value) {
  const raw = Number(value) >>> 0;
  const canonical = raw & 0x3fffff;
  return {
    raw,
    canonical,
    name: names.get(canonical) || 'UnknownResult',
  };
}

function resultError(label, value) {
  const result = decodeResult(value);
  const error = new Error(
    label +
      ': result 0x' +
      result.raw.toString(16) +
      ' (' +
      result.name +
      ', canonical 0x' +
      result.canonical.toString(16) +
      ')',
  );
  error.nativeResult = result;
  return error;
}

function success(reply, label) {
  if (reply.result) throw resultError(label, reply.result);
  return reply;
}
// it's good to clean up after yourself.
async function cleanup(steps, failure) {
  const errors = failure ? [failure] : [];
  for (const step of steps) {
    try { await step(); } catch (error) { errors.push(error); }
  }
  if (errors.length === 1) throw errors[0];
  if (errors.length) throw new AggregateError(errors, errors.map((error) => error.message).join('\n'));
}

async function withCleanup(operation, ...steps) {
  let value;
  let failure;
  try { value = await operation(); } catch (error) { failure = error; }
  await cleanup(steps, failure);
  return value;
}

async function closeHandles(s, handles) {
  await cleanup([...handles].reverse().map((handle) => async () => {
    if (s.handles.has(handle)) await s.close(handle);
  }));
}

function throwIfCancelled(shouldStop) {
  if (shouldStop()) throw Object.assign(new Error('FTP preparation cancelled'), { code: 'FTP_CANCELLED' });
}

module.exports = {
  packet, titleId, idBytes, fixedOutput, pathRequest, resultError,
  success, cleanup, withCleanup, closeHandles, throwIfCancelled,
};
