const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { success, idBytes, resultError, cleanup, withCleanup } = require('./protocol.cjs');

const ptr = (bytes, at = 0) => Number(bytes.readBigUInt64LE(at));
const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value); return bytes; };
const u64 = (value) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(BigInt(value)); return bytes; };

function candidates(bytes, layout) {

  const rows = [];

  for (let at = 0; at < bytes.length; at += 0x30) {
    if (ptr(bytes, at + 0x28) !== layout.rootVptr + 0x5888) continue;

    const domain = ptr(bytes, at + 0x18);
    const object = ptr(bytes, at + 0x20);
    rows.push({
      entry: layout.table + at,
      domain,
      object,
      pair: bytes.subarray(at + 0x20, at + 0x30).toString('hex'),
      owner: bytes.subarray(at + 0x18, at + 0x30).toString('hex'),
    });
  }

  return rows[0];
}

async function findRegistryInterface({ memory, layout }) {
  const row = candidates(await memory.read(layout.table, layout.count * 0x30), layout);
  const domain = await memory.read(row.domain, 0x20);
  const header = await memory.read(row.object, 0x18);

  const caller = header.readBigUInt64LE(8);
  return {
    ...row,
    identity: header.subarray(0, 16).toString('hex'),
    references: header.readUInt32LE(16),
  };
}

// undo the pointer change we do to grab a registry handle for mounting update romfs
async function restoreRegistrySlot(memory, state) {
  const own = state.auxiliary;

  const current = await memory.read(own.entry + 0x20, 16);
  const original = Buffer.from(own.originalPair, 'hex');

  if (current.equals(original)) return;

  const replacement = Buffer.from(state.source.pair, 'hex');
  await memory.write(own.entry + 0x20, replacement, original);
}

async function copyProgramRegistry({ attachment: a, reader }) {
  const { memory, layout } = reader;
  const source = await findRegistryInterface(reader);
  const state = { source };
  let auxiliary;
  let handle;
  let swapping = false;
  let closed = false;

  async function closeReference() {
    if (closed) return;

    await a.s.close(handle);
    closed = true;
  }

  try {
    auxiliary = await a.domain.openDomain(a.s, 'Owned registry reference');

    const entry = layout.table + (auxiliary.root - 1) * 0x30;
    const b = await memory.read(entry, 0x30);
    const domain = ptr(b, 0x18);
    const object = ptr(b, 0x20);
    const h = await memory.read(object, 0x40);
    state.auxiliary = { ...auxiliary, entry, domain, originalPair: b.subarray(0x20).toString('hex') };
    swapping = true;
    await memory.write(entry + 0x20, b.subarray(0x20), Buffer.from(source.pair, 'hex'));

    const reply = await a.domain.send(
      a.s,
      'Copy existing native program registry',
      auxiliary.handle,
      a.domain.wire.control(1, u32(auxiliary.root)),
    );

    if (reply.result) throw resultError('Copy existing native program registry', reply.result);

    handle = a.domain.oneHandle(reply);
    await restoreRegistrySlot(memory, state);
    swapping = false;
    await a.s.close(auxiliary.handle);
    auxiliary = null;
    return { handle, close: closeReference };
  } catch (error) {
    await cleanup([
      async () => {
        if (swapping) {
          await restoreRegistrySlot(memory, state);
          swapping = false;
        }
      },
      () => handle && !closed ? closeReference() : undefined,
      async () => {
        if (!auxiliary) return;
        await a.s.close(auxiliary.handle);
      },
    ], error);
  }
}

function accessControls(bytes, title) {
  function region(at, size, minimum) {
    return bytes.subarray(at, at + size);
  }

  const aci = region(bytes.readUInt32LE(0x70), bytes.readUInt32LE(0x74), 0x40);
  const acid = region(bytes.readUInt32LE(0x78), bytes.readUInt32LE(0x7c), 0x240);
  // oz is rsa-3072, 0x300
  // nx is rsa-2048, 0x200
  const header =
    acid.toString('ascii', 0x200, 0x204) === 'ACID'
      ? 0x200
      : acid.length >= 0x340 && acid.toString('ascii', 0x300, 0x304) === 'ACID'
        ? 0x300
        : -1;
  const program = BigInt('0x' + title);

  function control(parent, field, minimum) {
    const at = parent.readUInt32LE(field);
    const size = parent.readUInt32LE(field + 4);
    return Buffer.from(parent.subarray(at, at + size));
  }

  const fah = control(aci, 0x20, 0x1c);
  const fac = control(acid, header + 0x20, 0x2c);

  for (const field of [0xc, 0x14]) {
    const at = fah.readUInt32LE(field);
    const size = fah.readUInt32LE(field + 4);
  }

  return { fah, fac };
}

async function registryReader(a) {
  const engine = path.join(a.run, 'switch2');
  const layout = JSON.parse(await fs.readFile(path.join(engine, 'ro', a.live.session + '-layout.json')));
  const memory = await require(path.join(engine, 'tools/fs-memory.cjs')).connect();

  return { memory, layout };
}

// your program content. hand it over.
async function openProgramContent({ attachment: a, title, storage, policy, manual = false }) {
  const controls = accessControls(policy, title);
  const reader = await registryReader(a);
  // random ID for telling the system "look this very real process that's totally the game wants data"
  const owner = 0xf000000000000000n | BigInt('0x' + crypto.randomBytes(7).toString('hex'));
  let reference;
  let registered = false;
  return withCleanup(async () => {
    reference = await copyProgramRegistry({ attachment: a, reader });
    await a.s.write(a.s.base + 0x8000, controls.fah);
    await a.s.write(a.s.base + 0xc000, controls.fac);
    const input = Buffer.alloc(40);
    input[0] = storage;
    input.writeBigUInt64LE(owner, 8);
    idBytes(title).copy(input, 16);
    input.writeBigUInt64LE(BigInt(controls.fah.length), 24);
    input.writeBigUInt64LE(BigInt(controls.fac.length), 32);
    success(await a.s.ipc('Register owned temporary program context', reference.handle, 0, input, {
      send: [
        { address: a.s.base + 0x8000, size: controls.fah.length, mode: 0 },
        { address: a.s.base + 0xc000, size: controls.fac.length, mode: 0 },
      ],
    }), 'Register owned temporary program context');
    registered = true;
    // special handling for game manuals
    if (manual) {
      const input = Buffer.alloc(16);
      input.writeUInt32LE(4);
      idBytes(title).copy(input, 8);
      return a.fs.open(await a.fs.root(), 'Open composed game manual', 7, input);
    }
    return openCurrentProgramRomfs({ attachment: a, reader, owner });
  }, async () => {
    if (!registered) return;
    success(await a.s.ipc('Remove owned temporary program context', reference.handle, 1, u64(owner)),
      'Remove owned temporary program context');
  }, () => reference?.close());
}

async function restoreProgramRoot(memory, owner, fields) {
  await cleanup([...fields].reverse().map((field) => async () => {
    const original = Buffer.from(field.original, 'hex');
    const current = await memory.read(field.address, 8);
    if (current.equals(original)) return;
    await memory.write(field.address, current, original);
  }));
}

async function openCurrentProgramRomfs({ attachment: a, reader, owner }) {
  const { memory, layout } = reader;
  let fields = [];
  let client;
  let storage;

  try {
    return await withCleanup(async () => {
      client = await a.fs.program();

      const entry = layout.table + (client.objectId - 1) * 0x30;
      const b = await memory.read(entry, 0x30);
      const domain = ptr(b, 0x18);
      const root = ptr(b, 0x20);
      const h = await memory.read(root, 0x40);

      const nca = ptr(h, 0x10);
      const control = ptr(h, 0x18);
      const n = await memory.read(nca, 0x30);
      fields = [
        {
          object: root,
          address: root + 0x30,
          identity: h.subarray(0, 8).toString('hex'),
          original: h.subarray(0x30, 0x38).toString('hex'),
        },
        {
          object: nca,
          address: nca + 0x20,
          identity: n.subarray(0, 8).toString('hex'),
          original: n.subarray(0x20, 0x28).toString('hex'),
        },
      ];

      for (const field of fields) {
        await memory.write(field.address, Buffer.from(field.original, 'hex'), u64(owner));
      }

      storage = await a.fs.open(client, 'Open composed current-program RomFS', 200);
      return storage;
    }, () => restoreProgramRoot(memory, owner, fields));
  } catch (error) {
    await cleanup([() => storage && a.fs.close(storage)], error);
  }
}

const normalized = (rows) => [...rows].sort((a, b) => a.programId.localeCompare(b.programId));
const same = (a, b) => JSON.stringify(normalized(a)) === JSON.stringify(normalized(b));

function mapBytes(rows) {
  const bytes = Buffer.alloc(rows.length * 0x20);
  rows.forEach((row, i) => {
    idBytes(row.programId).copy(bytes, i * 0x20);
    idBytes(row.applicationId).copy(bytes, i * 0x20 + 8);
    bytes[i * 0x20 + 16] = row.programIndex;
    bytes[i * 0x20 + 17] = row.flags;
  });
  return bytes;
}

async function programMapReader(attachment) {
  const { memory } = await registryReader(attachment);
  // actually grab the address we need instead of guessing at it
  const nca = await memory.pointer(attachment.proof.rootAddress + 0x10);
  const resolver = await memory.pointer(nca + 0x18);
  const manager = await memory.pointer(resolver + 0x58);
  const head = manager + 0x50;

  async function entries() {

    const header = await memory.read(head, 16);
    const seen = new Set();
    const rows = [];
    const captures = [];
    let node = Number(header.readBigUInt64LE(8));
    let previous = head;

    while (node !== head) {
      seen.add(node);

      const bytes = await memory.read(node, 0x28);
      rows.push({
        programId: bytes.readBigUInt64LE(0x10).toString(16).padStart(16, '0'),
        applicationId: bytes.readBigUInt64LE(0x18).toString(16).padStart(16, '0'),
        programIndex: bytes[0x20],
        flags: bytes[0x21],
      });
      captures.push({ node, bytes });
      previous = node;
      node = Number(bytes.readBigUInt64LE(8));
    }

    for (const item of captures) {
    }

    return normalized(rows);
  }

  return { entries };
}

async function withProgramIndexMap({ attachment: a, title, runtimeProgramId, programIndex = 0, operation }) {
  const reader = await programMapReader(a);
  const before = await reader.entries();
  const existing = before.find((row) => row.programId === runtimeProgramId);
  if (existing && existing.applicationId === title && existing.programIndex === programIndex) return operation();
  const mapping = { programId: runtimeProgramId, applicationId: title, programIndex, flags: existing?.flags || 0 };
  // fs 810 counts 0 as a no-op
  const active = normalized([...before.filter(row => row.programId !== runtimeProgramId), mapping]);
  let attempted = false;
  async function register(rows, label) {
    const bytes = mapBytes(rows);
    const address = a.s.base + 0x10000;
    await a.s.write(address, bytes);
    const input = Buffer.alloc(4);
    input.writeInt32LE(rows.length);
    success(await a.s.ipc(label, a.root, 810, input, {
      send: [{ address, size: bytes.length, mode: 0 }],
    }), label);
  }
  return withCleanup(async () => {
    attempted = true;
    await register(active, 'Register owned original-program mapping');
    return operation();
  }, async () => {
    if (!attempted) return;
    const current = await reader.entries();
    if (same(current, before)) return;
    await register(before, 'Restore original program mappings');
  });
}

const openProgramRomfs = options => openProgramContent(options);
const openProgramManual = options => openProgramContent({ ...options, manual: true });

module.exports = { openProgramRomfs, openProgramManual, withProgramIndexMap };
