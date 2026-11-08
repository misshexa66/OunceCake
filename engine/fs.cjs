const { success, pathRequest, cleanup } = require('./protocol.cjs');

function createFs(attachment) {
  const { s, domain, filesystem } = attachment;
  let root;
  let program;

  async function convert(handle, label) {
    const reply = success(await domain.send(s, label, handle, domain.wire.control(0)), label);
    return { handle, objectId: reply.data.readUInt32LE() };
  }

  async function call(object, label, command, input = Buffer.alloc(0), options = {}, dataSize = 0) {
    return success(await domain.send(s, label, object.handle,
      domain.wire.domain(object.objectId, command, input, options), { domain: true, dataSize }), label);
  }

  const child = (parent, reply) => ({ handle: parent.handle, objectId: reply.objects[0] });

  async function open(parent, label, command, input, options) {
    return child(parent, await call(parent, label, command, input, options));
  }

  async function openPath(parent, label, command, input, filename) {
    const buffer = Buffer.alloc(0x301);
    buffer.write(filename);
    await s.write(s.base + 0x2000, buffer);
    const packet = domain.wire.domain(parent.objectId, command, input);
    packet.writeUInt32LE(4 | (1 << 16));
    pathRequest(command, input, s.base + 0x2000).copy(packet, 8, 8, 16);
    return child(parent, success(await domain.send(s, label, parent.handle, packet,
      { domain: true }), label));
  }

  async function close(object) {
    await domain.closeObject(s, { handle: object.handle, label: 'Game FS' }, object.objectId);
  }

  async function size(object) {
    return (await call(object, 'Game object size', 4, undefined, undefined, 8)).data.readBigUInt64LE();
  }

  async function read(object, offset, length, file = false) {
    const input = Buffer.alloc(file ? 24 : 16);
    input.writeBigUInt64LE(BigInt(offset), file ? 8 : 0);
    input.writeBigUInt64LE(BigInt(length), file ? 16 : 8);
    const reply = await call(object, file ? 'Read game file' : 'Read game storage', 0, input,
      { receive: [{ address: s.base + 0x6000, size: length, mode: 1 }] }, file ? 8 : 0);
    const count = file ? Number(reply.data.readBigUInt64LE()) : length;
    return filesystem.verifiedBytes(s, s.base + 0x6000, count, { ...object, offset });
  }

  return {
    convert, call, open, openPath, close, size, read,
    root: async () => {
      if (!root) {
        const handle = domain.oneHandle(success(await domain.send(s, 'Clone game mount FS root',
          attachment.root, domain.wire.control(2)), 'Clone game mount FS root'));
        try { root = await convert(handle, 'Convert game mount FS root'); }
        catch (error) { await cleanup([() => s.close(handle)], error); }
      }
      return root;
    },
    program: async () => {
      if (!program) {
        const opened = await domain.openDomain(s, 'Owned update program FS');
        program = { handle: opened.handle, objectId: opened.root };
      }
      return program;
    },
  };
}

module.exports = { createFs };
