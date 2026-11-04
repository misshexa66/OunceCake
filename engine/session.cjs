const fs = require('node:fs/promises');
const path = require('node:path');
const net = require('node:net');
const { success, cleanup } = require('./protocol.cjs');

function requestOnce(socketPath, command) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let input = '';
    socket.setEncoding('utf8');
    socket.setTimeout(60000, () => {
      socket.destroy(new Error('Memory request timed out; it was not replayed'));
    });
    socket.on('error', reject);
    socket.on('connect', () => socket.write(JSON.stringify(command) + '\n'));
    socket.on('data', (part) => {
      input += part;

      if (input.length > 16 * 1024 * 1024) socket.destroy(new Error('Memory reply exceeded its limit'));
    });
    socket.on('end', () => {
      try {
        const result = JSON.parse(input);

        if (result.error) throw new Error(result.error);

        resolve(result);
      } catch (error) {
        reject(error);
      }
    });
  });
}

async function request(socketPath, command) {
  const deadline = Date.now() + 3000;

  for (;;) {
    try {
      return await requestOnce(socketPath, command);
    } catch (error) {
      // command sometimes gets rejected because system is busy. just keep shoving the command at it till it works
      if (error.message !== 'Another memory request is active' || Date.now() >= deadline) throw error;

      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}

// some services happily show up with sm, some don't. try both methods
async function openServiceWithFallback({ s, sm, name }) {
  const direct = async () => s.openService(name);

  if (!sm) return direct();

  try {
    const packet = Buffer.alloc(256);
    packet.writeUInt32LE(0x11);
    packet.writeUInt32LE(2, 4);
    packet.write(name, 8);
    await s.write(s.base, packet);

    const transport = await s.call('send', s.base, 4096, sm);

    const reply = await s.readOwned(s.base, 256);

    let at = 8;
    let count = 0;
    let handle;

    if (reply.readUInt32LE(4) >>> 31) {
      const special = reply.readUInt32LE(at);
      at += 4;
      count = (special >>> 5) & 15;

      if (count) {
        handle = reply.readUInt32LE(at);
        at += 4;

        s.handles.add(handle);
      }
    }

    const result = reply.readUInt32LE(at);

    if (!result && count === 1 && handle > 0) return handle;

    const code = result & 0x3fffff;

    if (code === 0x615) return direct();

    throw new Error('SM could not open ' + name + ': 0x' + code.toString(16));
  } catch (error) {
    const message = String(error.message || error);

    if (!/0x615|service unavailable|service not found|SM could not open/i.test(message)) {
      throw error;
    }

    return direct();
  }
}

//attach to run from ns2jb, get handles for it's stuff
async function attachGame(run) {
  const engine = path.join(run, 'switch2');
  const read = (file) => fs.readFile(file, 'utf8').then(JSON.parse);
  const current = await read(path.join(engine, 'current-acquisition.json'));
  const proof = await read(path.join(engine, 'ro/root/current-root.json'));
  const { Session, live } = require(path.join(engine, 'app/session.cjs'));
  const domain = require(path.join(engine, 'app/domain.cjs'));
  const filesystem = require(path.join(engine, 'app/filesystem.cjs'));
  const original = await request(current.socketPath, { command: 'root-native-info' });
  const sm = original.services?.find((item) => item.sm)?.sm;

  const s = new Session('game-attach-' + Date.now(), 0x80000);
  s.record = async () => {};
  try {
    await s.initialize();
    const root = domain.oneHandle(success(await domain.send(
      s, 'Clone held promoted FS root', proof.rootHandle, domain.wire.control(2),
    ), 'Clone held promoted FS root'));
    const services = new Map();
    async function service(name) {
      const existing = services.get(name);
      if (s.handles.has(existing)) return existing;
      const handle = await openServiceWithFallback({ s, sm, name });
      services.set(name, handle);
      return handle;
    }
    return { s, root, domain, filesystem, service, run, live, Session, current, proof,
      close: async () => { if (!s.threads.size) await s.cleanup(); } };
  } catch (error) {
    await cleanup([() => s.cleanup()], error);
  }
}

module.exports = { attachGame };
