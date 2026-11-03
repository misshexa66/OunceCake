const net = require('node:net');

// tiny ftp client, just enough to pull files back off our own server

const REPLY_TIMEOUT = 60000;
const DONE_TIMEOUT = 30000; // how long to wait for "226" once all the data is in
const NOOP_EVERY = 30000;

function connect(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    socket.setNoDelay(true);
    socket.setTimeout(30000, () => socket.destroy(new Error('Timed out connecting to ' + host + ':' + port)));
    socket.once('error', reject);
    socket.once('connect', () => {
      socket.setTimeout(0);
      socket.removeAllListeners('timeout');
      socket.removeListener('error', reject);
      resolve(socket);
    });
  });
}

const timedOut = (what) => Object.assign(new Error('Timed out waiting for the FTP server to answer ' + what), {
  code: 'FTP_TIMEOUT',
});

class FtpClient {
  constructor(host, port) {
    this.host = host;
    this.port = port;
  }

  static async open(host, port) {
    const client = new FtpClient(host, port);
    await client.reconnect();
    return client;
  }

  // the control connection sits idle for the whole of a big transfer and wsl/windows networking
  // has been seen silently dropping it, so we can swap in a fresh one when that happens
  async reconnect() {
    this.socket?.destroy();
    const socket = await connect(this.host, this.port);

    this.socket = socket;
    this.input = '';
    this.replies = [];
    this.waiting = [];
    this.failure = null;
    this.current = null;
    this.noops = 0;

    socket.setKeepAlive(true, 15000);
    socket.setEncoding('utf8');
    socket.on('data', (part) => this.socket === socket && this.receive(part));
    socket.on('error', (error) => this.socket === socket && this.fail(error));
    socket.on('close', () => this.socket === socket && this.fail(new Error('FTP control connection closed')));

    await this.expect(null, [220]);
    await this.expect('TYPE I', [200]);
  }

  receive(part) {
    this.input += part;
    let end;

    while ((end = this.input.indexOf('\n')) >= 0) {
      const line = this.input.slice(0, end).replace(/\r$/, '');
      this.input = this.input.slice(end + 1);

      // multi line replies look like "211-..." up to "211 ..."
      if (this.current) {
        this.current.lines.push(line);
        if (line.startsWith(this.current.code + ' ')) this.finish(this.current);
        continue;
      }

      const match = /^(\d{3})([ -])/.exec(line);
      if (!match) continue;

      const reply = { code: Number(match[1]), lines: [line] };
      if (match[2] === '-') this.current = reply;
      else this.finish(reply);
    }
  }

  finish(reply) {
    this.current = null;
    reply.text = reply.lines.join('\n');

    // answers to our keepalive NOOPs, they show up after the transfer's own reply
    if (this.noops && reply.code === 200) {
      this.noops--;
      return;
    }

    const next = this.waiting.shift();
    if (next) next.resolve(reply);
    else this.replies.push(reply);
  }

  fail(error) {
    if (this.failure) return;
    this.failure = error;
    for (const next of this.waiting.splice(0)) next.reject(error);
  }

  reply(what, timeout = REPLY_TIMEOUT) {
    if (this.replies.length) return Promise.resolve(this.replies.shift());
    if (this.failure) return Promise.reject(this.failure);

    return new Promise((resolve, reject) => {
      const waiter = {
        resolve: (reply) => {
          clearTimeout(timer);
          resolve(reply);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
      const timer = setTimeout(() => {
        this.waiting.splice(this.waiting.indexOf(waiter), 1);
        reject(timedOut(what));
      }, timeout);
      this.waiting.push(waiter);
    });
  }

  async expect(command, codes, timeout) {
    if (command !== null) this.socket.write(command + '\r\n');
    const reply = await this.reply(command || 'the greeting', timeout);

    if (!codes.includes(reply.code)) {
      throw new Error('FTP ' + (command || 'greeting') + ' failed: ' + reply.text);
    }

    return reply;
  }

  // streams a file through onChunk (awaited, so slow consumers slow the transfer down instead of eating ram)
  async retrieve(filename, size, onChunk) {
    const passive = await this.expect('EPSV', [229]);
    const port = Number(/\(\|\|\|(\d+)\|\)/.exec(passive.text)?.[1]);
    if (!port) throw new Error('FTP EPSV reply was not understood: ' + passive.text);

    const data = await connect(this.host, port);
    data.on('error', () => {}); // surfaces through the for await below instead
    data.setTimeout(60000, () => data.destroy(new Error('FTP data connection stalled on ' + filename)));

    let received = 0;
    let keepalive;

    try {
      await this.expect('RETR ' + filename, [150]);

      // the server only reads these once the transfer is done, but they keep the connection alive
      keepalive = setInterval(() => {
        this.noops++;
        this.socket.write('NOOP\r\n');
      }, NOOP_EVERY);

      for await (const chunk of data) {
        received += chunk.length;
        if (received > size) throw new Error('FTP sent more data than expected for ' + filename);
        await onChunk(chunk);
      }
    } finally {
      clearInterval(keepalive);
      data.destroy();
    }

    try {
      await this.expect(null, [226], DONE_TIMEOUT);
    } catch (error) {
      // every byte made it, so only the control connection died. carry on with a new one
      if (error.code !== 'FTP_TIMEOUT' || received !== size) throw error;
      console.warn('\n  (FTP control connection went quiet after ' + filename + ', reconnecting)');
      await this.reconnect();
    }

    if (received !== size) {
      throw new Error('FTP transfer of ' + filename + ' was short: ' + received + ' of ' + size + ' bytes');
    }
  }

  async close() {
    if (this.failure) return this.socket.destroy();

    try {
      this.socket.write('QUIT\r\n');
      await this.reply('QUIT', 1000);
    } catch {}

    this.socket.destroy();
  }
}

module.exports = { FtpClient };
