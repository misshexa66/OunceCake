const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const zlib = require('node:zlib');
const { pipeline } = require('node:stream/promises');
const { promisify } = require('node:util');
const { createHash } = require('node:crypto');
const { FtpClient } = require('./ftp-client.cjs');

// writes a .nup (see the NUP spec) straight from our own ftp server
// romfs comes down as one big image per mount (<prefix>/romfs.img) and gets cut up here,
// so we don't pay the per file ftp overhead thousands of times

const NONE = 0xffffffff;
const KIND = { base: 0, update: 1, addon: 2 };
const STANDALONE_UPDATE = 1;
const CODEC = { raw: 0, zstd: 1 };
const MEMORY_LIMIT = 64 * 1024 * 1024; // files bigger than this get spilled to disk while they come in
const ZSTD = { params: { [zlib.constants.ZSTD_c_compressionLevel]: 3 } };
const zstdCompress = promisify(zlib.zstdCompress);

const align16 = (n) => Math.ceil(n / 16) * 16;
const EMPTY_SHA = createHash('sha256').digest();

// spec wants the content size in the frame header
function frameHasSize(frame) {
  if (frame.length < 5 || frame.readUInt32LE(0) !== 0xfd2fb528) return false;
  return frame[4] >> 6 !== 0 || ((frame[4] >> 5) & 1) === 1;
}

async function writeAll(handle, buffer, position) {
  for (let done = 0; done < buffer.length; ) {
    const { bytesWritten } = await handle.write(buffer, done, buffer.length - done, position + done);
    done += bytesWritten;
  }
}

class Content {
  constructor(size, spillDir) {
    this.size = size;
    this.spillDir = spillDir;
    this.hash = createHash('sha256');
    this.chunks = [];
    this.spill = null;
    this.spillHandle = null;
    this.spillAt = 0;
  }

  async add(chunk) {
    this.hash.update(chunk);

    if (this.size <= MEMORY_LIMIT) {
      this.chunks.push(chunk);
      return;
    }

    if (!this.spillHandle) {
      this.spill = path.join(this.spillDir, 'spill-' + process.hrtime.bigint());
      this.spillHandle = await fsp.open(this.spill, 'w');
    }

    await writeAll(this.spillHandle, chunk, this.spillAt);
    this.spillAt += chunk.length;
  }

  async seal() {
    if (this.spillHandle) await this.spillHandle.close();
    this.spillHandle = null;
    this.sha = this.hash.digest();
  }

  async discard() {
    this.chunks = [];
    if (this.spill) await fsp.rm(this.spill, { force: true });
  }
}

class Blob {
  constructor(handle, start) {
    this.handle = handle;
    this.cursor = start;
    this.extents = new Map();
    this.stats = { files: 0, bytes: 0, stored: 0, deduped: 0 };
  }

  async store(content) {
    this.stats.files++;
    this.stats.bytes += content.size;

    if (!content.size) return { offset: 0, extentSize: 0, codec: CODEC.raw, sha: EMPTY_SHA };

    const key = content.sha.toString('hex') + ':' + content.size;
    const known = this.extents.get(key);

    if (known) {
      this.stats.deduped += content.size;
      return known;
    }

    const offset = align16(this.cursor);
    const stored = content.spill ? await this.storeSpilled(content, offset) : await this.storeMemory(content, offset);
    const result = { offset, ...stored, sha: content.sha };

    this.cursor = offset + stored.extentSize;
    this.stats.stored += stored.extentSize;
    this.extents.set(key, result);
    return result;
  }

  async storeMemory(content, offset) {
    const data = content.chunks.length === 1 ? content.chunks[0] : Buffer.concat(content.chunks, content.size);
    let packed = null;

    try {
      packed = await zstdCompress(data, { ...ZSTD, pledgedSrcSize: data.length });
    } catch {}

    if (packed && packed.length < data.length && frameHasSize(packed)) {
      await writeAll(this.handle, packed, offset);
      return { extentSize: packed.length, codec: CODEC.zstd };
    }

    await writeAll(this.handle, data, offset);
    return { extentSize: data.length, codec: CODEC.raw };
  }

  async storeSpilled(content, offset) {
    const compressor = zlib.createZstdCompress({ ...ZSTD, pledgedSrcSize: content.size });
    const feeding = pipeline(fs.createReadStream(content.spill), compressor);
    let written = 0;
    let usable = true;
    let first = null;

    for await (const out of compressor) {
      if (written + out.length >= content.size) {
        usable = false;
        break;
      }

      first ??= out;
      await writeAll(this.handle, out, offset + written);
      written += out.length;
    }

    if (usable) await feeding;
    else await feeding.catch(() => {});

    if (usable && frameHasSize(first || Buffer.alloc(0))) return { extentSize: written, codec: CODEC.zstd };

    // didn't get smaller, store it raw instead (overwrites whatever we wrote)
    let at = 0;
    for await (const chunk of fs.createReadStream(content.spill)) {
      await writeAll(this.handle, chunk, offset + at);
      at += chunk.length;
    }
    return { extentSize: at, codec: CODEC.raw };
  }
}

function directory(name) {
  return { type: 'directory', name, children: new Map() };
}

function child(parent, name, make) {
  let node = parent.children.get(name);

  if (!node) {
    node = make();
    parent.children.set(name, node);
  } else if (node.type !== make().type) {
    throw new Error('NUP tree has a file/directory collision at ' + name);
  }

  return node;
}

// '/a/b/c' -> parent dir of c, created as needed
function parentOf(root, filename) {
  const parts = filename.split('/').filter(Boolean);
  let at = root;

  for (const part of parts.slice(0, -1)) at = child(at, part, () => directory(part));

  return { at, name: parts[parts.length - 1] };
}

function addEntries(root, entries) {
  const files = [];

  for (const entry of entries) {
    const { at, name } = parentOf(root, entry.path);

    if (entry.type === 'directory') {
      child(at, name, () => directory(name));
      continue;
    }

    const record = { type: 'file', name, size: entry.size, result: null };

    if (at.children.has(name)) throw new Error('NUP tree has a duplicate path: ' + entry.path);

    at.children.set(name, record);
    files.push({ ...entry, record });
  }

  return files;
}

function planPackages(views, title) {
  const groups = new Map();

  for (const view of views) {
    const prefix = path.posix.dirname(view.path);
    if (!groups.has(prefix)) groups.set(prefix, { prefix });
    groups.get(prefix)[path.posix.basename(view.path)] = view;
  }

  const packages = [...groups.values()].map((group) => {
    const source = (group.romfs || group.exefs).source;
    const kind =
      group.prefix === '/base' ? KIND.base : group.prefix.startsWith('/dlc/') ? KIND.addon : KIND.update;

    const root = directory('');
    const pack = {
      prefix: group.prefix,
      kind,
      titleId: kind === KIND.base ? title : source.contentTitle || title,
      version: source.version >>> 0,
      flags: 0,
      root,
      exefsDir: null,
      romfsDir: null,
      exefsFiles: [],
      romfs: null,
      meta: [],
    };

    if (group.exefs) {
      pack.exefsDir = child(root, 'exefs', () => directory('exefs'));
      pack.exefsFiles = addEntries(pack.exefsDir, group.exefs.entries).map((file) => ({
        ...file,
        ftpPath: group.exefs.path + file.path,
      }));
    }

    if (group.romfs) {
      pack.romfsDir = child(root, 'romfs', () => directory('romfs'));
      pack.romfs = {
        ftpPath: group.romfs.path + '.img',
        size: group.romfs.size,
        files: addEntries(pack.romfsDir, group.romfs.entries),
      };
    }

    return pack;
  });

  packages.sort((a, b) => a.kind - b.kind || a.titleId.localeCompare(b.titleId) || a.version - b.version);

  if (!packages.some((pack) => pack.kind === KIND.base)) {
    for (const pack of packages) if (pack.kind === KIND.update) pack.flags |= STANDALONE_UPDATE;
  }

  return packages;
}

function tlv(type, payload) {
  const header = Buffer.alloc(8);
  header.writeUInt16LE(type, 0);
  header.writeUInt32LE(payload.length, 4);
  return Buffer.concat([header, payload]);
}

// same records (sorted by type) as the reference packer (a55uka/nup), so `nup edit` etc. treat them the same
function buildMeta(pack, { npdm, mainHead, name }) {
  const records = [];

  if (npdm) records.push(tlv(0x0001, npdm));

  if (pack.kind === KIND.base && name) records.push(tlv(0x0005, Buffer.from(name)));

  if (mainHead && mainHead.length >= 0x60) {
    const magic = mainHead.toString('latin1', 0, 4);
    const nro = mainHead.toString('latin1', 0x10, 0x14);
    if (magic === 'NSO0' || nro === 'NRO0') records.push(tlv(0x0007, mainHead.subarray(0x40, 0x60)));
  }

  records.push(tlv(0x0008, Buffer.from('OunceCake')));
  return Buffer.concat(records);
}

// program id out of the npdm's ACI0, which is what the reference packer uses as title_id
function npdmProgramId(npdm) {
  const at = npdm ? npdm.indexOf('ACI0') : -1;
  if (at < 0 || at + 0x18 > npdm.length) return null;
  const id = npdm.readBigUInt64LE(at + 0x10);
  return id ? id.toString(16).padStart(16, '0') : null;
}

// assigns dir/file indices and children slots, breadth first so every dir's children are contiguous
function layout(packages) {
  const dirs = [];
  const files = [];
  const children = [];
  const strings = new Map();
  const pool = [];
  let poolBytes = 0;

  const string = (value) => {
    if (!strings.has(value)) {
      const bytes = Buffer.from(value);
      strings.set(value, { offset: poolBytes, length: bytes.length });
      pool.push(bytes);
      poolBytes += bytes.length;
    }

    return strings.get(value);
  };

  const queue = [];
  const enqueue = (dir) => {
    dir.index = dirs.length;
    dirs.push(dir);
    queue.push(dir);
  };

  for (const pack of packages) enqueue(pack.root);

  for (let at = 0; at < queue.length; at++) {
    const dir = queue[at];
    const sorted = [...dir.children.values()].sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));

    dir.firstChild = children.length;
    dir.childCount = sorted.length;

    for (const node of sorted) {
      if (node.type === 'directory') enqueue(node);
      else {
        node.index = files.length;
        files.push(node);
      }

      children.push(node);
    }
  }

  for (const node of [...dirs, ...files]) node.string = string(node.name);

  const offsets = {};
  offsets.packages = 0x30;
  offsets.dirs = offsets.packages + packages.length * 0x40;
  offsets.files = offsets.dirs + dirs.length * 0x18;
  offsets.children = offsets.files + files.length * 0x50;
  offsets.pool = offsets.children + children.length * 4;
  const size = align16(offsets.pool + poolBytes);

  return { dirs, files, children, pool: Buffer.concat(pool, poolBytes), offsets, size };
}

function encodeToc(packages, plan) {
  const { dirs, files, children, pool, offsets } = plan;
  const toc = Buffer.alloc(plan.size);
  const id = (node) => (node.type === 'directory' ? node.index : dirs.length + node.index);

  toc.write('TOC\x01', 0, 'latin1');
  toc.writeUInt32LE(packages.length, 4);
  toc.writeBigUInt64LE(BigInt(dirs.length), 0x08);
  toc.writeBigUInt64LE(BigInt(files.length), 0x10);
  toc.writeBigUInt64LE(BigInt(offsets.pool), 0x18);
  toc.writeBigUInt64LE(BigInt(pool.length), 0x20);

  packages.forEach((pack, i) => {
    const at = offsets.packages + i * 0x40;
    toc.writeBigUInt64LE(BigInt('0x' + pack.titleId), at);
    toc.writeUInt32LE(pack.root.index, at + 0x08);
    toc.writeUInt32LE(pack.exefsDir ? pack.exefsDir.index : NONE, at + 0x0c);
    toc.writeUInt32LE(pack.romfsDir ? pack.romfsDir.index : NONE, at + 0x10);
    toc.writeUInt32LE(pack.version, at + 0x14);
    toc[at + 0x18] = pack.kind;
    toc[at + 0x19] = pack.flags;
    toc.writeBigUInt64LE(BigInt(pack.metaOffset || 0), at + 0x20);
    toc.writeUInt32LE(pack.metaSize || 0, at + 0x28);
  });

  dirs.forEach((dir, i) => {
    const at = offsets.dirs + i * 0x18;
    toc.writeUInt32LE(dir.string.offset, at);
    toc.writeUInt32LE(dir.string.length, at + 4);
    toc.writeUInt32LE(dir.firstChild, at + 8);
    toc.writeUInt32LE(dir.childCount, at + 12);
  });

  files.forEach((file, i) => {
    const at = offsets.files + i * 0x50;
    if (!file.result) throw new Error('NUP file was never written: ' + file.name);
    toc.writeUInt32LE(file.string.offset, at);
    toc.writeUInt32LE(file.string.length, at + 4);
    toc.writeBigUInt64LE(BigInt(file.size), at + 0x08);
    toc.writeBigUInt64LE(BigInt(file.result.offset), at + 0x10);
    toc.writeBigUInt64LE(BigInt(file.result.extentSize), at + 0x18);
    file.result.sha.copy(toc, at + 0x20);
    toc[at + 0x40] = file.result.codec;
  });

  children.forEach((node, i) => toc.writeUInt32LE(id(node), offsets.children + i * 4));
  pool.copy(toc, offsets.pool);
  return toc;
}

function encodeSuperblock(packages, { toc, blobOffset, fileSize }) {
  const block = Buffer.alloc(0x80);
  Buffer.from([0x4e, 0x55, 0x50, 0x01]).copy(block, 0);
  block.writeUInt16LE(0x80, 0x04);
  block.writeUInt16LE(1, 0x06);
  block.writeBigUInt64LE(0x80n, 0x08);
  block.writeBigUInt64LE(BigInt(toc.length), 0x10);
  createHash('sha256').update(toc).digest().copy(block, 0x18);
  block.writeBigUInt64LE(BigInt(blobOffset), 0x38);
  block.writeBigUInt64LE(BigInt(fileSize), 0x40);
  block.writeUInt32LE(packages.length, 0x48);

  const uuid = createHash('sha256');
  for (const pack of packages) {
    const key = Buffer.alloc(13);
    key.writeBigUInt64LE(BigInt('0x' + pack.titleId), 0);
    key.writeUInt32LE(pack.version, 8);
    key[12] = pack.kind;
    uuid.update(key);
  }
  uuid.digest().copy(block, 0x50, 0, 16);
  return block;
}

const mb = (bytes) => (bytes / 1048576).toFixed(1);

function progress(label, total) {
  const started = Date.now();
  let done = 0;
  let shown = 0;
  let window = { at: started, done: 0, rate: 0 }; // speed over the last few seconds, the average hides slow/fast stretches
  const tty = process.stdout.isTTY;

  const show = (final) => {
    const now = Date.now();
    const seconds = Math.max((now - started) / 1000, 0.001);
    if (now - window.at >= 3000) window = { at: now, done, rate: ((done - window.done) * 1000) / (now - window.at) };
    const rate = final || !window.rate ? '' : mb(window.rate) + ' MB/s now, ';
    const line = '  ' + label + '  ' + mb(done) + '/' + mb(total) + ' MB  ' + rate + mb(done / seconds) + ' MB/s avg';
    if (tty) process.stdout.write('\r' + line + '\x1b[K' + (final ? '\n' : ''));
    else if (final) console.log(line);
  };

  return {
    add(bytes) {
      done += bytes;
      if (Date.now() - shown > 500) {
        shown = Date.now();
        show(false);
      }
    },
    end: () => show(true),
  };
}

// pulls one romfs image and feeds every file in it to the blob as its bytes go past
async function pullImage(client, romfs, blob, spillDir, shouldStop) {
  const groups = new Map();

  for (const file of romfs.files) {
    if (!file.size) {
      file.record.result = await blob.store({ size: 0 });
      continue;
    }

    const key = file.offset + ':' + file.size;
    if (!groups.has(key)) groups.set(key, { offset: file.offset, size: file.size, records: [] });
    groups.get(key).records.push(file.record);
  }

  const pending = [...groups.values()].sort((a, b) => a.offset - b.offset || a.size - b.size);
  const active = [];
  const meter = progress(romfs.ftpPath, romfs.size);
  let position = 0;
  let next = 0;

  await client.retrieve(romfs.ftpPath, romfs.size, async (chunk) => {
    if (shouldStop()) throw Object.assign(new Error('Cancelled'), { code: 'FTP_CANCELLED' });

    const start = position;
    const end = position + chunk.length;
    position = end;

    while (next < pending.length && pending[next].offset < end) {
      const group = pending[next++];
      group.content = new Content(group.size, spillDir);
      active.push(group);
    }

    for (const group of active) {
      const from = Math.max(start, group.offset);
      const to = Math.min(end, group.offset + group.size);
      if (to > from) await group.content.add(chunk.subarray(from - start, to - start));
    }

    for (let i = 0; i < active.length; ) {
      const group = active[i];

      if (group.offset + group.size > end) {
        i++;
        continue;
      }

      active.splice(i, 1);
      await group.content.seal();
      const result = await blob.store(group.content);
      await group.content.discard();
      group.content = null;
      for (const record of group.records) record.result = result;
    }

    meter.add(chunk.length);
  });

  meter.end();

  if (active.length || next < pending.length) throw new Error(romfs.ftpPath + ' ended before all of its files');
}

async function packNup({ host, port, views, title, name, output, shouldStop = () => false }) {
  const packages = planPackages(views, title);
  const partial = output + '.part';
  const spillDir = await fsp.mkdtemp(path.join(path.dirname(output), '.ouncecake-'));
  const client = await FtpClient.open(host, port);
  let handle;

  try {
    const plan = layout(packages);
    const blobOffset = align16(0x80 + plan.size);
    handle = await fsp.open(partial, 'w');
    const blob = new Blob(handle, blobOffset);

    for (const pack of packages) {
      let npdm = null;
      let mainHead = null;

      for (const file of pack.exefsFiles) {
        if (shouldStop()) throw Object.assign(new Error('Cancelled'), { code: 'FTP_CANCELLED' });

        const content = new Content(file.size, spillDir);
        const head = [];
        await client.retrieve(file.ftpPath, file.size, async (chunk) => {
          if (file.path === '/main.npdm') head.push(chunk);
          else if (file.path === '/main' && Buffer.concat(head).length < 0x60) head.push(chunk);
          await content.add(chunk);
        });
        await content.seal();
        file.record.result = await blob.store(content);
        await content.discard();

        if (file.path === '/main.npdm') npdm = Buffer.concat(head);
        if (file.path === '/main') mainHead = Buffer.concat(head).subarray(0, 0x60);
      }

      if (pack.exefsFiles.length) console.log('  ' + pack.prefix + '/exefs  ' + pack.exefsFiles.length + ' files');
      if (pack.kind !== KIND.addon) pack.titleId = npdmProgramId(npdm) || pack.titleId;
      pack.metaBlock = buildMeta(pack, { npdm, mainHead, name });
    }

    for (const pack of packages) {
      if (pack.romfs) await pullImage(client, pack.romfs, blob, spillDir, shouldStop);
    }

    // meta blocks are the tail of the file, after every extent (`nup edit` relies on that)
    let fileSize = Math.max(blob.cursor, blobOffset);
    for (const pack of packages) {
      pack.metaOffset = fileSize;
      pack.metaSize = pack.metaBlock.length;
      await writeAll(handle, pack.metaBlock, fileSize);
      fileSize += pack.metaSize;
    }

    const toc = encodeToc(packages, plan);
    await writeAll(handle, toc, 0x80);
    await writeAll(handle, encodeSuperblock(packages, { toc, blobOffset, fileSize }), 0);
    await handle.truncate(fileSize);
    await handle.close();
    handle = null;
    await fsp.rename(partial, output);

    const { files, bytes, deduped } = blob.stats;
    console.log(
      'Wrote ' + output + ': ' + packages.length + ' packages, ' + files + ' files, ' +
        mb(bytes) + ' MB of content -> ' + mb(fileSize) + ' MB (' + mb(deduped) + ' MB deduped)',
    );
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fsp.rm(partial, { force: true });
    throw error;
  } finally {
    await client.close();
    await fsp.rm(spillDir, { recursive: true, force: true });
  }
}

module.exports = { packNup, planPackages, layout, encodeToc, encodeSuperblock };
