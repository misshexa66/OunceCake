const path = require('node:path');

const MEMBER_BYTES = 64;
const OUTPUT_BYTES = 0x40000;
const MAX_OCTAL_SIZE = 0o77777777777n;
const padded = size => (size + 511n) & ~511n;

function paxRecord(key, value) {
  const body = ' ' + key + '=' + value + '\n';
  let bytes = Buffer.byteLength(body) + 1;

  for (;;) {
    const next = Buffer.byteLength(body) + String(bytes).length;
    if (next === bytes) return String(bytes) + body;
    bytes = next;
  }
}

function headerPath(filename) {
  if (!/^[\x20-\x7e]+$/.test(filename)) return null;
  if (filename.length <= 100) return { name: filename, prefix: '' };

  for (let split = filename.lastIndexOf('/'); split > 0; split = filename.lastIndexOf('/', split - 1)) {
    const name = filename.slice(split + 1);
    if (split <= 155 && name.length > 0 && name.length <= 100) {
      return { name, prefix: filename.slice(0, split) };
    }
  }

  return null;
}

function planTar(view) {
  const root = path.posix.basename(view.path);
  const filesystem = view.kind === 'filesystem' || view.kind === 'deferred-filesystem';
  const compare = (a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path));
  const directories = view.entries.filter(item => item.type === 'directory').sort(compare);
  const files = view.entries.filter(item => item.type === 'file').sort(filesystem ? compare : (a, b) => {
    const offset = BigInt(a.offset ?? 0) - BigInt(b.offset ?? 0);
    return offset < 0n ? -1 : offset > 0n ? 1 : compare(a, b);
  });

  let position = 0n;
  const members = [{ path: '', type: 'directory' }, ...directories, ...files].map((item, index) => {
    const directory = item.type === 'directory';
    const filename = root + item.path + (directory ? '/' : '');
    const size = directory ? 0n : BigInt(item.size);
    const header = headerPath(filename);
    let pax = header ? '' : paxRecord('path', filename);
    if (size > MAX_OCTAL_SIZE) pax += paxRecord('size', size);

    const paxBytes = Buffer.byteLength(pax);
    const end = position + 512n + (paxBytes ? 512n + padded(BigInt(paxBytes)) : 0n) + padded(size);
    const member = {
      start: position, end, size,
      offset: directory || filesystem ? 0n : BigInt(item.offset ?? 0),
      name: header?.name ?? 'PaxEntry' + index + (directory ? '/' : ''),
      prefix: header?.prefix ?? '',
      sourcePath: filesystem && !directory ? item.path : '',
      pax, paxBytes, directory,
    };

    position = end;
    return member;
  });

  return { members, size: position + 1024n };
}

module.exports = { planTar, MEMBER_BYTES, OUTPUT_BYTES };
