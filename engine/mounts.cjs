const path = require('node:path');
const { TextDecoder } = require('node:util');
const { success, pathRequest, idBytes, resultError, cleanup, closeHandles, throwIfCancelled } = require('./protocol.cjs');
const { discoverBase, discoverUpdates, discoverDlc, discoverDataPatches, resolveContent } = require('./content.cjs');
const { createProgramMounts, prepareInstalledLicense } = require('./program.cjs');
const { openDlcPatch } = require('./dlc.cjs');
const { planTar, MEMBER_BYTES } = require('./tar.cjs');

// ncm mounts + metadata used for getting the ftp server ready

const MAX_CHUNK = 0x40000;
const safeSize = (n) => { // lol, ai put this in. in what situation would this ever happen
  return Number(n);
};

function createGameFiles(attachment) {
  const { openCode, openUpdate, openManualPatch } = createProgramMounts(attachment);
  const originals = new Map();
  const originalManuals = new Map();
  const { s, root, domain, filesystem, service } = attachment;

  const send = async (label, handle, bytes) => success(await domain.send(s, label, handle, bytes), label);

  async function open({ title, storage, section = 'romfs', base, update, dlc, dataPatch, content }) {
    let source;
    let mounted;

    try {
      source = await resolveContent({
        s,
        root,
        domain,
        service,
        title,
        storage,
        base,
        update,
        dlc,
        dataPatch,
        content,
      });

      const { contentPath, attributes } = source;
      const filename = Buffer.alloc(0x301);
      filename.write(contentPath);

      let handle;
      let composed = false;

      const filesystemType = { meta: 5, logo: 2, control: 3, manual: 4, legal: 4 }[section];

      if (update && section === 'manual' && originalManuals.has(source.programIndex)) {
        source.originalSource = originalManuals.get(source.programIndex);
        const originalProgramSource = originals.get(source.programIndex) || originals.get(0);
        const programContent = update.contents.find(item => item.contentType === 1 &&
          item.programIndex === source.programIndex);
        const programSource = programContent
          ? await resolveContent({ s, root, domain, service, title, storage, update, content: programContent })
          : originalProgramSource;
        if (!programSource) throw new Error('No game program found for manual index ' + source.programIndex);
        handle = await openManualPatch({ title, source, originalSource: source.originalSource,
          programSource, originalProgramSource });
        composed = true;
      } else if (filesystemType !== undefined) {
        source.proxyType = filesystemType;
        const input = Buffer.alloc(16);
        input[0] = attributes;
        input.writeUInt32LE(filesystemType, 4);
        idBytes(source.runtimeProgramId).copy(input, 8);
        await s.write(s.base + 0x2000, filename);
        handle = domain.oneHandle(await send('Open game ' + section, root,
          pathRequest(10, input, s.base + 0x2000)));
      } else if (dataPatch) {
        const originalContent = dataPatch.original.contents.find(item =>
          item.contentType === source.contentType && item.programIndex === source.programIndex);
        if (!originalContent) throw new Error('No original DLC content found for index ' + source.programIndex);
        source.originalSource = await resolveContent({
          s, root, domain, service, title,
          storage: dataPatch.original.storage,
          dlc: dataPatch.original,
          content: originalContent,
        });
        handle = source.contentType === 1
          ? await openUpdate({ title, storage, attributes, source, section, originalSource: source.originalSource })
          : await openDlcPatch({ attachment, title, source, originalSource: source.originalSource });
      } else if (update && source.contentType === 1) {
        source.originalSource = originals.get(source.programIndex);
        handle = await openUpdate({
          title, storage, attributes, source, section,
          originalSource: source.originalSource,
        });
      } else if (section === 'exefs') {
        handle = await openCode({ title: source.runtimeProgramId, storage, attributes, source });
      } else {
        // base program archive uses type 1, other nca files (data) use 6
        await s.write(s.base + 0x2000, filename);

        const input = Buffer.alloc(8);
        input[0] = attributes;
        source.proxyType = source.contentType === 2 ? 6 : 1;
        input.writeUInt32LE(source.proxyType, 4);

        handle = domain.oneHandle(
          await send('OpenDataStorageByPath', root, pathRequest(206, input, s.base + 0x2000)),
        );
      }

      mounted = {
        handle,
        kind: section === 'romfs' ? 'storage' : 'filesystem',
        source,
        title,
        composed,
      };

      if (mounted.kind === 'storage') {
        const reply = success(await s.ipc('Game storage size', handle, 4), 'Game storage size');
        mounted.size = safeSize(reply.data.readBigUInt64LE());
      }

      if (base && source.contentType === 1) originals.set(source.programIndex, source);
      if (base && source.contentType === 4) originalManuals.set(source.programIndex, source);
      return mounted;
    } catch (error) {
      if (source) error.source = source;

      await cleanup([() => closeHandles(s, mounted ? [mounted.handle] : [])], error);
    }
  }

  async function list(mount, path, shouldStop) {

    const mode = Buffer.alloc(4);
    mode.writeUInt32LE(3);

    const handle = domain.oneHandle(
      success(await filesystem.pathMethod(s, mount.handle, 9, path, mode), 'Open game directory'),
    );
    const entries = [];

    try {
      for (;;) {
        if (shouldStop()) {
          throw Object.assign(new Error('FTP preparation cancelled'), { code: 'FTP_CANCELLED' });
        }

        const reply = success(
          await s.ipc('Read game directory', handle, 0, Buffer.alloc(0), {
            receive: [{ address: s.base + 0x6000, size: 32 * 0x310, mode: 0 }],
          }),
          'Read game directory',
        );
        const count = safeSize(reply.data.readBigUInt64LE());

        if (!count) return entries;

        const bytes = await filesystem.verifiedBytes(s, s.base + 0x6000, count * 0x310, { directory: path });

        for (let i = 0; i < count; i++) {
          const row = bytes.subarray(i * 0x310, (i + 1) * 0x310);
          const end = row.subarray(0, 0x301).indexOf(0);

          const name = row.subarray(0, end).toString('utf8');
          const type = row[0x304];
          entries.push({
            name,
            type: type === 1 ? 'file' : 'directory',
            size: safeSize(row.readBigUInt64LE(0x308)),
          });
        }
      }
    } finally {
      await s.close(handle);
    }
  }

  async function read(mount, offset, length) {

    const bytes = length ? await filesystem.readStorage(s, mount.handle, offset, length) : Buffer.alloc(0);
    return bytes;
  }

  async function close(mount) {
    await s.close(mount.handle);
  }

  return {
    open,
    list,
    read,
    close,
  };
}

// pc side romfs metadata reader. used for getting the file list together

const utf8 = new TextDecoder('utf-8', { fatal: true });
const NONE = 0xffffffff;
const MAX_METADATA = 64 * 1024 * 1024;

function checkRomfs(ok, why) {
  if (!ok) throw new Error('Invalid RomFS: ' + why);
}

function integer(value) {
  checkRomfs(value <= BigInt(Number.MAX_SAFE_INTEGER), 'offset exceeds numeric precision');
  return Number(value);
}

function name(bytes, root = false) {
  const value = utf8.decode(bytes);
  checkRomfs((root || value.length > 0) && !/[\/\\\0]/.test(value) && !['.', '..'].includes(value), 'entry name');
  return value;
}

async function readRomfs(read, storageSize) {
  checkRomfs(Number.isSafeInteger(storageSize) && storageSize >= 0x50, 'storage size');

  async function exact(offset, length) {
    checkRomfs(
      Number.isSafeInteger(offset) && offset >= 0 && length >= 0 && offset + length <= storageSize,
      'range',
    );

    const parts = [];

    for (let at = 0; at < length; at += 0x40000) {
      const n = Math.min(0x40000, length - at);
      const part = await read(offset + at, n);
      parts.push(part);
    }

    return Buffer.concat(parts);
  }

  const header = await exact(0, 0x50);
  const h = Array.from({ length: 10 }, (_, i) => integer(header.readBigUInt64LE(i * 8)));
  checkRomfs(h[0] === 0x50, 'header size');

  const ranges = [];

  for (let i = 1; i < 9; i += 2) {
    checkRomfs(
      h[i] >= 0x50 &&
        h[i + 1] <= MAX_METADATA &&
        Number.isSafeInteger(h[i] + h[i + 1]) &&
        h[i] + h[i + 1] <= storageSize,
      'metadata extent',
    );
    ranges.push([h[i], h[i] + h[i + 1]]);
  }

  ranges.sort((a, b) => a[0] - b[0]);
  checkRomfs(
    ranges.every((r, i) => !i || r[0] >= ranges[i - 1][1]),
    'overlapping metadata',
  );
  checkRomfs(h[4] >= 24 && h[4] + h[8] <= MAX_METADATA && h[9] >= 0x50 && h[9] <= storageSize, 'metadata budget');

  const dirs = await exact(h[3], h[4]);
  const files = await exact(h[7], h[8]);

  const dirSlots = new Uint8Array(Math.ceil(dirs.length / 4));
  const fileSlots = new Uint8Array(Math.ceil(files.length / 4));

  function entry(table, offset, fixed, root = false) {
    checkRomfs(offset % 4 === 0 && offset + fixed <= table.length, 'entry offset');

    const n = table.readUInt32LE(offset + fixed - 4);
    checkRomfs(n <= 0x300 && offset + fixed + n <= table.length, 'entry length');

    // make sure our offsets for reading point to the *start* of each entry and not somewhere inside one
    const slots = table === dirs ? dirSlots : fileSlots;
    const first = offset / 4;
    const end = Math.ceil((offset + fixed + n) / 4);
    checkRomfs(slots[first] !== 2, 'overlapping entries');

    if (slots[first] !== 1) {
      for (let i = first; i < end; i++) {
        checkRomfs(!slots[i], 'overlapping entries');
      }

      slots.fill(2, first, end);
      slots[first] = 1;
    }

    return {
      name: name(table.subarray(offset + fixed, offset + fixed + n), root),
      bytes: table.subarray(offset, offset + fixed),
    };
  }

  const output = [];
  const stack = [{ offset: 0, path: '/', parent: 0 }];
  const seenDirs = new Set([0]);
  const seenFiles = new Set();

  while (stack.length) {
    const dir = stack.pop();
    const current = entry(dirs, dir.offset, 24, dir.offset === 0);

    if (dir.offset) checkRomfs(current.bytes.readUInt32LE() === dir.parent, 'directory parent');

    let child = current.bytes.readUInt32LE(8);
    let file = current.bytes.readUInt32LE(12);

    while (child !== NONE) {
      checkRomfs(!seenDirs.has(child), 'directory cycle or duplicate');
      seenDirs.add(child);

      const e = entry(dirs, child, 24);
      const childPath = dir.path.replace(/\/$/, '') + '/' + e.name;
      output.push({ path: childPath, type: 'directory', size: 0 });
      stack.push({ offset: child, path: childPath, parent: dir.offset });
      child = e.bytes.readUInt32LE(4);
    }

    while (file !== NONE) {
      checkRomfs(!seenFiles.has(file), 'file cycle or duplicate');
      seenFiles.add(file);

      const e = entry(files, file, 32);
      checkRomfs(e.bytes.readUInt32LE() === dir.offset, 'file parent');

      const relative = integer(e.bytes.readBigUInt64LE(8));
      const size = integer(e.bytes.readBigUInt64LE(16));
      const offset = h[9] + relative;
      checkRomfs(Number.isSafeInteger(offset + size) && offset + size <= storageSize, 'file extent');
      checkRomfs(
        !size || ranges.every(([start, end]) => offset + size <= start || offset >= end),
        'file overlaps metadata',
      );
      output.push({ path: dir.path.replace(/\/$/, '') + '/' + e.name, type: 'file', size, offset });
      file = e.bytes.readUInt32LE(4);
    }
  }

  return output;
}

const MAGIC = Buffer.from('NS2FTPIX');
const HEADER = 64;
const STRIDE = 48;
const checkIndex = (ok, why) => {
  if (!ok) throw new Error('Invalid FTP index: ' + why);
};

function buildIndex(views, { tar = false } = {}) {
  const nodes = [{ path: '/', name: '', parent: 0, type: 'directory', children: [] }];
  const byPath = new Map([['/', 0]]);
  const entries = new Set();
  const members = [];

  function addDirectory(filename) {
    if (byPath.has(filename)) {
      checkIndex(nodes[byPath.get(filename)].type === 'directory', 'file/directory collision');
      return byPath.get(filename);
    }

    const parent = addDirectory(path.posix.dirname(filename));
    const id = nodes.length;
    const node = {
      path: filename,
      name: path.posix.basename(filename),
      parent,
      type: 'directory',
      children: [],
    };
    nodes.push(node);
    byPath.set(filename, id);
    nodes[parent].children.push(id);
    return id;
  }

  const strings = [];
  const stringsByValue = new Map();
  let stringBytes = 0;

  function string(value, extended = false) {
    checkIndex(!(extended ? /\0/ : /[\0\r\n]/).test(value), 'control character in a name');

    if (stringsByValue.has(value)) return stringsByValue.get(value);

    const bytes = Buffer.from(value + '\0');
    const offset = stringBytes;
    stringBytes += bytes.length;
    strings.push(bytes);
    stringsByValue.set(value, offset);
    return offset;
  }

  for (const view of views) {
    const prefix = view.path;

    if (view.kind === 'deferred-storage' || view.kind === 'deferred-filesystem') {
      checkIndex(view.source.contentPath.startsWith('@'), 'deferred content path');
      checkIndex(Buffer.byteLength(view.source.contentPath) <= 0x300, 'content path is too long');
    }

    if (tar) {
      const archive = planTar(view);
      const filename = prefix + '.tar';
      checkIndex(Buffer.byteLength(filename) <= 1023 && !/[\0\r\n]/.test(filename), 'FTP archive path');
      checkIndex(!byPath.has(filename), 'duplicate archive path');
      const parent = addDirectory(path.posix.dirname(filename));
      const id = nodes.length;
      checkIndex(members.length + archive.members.length < NONE, 'too many archive members');
      nodes.push({
        path: filename, name: path.posix.basename(filename), parent, type: 'tar',
        mount: view.mount,
        offset: BigInt(members.length) | (BigInt(archive.members.length) << 32n),
        size: archive.size,
        sourcePath: view.kind.startsWith('deferred-') ? view.source.contentPath : '',
      });
      byPath.set(filename, id);
      nodes[parent].children.push(id);
      for (const member of archive.members) members.push(member);
      continue;
    }

    addDirectory(prefix);

    for (const item of view.entries) {
      const filename = prefix + item.path;
      checkIndex(!entries.has(filename), 'duplicate path');
      entries.add(filename);

      if (view.kind === 'filesystem' || view.kind === 'deferred-filesystem')
        checkIndex(Buffer.byteLength(item.path) <= 0x300, 'filesystem path is too long');

      checkIndex(Buffer.byteLength(filename) <= 1023 && !/[\r\n]/.test(filename), 'FTP path length or character');

      if (item.type === 'directory') {
        addDirectory(filename);
        continue;
      }

      checkIndex(!byPath.has(filename), 'file/directory collision');

      const parent = addDirectory(path.posix.dirname(filename));
      const id = nodes.length;
      nodes.push({
        path: filename,
        name: path.posix.basename(filename),
        parent,
        type: 'file',
        mount: view.mount,
        offset: view.kind === 'deferred-filesystem' ? string(view.source.contentPath) : item.offset || 0,
        size: item.size,
        sourcePath:
          view.kind === 'filesystem' || view.kind === 'deferred-filesystem'
            ? item.path
            : view.kind === 'deferred-storage'
              ? view.source.contentPath
              : '',
      });
      byPath.set(filename, id);
      nodes[parent].children.push(id);
    }
  }

  for (const node of nodes) {
    node.nameOffset = string(node.name);
    node.sourceOffset = string(node.sourcePath || '');
    node.children?.forEach((id, index) => {
      nodes[id].next = node.children[index + 1] ?? NONE;
    });
  }

  for (const member of members) {
    member.nameOffset = string(member.name);
    member.prefixOffset = string(member.prefix);
    member.sourceOffset = string(member.sourcePath);
    member.paxOffset = string(member.pax, true);
  }

  const headerBytes = tar ? 96 : HEADER;
  const memberOffset = headerBytes + nodes.length * STRIDE;
  const stringOffset = memberOffset + members.length * MEMBER_BYTES;
  const length = stringOffset + stringBytes;
  checkIndex(length <= 0xffffffff, 'index exceeds format precision');

  const bytes = Buffer.alloc(length);
  MAGIC.copy(bytes);
  bytes.writeUInt32LE(tar ? 2 : 1, 8);
  bytes.writeUInt32LE(STRIDE, 12);

  for (const [at, value] of [
    [16, nodes.length],
    [24, headerBytes],
    [32, stringOffset],
    [40, stringBytes],
    [48, length],
  ]) {
    bytes.writeBigUInt64LE(BigInt(value), at);
  }
  if (tar) {
    bytes.writeBigUInt64LE(BigInt(memberOffset), 56);
    bytes.writeBigUInt64LE(BigInt(members.length), 64);
    bytes.writeBigUInt64LE(BigInt(MEMBER_BYTES), 72);
  }

  nodes.forEach((node, id) => {
    const at = headerBytes + id * STRIDE;
    bytes.writeUInt32LE(node.parent, at);
    bytes.writeUInt32LE(node.children?.[0] ?? NONE, at + 4);
    bytes.writeUInt32LE(node.next ?? NONE, at + 8);
    bytes.writeUInt32LE(node.type === 'tar' ? 2 : node.type === 'file' ? 1 : 0, at + 12);
    bytes.writeUInt32LE(node.nameOffset, at + 16);
    bytes.writeUInt32LE(Buffer.byteLength(node.name), at + 20);
    bytes.writeUInt32LE(node.mount || 0, at + 24);
    bytes.writeUInt32LE(node.sourceOffset, at + 28);
    bytes.writeBigUInt64LE(BigInt(node.offset || 0), at + 32);
    bytes.writeBigUInt64LE(BigInt(node.size || 0), at + 40);
  });
  members.forEach((member, i) => {
    const at = memberOffset + i * MEMBER_BYTES;
    bytes.writeBigUInt64LE(member.start, at);
    bytes.writeBigUInt64LE(member.size, at + 8);
    bytes.writeBigUInt64LE(member.offset, at + 16);
    for (const [offset, value] of [
      [24, member.nameOffset], [28, Buffer.byteLength(member.name)],
      [32, member.prefixOffset], [36, Buffer.byteLength(member.prefix)],
      [40, member.sourceOffset], [44, member.paxOffset],
      [48, member.paxBytes], [52, member.directory ? 1 : 0],
    ]) bytes.writeUInt32LE(value, at + offset);
    bytes.writeBigUInt64LE(member.end, at + 56);
  });
  Buffer.concat(strings, stringBytes).copy(bytes, stringOffset);
  return bytes;
}

async function prepareGame({ attachment: a, title, shouldStop = () => false, tar = false }) {
  const views = [];
  const sources = [];
  const absentSources = [];
  const prepared = new Set();
  const files = createGameFiles(a);

  const cancelled = () => throwIfCancelled(shouldStop);

  async function open(options) {
    cancelled();

    try {
      return await files.open({ title, ...options });
    } catch (error) {
      if (
        error.nativeResult?.canonical !== 0x7d802 ||
        prepared.has(error.source?.contentPath)
      )
        throw error;

      prepared.add(error.source.contentPath);
      await prepareInstalledLicense({ ...a, title, source: error.source });
      cancelled();
      return files.open({ title, ...options });
    }
  }

  async function filesystemEntries(mount) {
    const pending = ['/'];
    const entries = [];

    while (pending.length) {
      const filename = pending.pop();
      cancelled();

      for (const item of await files.list(mount, filename, shouldStop)) {
        const entry = {
          path: filename.replace(/\/$/, '') + '/' + item.name,
          type: item.type,
          size: item.size,
        };
        entries.push(entry);

        if (entry.type === 'directory') pending.push(entry.path);
      }
    }

    return entries;
  }

  async function mountView(prefix, section, candidates, allowAbsent = false) {
    if (prefix.includes("update")) {
      console.log('Opening ' + prefix + '/' + section, ' (This takes a LOT of time! Don\'t assume we crashed!)');
    } else {
      console.log('Opening ' + prefix + '/' + section);
    }
    let mounted;
    let lastError;

    for (const candidate of candidates) {
      try {
        mounted = await open({ section, ...candidate });
        break;
      } catch (error) {
        if (!error.nativeResult || error.code === 'FTP_CANCELLED') throw error;

        if (allowAbsent && error.nativeResult.canonical === 0x7d202) {
          absentSources.push(error.source);
          return { source: error.source };
        }

        lastError = error;
      }
    }

    if (!mounted)
      throw new Error(
        'Could not prepare ' + prefix + '/' + section + ': ' + (lastError?.message || 'No installed content'),
      );

    const entries =
      mounted.kind === 'storage'
        ? await readRomfs((offset, length) => {
            cancelled();
            return files.read(mounted, offset, length);
          }, mounted.size)
        : await filesystemEntries(mounted);
    const mount = sources.length;
    // composed stuff (i.e game updates mounted on base games) and codefs need to stay mounted
    const deferredFilesystem = mounted.kind === 'filesystem' && section !== 'exefs' && !mounted.composed;
    const deferredStorage = mounted.kind === 'storage' &&
      mounted.source.selection !== 'datapatch' &&
      !(mounted.source.selection === 'update' && mounted.source.contentType === 1);
    const deferred = deferredFilesystem || deferredStorage;

    if (deferred) await files.close(mounted);

    sources.push({
      handle: deferred ? a.root : mounted.handle,
      kind: deferredFilesystem ? 3 : deferredStorage ? 2 : mounted.kind === 'storage' ? 0 : 1,
      attributes: deferred ? mounted.source.attributes : undefined,
      proxyType: deferred ? mounted.source.proxyType : undefined,
      programId: deferredFilesystem ? mounted.source.runtimeProgramId : undefined,
      size: mounted.size || 0,
      source: mounted.source,
    });
    views.push({
      path: prefix + '/' + section,
      mount,
      kind: deferredFilesystem ? 'deferred-filesystem' : deferredStorage ? 'deferred-storage' : mounted.kind,
      entries,
      source: mounted.source,
    });
    return mounted;
  }

  function groups(records) {
    const grouped = new Map();

    for (const record of records) {
      const key = record.contentTitle + ':' + record.version;

      if (!grouped.has(key)) grouped.set(key, []);

      grouped.get(key).push(record);
    }

    return grouped.values();
  }

  async function mountPackage(prefix, candidates) {
    const contents = new Map();
    for (const candidate of candidates) {
      const record = candidate.dataPatch || candidate.dlc || candidate.update || candidate.base;
      for (const content of record.contents) {
        // skip deltafragment, it isn't an fs
        if (content.contentType === 6) continue;
        const key = content.programIndex + ':' + content.contentType;
        if (!contents.has(key)) contents.set(key, []);
        contents.get(key).push({ ...candidate, content });
      }
    }

    for (let choices of contents.values()) {
      const { contentType, programIndex } = choices[0].content;
      let path = prefix + '/program/' + programIndex;
      // program and data can end up on top of the same folder. if that happens, shove them into subfolders
      if ((contentType === 1 || contentType === 2) &&
          contents.has(programIndex + ':1') && contents.has(programIndex + ':2')) {
        path += contentType === 1 ? '/program' : '/data';
      }
      const sections = [
        ['meta'], ['romfs', 'exefs', 'logo'], ['romfs'], ['control'], ['manual'], ['legal'],
      ][contentType];
      for (const section of sections) {
        const mounted = await mountView(path, section, choices,
          contentType === 1 && (section === 'romfs' || section === 'logo'));
        choices = choices.filter(candidate => candidate.storage === mounted.source.storage);
      }
    }
  }

  cancelled();

  const bases = await discoverBase({ ...a, title });
  cancelled();
  const updates = await discoverUpdates({ ...a, title });
  cancelled();

  const dlc = await discoverDlc({ ...a, title });
  cancelled();
  const dataPatches = await discoverDataPatches({ ...a, title });
  const [baseGroup] = groups(bases);
  if (!baseGroup) throw new Error('No installed base content was found');
  await mountPackage('/base', baseGroup.map(base => ({ storage: base.storage, base })));

  for (const group of groups(updates)) {
    await mountPackage('/updates/' + group[0].version,
      group.map(update => ({ storage: update.storage, update })));
  }

  for (const group of groups(dlc)) {
    const first = group[0];
    const prefix = '/dlc/' + first.contentTitle + '/' + first.version + '/base';
    await mountPackage(prefix, group.map(dlc => ({ storage: dlc.storage, dlc })));
  }

  for (const group of groups(dataPatches)) {
    const patch = group[0];
    const originals = dlc.filter(item => item.contentTitle === patch.dataTitle &&
      (!item.dataPatchTitle || item.dataPatchTitle === patch.contentTitle));
    if (!originals.length) throw new Error('No original DLC found for update ' + patch.contentTitle);

    for (const originalGroup of groups(originals)) {
      const original = originalGroup[0];
      const prefix = '/dlc/' + original.contentTitle + '/' + original.version + '/updates/' + patch.version;
      const candidates = group.flatMap(item => originalGroup.map(base => ({
        storage: item.storage,
        dataPatch: { ...item, original: base },
      })));
      await mountPackage(prefix, candidates);
    }
  }

  const ncm = await a.service('ncm');
  const pinned = new Set();
  const selectedSources = [
    ...sources.flatMap(item => [item.source, item.source.originalSource].filter(Boolean)),
    ...absentSources,
  ];

  for (const source of selectedSources) {
    cancelled();

    const contentTitle = source.contentTitle || title;
    const id = source.storage + ':' + contentTitle;

    if (pinned.has(id)) continue;

    pinned.add(id);

    const opened = await a.s.ipc('FTP pin source database', ncm, 5, Buffer.from([source.storage]));

    if (opened.result) throw resultError('FTP pin source database', opened.result);

    const database = a.domain.oneHandle(opened);

    try {
      const latest = await a.s.ipc('FTP pin source version', database, 6, idBytes(contentTitle));

      if (latest.result) throw resultError('FTP pin source version', latest.result);

      const key = latest.data.subarray(0, 16);

      for (const other of selectedSources.filter(
        (item) => item.storage === source.storage && (item.contentTitle || title) === contentTitle,
      )) {
        const input = Buffer.alloc(24);
        input[0] = other.contentType;
        input[1] = other.programIndex;
        key.copy(input, 8);
        const content = await a.s.ipc('FTP pin source content', database, 20, input);
        if (content.result) throw resultError('FTP pin source content', content.result);
        if (!key.equals(other.metaKey) ||
            !content.data.subarray(0, 16).equals(Buffer.from(other.contentId, 'hex'))) {
          throw new Error('Installed content changed somehow: ' + contentTitle);
        }
      }
    } finally {
      await a.s.close(database);
    }
  }

  return { index: buildIndex(views, { tar }), sources };
}

module.exports = { prepareGame, readRomfs, buildIndex };
