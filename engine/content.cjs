const { inflateRawSync } = require('node:zlib');
const { success, idBytes, fixedOutput, pathRequest, resultError, withCleanup, closeHandles, throwIfCancelled } = require('./protocol.cjs');

// read nca content!

const inactive = new Set([0x21005, 0x20a05]);

async function readContentMeta(s, database, key) {
  const size = success(await s.ipc('Get content metadata size', database, 10, key), 'GetSize')
    .data.readUInt32LE();
  const address = s.base + 0x6000;
  if (size > s.bytes - 0x6000) throw new Error('Content metadata is too large');
  success(await s.ipc('Read content metadata', database, 1, key, {
    receive: [{ address, size, mode: 0 }],
  }), 'Get content metadata');
  return s.readOwned(address, size);
}

async function discoverInstalled({ s, domain, service, title, metaType, kind }) {
  const label = { 0x80: 'application', 0x81: 'update', 0x82: 'DLC', 0x84: 'DLC update' }[metaType];
  const ncm = await service('ncm');
  const records = [];

  for (const storage of [4, 5, 2]) {
    let database;

    try {
      await withCleanup(async () => {
        database = domain.oneHandle(
          success(
            await s.ipc('Open ' + label + ' metadata database', ncm, 5, Buffer.from([storage])),
            'OpenContentMetaDatabase',
          ),
        );

        const found = new Map();

        async function list(min, max) {
          const input = Buffer.alloc(32);
          input[0] = metaType;
          idBytes(title).copy(input, 8);
          input.writeBigUInt64LE(min, 16);
          input.writeBigUInt64LE(max, 24);

          const address = s.base + 0x6000;
          const capacity = 32;
          const size = capacity * 16;

          const reply = success(
            await s.ipc('List installed game ' + kind, database, 5, input, {
              receive: [{ address, size, mode: 0 }],
            }),
            'List installed game ' + kind,
          );

          const total = reply.data.readInt32LE();
          const count = reply.data.readInt32LE(4);

          const bytes = await s.readOwned(address, size);

          for (let i = 0; i < count; i++) {
            const key = bytes.subarray(i * 16, (i + 1) * 16);
            const id = key.readBigUInt64LE();

            const contentTitle = id.toString(16).padStart(16, '0');
            const version = key.readUInt32LE(8);

            if (!found.has(contentTitle) || version > found.get(contentTitle).version) {
              found.set(contentTitle, { contentTitle, version, storage, metaKey: Buffer.from(key) });
            }
          }

          if (total <= count) return;

          // properly handle a weirdly high amount of packages
          if (min === max) {
            const latest = success(
              await s.ipc(
                'Get latest installed ' + label,
                database,
                6,
                idBytes(min.toString(16).padStart(16, '0')),
              ),
              'GetLatestContentMetaKey',
            );

            const contentTitle = min.toString(16).padStart(16, '0');
            found.set(contentTitle, {
              contentTitle,
              version: latest.data.readUInt32LE(8),
              storage,
              metaKey: Buffer.from(latest.data.subarray(0, 16)),
            });
            return;
          }

          const mid = (min + max) / 2n;
          await list(min, mid);
          await list(mid + 1n, max);
        }

        await list(0n, 0xffffffffffffffffn);

        if (metaType !== 0x80 || title !== '0000000000000000') {
          for (const item of found.values()) {
            const meta = await readContentMeta(s, database, item.metaKey);
            item.contents = [];
            for (let i = 0; i < meta.readUInt16LE(2); i++) {
              const info = meta.subarray(8 + meta.readUInt16LE() + i * 24);
              item.contents.push({
                contentId: info.subarray(0, 16).toString('hex'),
                attributes: info[21] & 15,
                contentType: info[22],
                programIndex: info[23],
              });
            }
            item.contents.sort((a, b) => a.programIndex - b.programIndex || a.contentType - b.contentType);
            if (metaType === 0x82 || metaType === 0x84) {
              const owner = meta.readBigUInt64LE(metaType === 0x82 ? 8 : 16);
              if (owner !== BigInt('0x' + title)) {
                found.delete(item.contentTitle);
                continue;
              }
            }
            if (metaType === 0x84) {
              item.dataTitle = meta.readBigUInt64LE(8).toString(16).padStart(16, '0');
            } else if (metaType === 0x82 && meta.readUInt16LE() >= 0x18) {
              const patch = meta.readBigUInt64LE(24);
              if (patch) item.dataPatchTitle = patch.toString(16).padStart(16, '0');
            }
          }
        }

        records.push(...found.values());
      }, () => closeHandles(s, database ? [database] : []));
    } catch (error) {
      if (!inactive.has(error.nativeResult?.canonical)) throw error;
    }
  }

  records.sort(
    (a, b) => b.version - a.version || a.contentTitle.localeCompare(b.contentTitle) || a.storage - b.storage,
  );
  return records;
}

const discoverUpdates = (options) => discoverInstalled({ ...options, metaType: 0x81, kind: 'updates' });
const discoverDlc = (options) => discoverInstalled({ ...options, metaType: 0x82, kind: 'dlc' });
const discoverDataPatches = (options) => discoverInstalled({ ...options, metaType: 0x84, kind: 'DLC updates' });
const discoverBase = (options) => discoverInstalled({ ...options, metaType: 0x80, kind: 'base content' });
const discoverApplications = (options) =>
  discoverInstalled({ ...options, title: '0000000000000000', metaType: 0x80, kind: 'applications' });

// Resolve an installed content record without mounting its filesystem.
async function resolveContent({ s, root, domain, service, title, storage, base, update, dlc, dataPatch, content, contentType = content?.contentType ?? 1 }) {
  const contentName = ['Meta', 'Program', 'Data', 'Control', 'HtmlDocument', 'LegalInformation', 'DeltaFragment'][contentType];

  const handles = [];
  const own = (reply) => {
    const h = domain.oneHandle(reply);
    handles.push(h);
    return h;
  };

  return withCleanup(async () => {
    const ncm = await service('ncm');
    const database = own(
      success(
        await s.ipc('OpenContentMetaDatabase', ncm, 5, Buffer.from([storage])),
        'OpenContentMetaDatabase',
      ),
    );
    const selected = dataPatch || dlc || update || base;
    const contentTitle = selected ? selected.contentTitle : title;
    let key;
    if (selected) {
      key = selected.metaKey ? Buffer.from(selected.metaKey) : Buffer.alloc(16);
      idBytes(contentTitle).copy(key);
      key.writeUInt32LE(selected.version, 8);
      key[12] = dataPatch ? 0x84 : dlc ? 0x82 : update ? 0x81 : 0x80;
    } else {
      const latest = success(
        await s.ipc('GetLatestContentMetaKey', database, 6, idBytes(contentTitle)),
        'GetLatestContentMetaKey',
      );
      key = Buffer.from(latest.data.subarray(0, 16));
    }

    if (selected && !base) {
      const owner = success(
        await s.ipc('Verify selected ' + (dlc ? 'DLC' : 'update') + ' application', database, 22, key),
        'GetOwnerApplicationId',
      );
      if (owner.data.readBigUInt64LE() !== BigInt('0x' + title)) {
        throw new Error('Selected content belongs to another application');
      }
    }

    const input = Buffer.alloc(24);
    input[0] = contentType;
    key.copy(input, 8);

    let contentId;
    let attributes;
    let programIndex;
    if (content) {
      contentId = Buffer.from(content.contentId, 'hex');
      attributes = content.attributes;
      programIndex = content.programIndex;
    } else {
      const content = success(await s.ipc('GetContentIdByType', database, 3, input), 'GetContentIdByType');
      contentId = Buffer.from(content.data.subarray(0, 16));
      const info = success(
        await s.ipc('Get installed ' + contentName + ' content information', database, 24, input),
        'Get installed ' + contentName + ' content information',
      ).data;
      attributes = info[21] & 15;
      programIndex = info[23];
    }
    const store = own(
      success(await s.ipc('OpenContentStorage', ncm, 4, Buffer.from([storage])), 'OpenContentStorage'),
    );
    const address = s.base + 0x3000;
    const size = 0x300;

    const resolved = await domain.send(
      s,
      'Resolve installed game path',
      store,
      fixedOutput(8, contentId, address, size),
    );
    success(resolved, 'Resolve installed game path');

    const bytes = await s.readOwned(address, size);
    const end = bytes.indexOf(0);

    const contentPath = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, end));

    const source = {
      route: 'ncm',
      storage,
      contentPath,
      attributes,
      contentType,
      contentId: contentId.toString('hex'),
      version: key.readUInt32LE(8),
      metaType: key[12],
      metaKey: key,
      programIndex,
      applicationTitle: title,
    };

    if (root) {
      const filename = Buffer.alloc(0x301);
      filename.write(contentPath);
      await s.write(s.base + 0x2000, filename);
      const identity = success(await domain.send(s, 'Read selected NCA ProgramId', root,
        pathRequest(618, Buffer.from([attributes]), s.base + 0x2000)), 'Read selected NCA ProgramId');
      source.runtimeProgramId = identity.data.readBigUInt64LE().toString(16).padStart(16, '0');
    }

    if (update) {
      Object.assign(source, {
        selection: 'update',
        applicationTitle: title,
        contentTitle,
      });
    }

    if (dlc) {
      Object.assign(source, {
        selection: 'dlc',
        applicationTitle: title,
        contentTitle,
        dataPatchTitle: dlc.dataPatchTitle,
      });
    }

    if (dataPatch) {
      Object.assign(source, {
        selection: 'datapatch',
        applicationTitle: title,
        contentTitle,
        dataTitle: dataPatch.dataTitle,
      });
    }

    return source;
  }, () => closeHandles(s, handles));
}

const resolveProgramContent = (options) => resolveContent({ ...options, contentType: 1 });
const resolveControlContent = (options) =>
  resolveContent({ ...options, dlc: undefined, update: undefined, contentType: 3 });
const resolveDlcContent = (options) => {
  return resolveContent({ ...options, contentType: 2 });
};
const resolveDataPatchContent = (options) => resolveContent({ ...options, contentType: 2 });

async function findOriginalContent(options) {
  for (const storage of [4, 5, 2]) {
    try {
      return await resolveProgramContent({ ...options, storage, update: undefined });
    } catch (error) {
      const absent = new Set([0xe05, 0x21005, 0x20a05]); // collection of error codes for "we don't have this"
      if (!absent.has(error.nativeResult?.canonical)) throw error;
    }
  }

  throw new Error('No installed base Program content was found');
}

// handling for switch 2 editions, mainly. their switch 2 updates seem to have different title ids from their base apps
function isInstalledUpdate(title, source) {
  return (
    source.selection === 'update' &&
    source.applicationTitle === title &&
    source.metaType === 0x81 &&
    source.contentTitle !== title
  );
}

function programMatchesApplication(title, source, programId) {
  return (
    programId === title ||
    (isInstalledUpdate(title, source) && title.startsWith('01') && programId === '04' + title.slice(2))
  );
}

// display name grabbing for game select
const cleanName = (name) =>
  name
    .replace(/[\x00-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

function applicationName(nacp) {

  const format = nacp[0x3215];
  let titles = nacp.subarray(0, 0x3000);

  if (format === 1) {
    const size = titles.readUInt16LE();
    titles = inflateRawSync(titles.subarray(2, 2 + size), { maxOutputLength: 32 * 0x300 });
  } else {
  }

  // english, then whatever else is on hand
  for (let i = 0; i < titles.length / 0x300; i++) {
    const bytes = titles.subarray(i * 0x300, i * 0x300 + 0x200);
    const end = bytes.indexOf(0);

    if (!end) continue;

    const name = cleanName(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, end)));

    if (name) return name;
  }

  return null;
}

function optionalName(bytes) {
  try { return applicationName(bytes); } catch { return null; }
}

async function controlName({ s, root, domain, service, filesystem }, game) {
  for (const storage of game.storages) {
    const handles = [];
    const name = await withCleanup(async () => {
      try {
        const source = await resolveControlContent({ s, domain, service, title: game.title, storage });
        const filename = Buffer.alloc(0x301);
        filename.write(source.contentPath);
        await s.write(s.base + 0x2000, filename);
        const input = Buffer.alloc(16);
        input[0] = source.attributes;
        input.writeUInt32LE(3, 4);
        idBytes(game.title).copy(input, 8);
        const opened = success(await domain.send(
          s, 'Open installed game control metadata', root, pathRequest(10, input, s.base + 0x2000),
        ), 'Open installed game control metadata');
        const control = domain.oneHandle(opened);
        handles.push(control);
        const file = success(await filesystem.openFile(s, control, '/control.nacp'),
          'Open installed game control property');
        handles.push(file.handle);
        if (await filesystem.fileSize(s, file.handle) < 0x4000n) return null;
        return optionalName(await filesystem.readFile(s, file.handle, 0, 0x4000));
      } catch (error) {
        if (!error.nativeResult) throw error;
        return null;
      }
    }, () => closeHandles(s, handles));
    if (name) return name;
  }
  return null;
}

async function discoverGames({ s, root, domain, service, filesystem, shouldStop = () => false }) {
  console.log("Getting games list..");
  const cancelled = () => throwIfCancelled(shouldStop);
  cancelled();

  const inventory = await discoverApplications({ s, domain, service });
  const byTitle = new Map();

  for (const item of inventory) {
    const title = item.contentTitle;

    if (!byTitle.has(title)) byTitle.set(title, { title, name: null, storages: [] });

    const game = byTitle.get(title);

    if (!game.storages.includes(item.storage)) game.storages.push(item.storage);
  }

  if (!byTitle.size) return [];

  cancelled();

  let control;

  await withCleanup(async () => {
    let ns;

    try {
      ns = await service('ns:ro');
    } catch (error) {
      if (!/0x615|service unavailable|service not found/i.test(error.message)) {
        throw error;
      }

      ns = await service('ns:am2');
    }

    const opened = await s.ipc('Open read-only application names', ns, 7989);

    if (opened.result) throw resultError('Open read-only application names', opened.result);

    control = domain.oneHandle(opened);

    const address = s.base + 0x10000;
    const size = 0x24000;

    for (const game of byTitle.values()) {
      cancelled();

      const input = Buffer.alloc(16);
      input[0] = 1;
      idBytes(game.title).copy(input, 8);

      const reply = await s.ipc('Read installed game name', control, 0, input, {
        receive: [{ address, size, mode: 0 }],
      });

      if (reply.result) continue;


      const nacp = await s.readOwned(address, 0x4000);

      game.name = optionalName(nacp);
    }
  }, () => closeHandles(s, control ? [control] : []));

  const games = [...byTitle.values()];
  for (const game of games) {
    if (!game.name) {
      cancelled();
      game.name = await controlName({ s, root, domain, service, filesystem }, game);
    }
    game.storages.sort((a, b) => a - b);
  }

  games.sort(
    (a, b) =>
      Number(!a.name) - Number(!b.name) ||
      (a.name || '').localeCompare(b.name || '', 'en', { sensitivity: 'base' }) ||
      a.title.localeCompare(b.title),
  );
  return games;
}

module.exports = {
  discoverGames, discoverBase, discoverUpdates, discoverDlc, discoverDataPatches,
  resolveContent, resolveProgramContent, resolveDlcContent, resolveDataPatchContent, findOriginalContent,
  isInstalledUpdate, programMatchesApplication,
};
