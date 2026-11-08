const fs = require('node:fs/promises');
const path = require('node:path');
const { idBytes, fixedOutput, pathRequest, resultError, success, withCleanup, cleanup, closeHandles } = require('./protocol.cjs');
const { findOriginalContent, isInstalledUpdate, programMatchesApplication } = require('./content.cjs');
const { withProgramIndexMap, openProgramRomfs, openProgramManual } = require('./fs-context.cjs');

// if license on most recent account doesn't work, try other ones on the system
async function linkedAccounts(s, domain, service) {
  const account = await service('acc:su');
  const address = s.base + 0x3600;
  const bytes = 8 * 16;
  await s.write(address, Buffer.alloc(bytes));

  const packet = fixedOutput(2, Buffer.alloc(2), address, bytes);
  packet.writeUInt16LE(bytes, 40);

  const reply = await domain.send(s, 'List local export users', account, packet);

  if (reply.result) throw resultError('List local export users', reply.result);

  const output = await s.readOwned(address, bytes);

  const accounts = [];

  for (let at = 0; at < bytes; at += 16) {
    const user = output.subarray(at, at + 16);

    if (user.equals(Buffer.alloc(16))) continue;

    const opened = await s.ipc('Open local export account manager', account, 102, user);

    if (opened.result) continue; // if we error somehow grabbing the account, do the next one

    const manager = domain.oneHandle(opened);

    try {
      const linked = await s.ipc('Get linked export account identity', manager, 120);

      if (linked.result) continue;

      const id = Buffer.from(linked.data.subarray(0, 8));

      if (!id.equals(Buffer.alloc(8)) && !accounts.some((other) => other.equals(id))) accounts.push(id);
    } finally {
      await s.close(manager);
    }
  }

  return accounts;
}

// tell es service to grab the license we need
// we do NOT get the key back and do NOT decrypt anything pc side
async function prepareInstalledLicense({ s, root, domain, service, title, source }) {
  const filename = Buffer.alloc(0x301);
  filename.write(source.contentPath);

  const attributes = Buffer.from([source.attributes]);
  await s.write(s.base + 0x2000, filename);

  const identity = await domain.send(
    s,
    'Verify licensed content title',
    root,
    pathRequest(618, attributes, s.base + 0x2000),
  );

  if (identity.result) throw resultError('GetProgramId for licensed content', identity.result);

  const contentProgramId = identity.data.readBigUInt64LE().toString(16).padStart(16, '0');
  const installedPatch = isInstalledUpdate(title, source);
  const installedDlc =
    source.selection === 'dlc' &&
    source.applicationTitle === title &&
    source.metaType === 0x82 &&
    source.contentType === 2;

  const ncm = await service('ncm');
  const opened = await s.ipc('Open installed license content storage', ncm, 4, Buffer.from([source.storage]));

  if (opened.result) throw resultError('Open installed license content storage', opened.result);

  const storage = domain.oneHandle(opened);
  let rights;
  let generation;

  try {
    const input = Buffer.alloc(17);
    Buffer.from(source.contentId, 'hex').copy(input);
    input[16] = source.attributes;

    const installed = await s.ipc('Get installed content rights identity', storage, 20, input);

    if (installed.result) throw resultError('Get installed content rights identity', installed.result);

    rights = Buffer.from(installed.data.subarray(0, 16));
    generation = installed.data[16];
  } finally {
    await s.close(storage);
  }

  if (rights.equals(Buffer.alloc(16))) return false;

  // es uses first 8 bytes for lookup
  const rightsApplication = rights.readBigUInt64BE().toString(16).padStart(16, '0');

  if (rights.readBigUInt64LE(8) & (1n << 52n)) {
    const error = new Error(
      'Content requires an original-content mount; standalone ES preparation does not apply',
    );
    error.code = 'GAME_ORIGINAL_CONTENT_REQUIRED';
    throw error;
  }

  const keyGeneration = Buffer.alloc(4);
  keyGeneration.writeUInt32LE(generation);
  await s.write(s.base + 0x3000, rights);
  await s.write(s.base + 0x3100, keyGeneration);

  const es = await service('es');
  const prepare = () =>
    s.ipc('Prepare installed title license', es, 503, Buffer.alloc(0), {
      send: [
        { address: s.base + 0x3000, size: 16, mode: 0 },
        { address: s.base + 0x3100, size: 4, mode: 0 },
      ],
    });
  let result = await prepare();

  if ([0x1491, 0x691].includes(result.result & 0x3fffff)) {

    let owned = s.installedLicenseContext;

    if (!owned || !s.handles.has(owned.handle)) {
      const opened = await s.ipc('Create export rights context', es, 2001);

      if (opened.result) throw resultError('Create export rights context', opened.result);

      owned = s.installedLicenseContext = {
        handle: domain.oneHandle(opened),
        applications: new Set(),
        accountSelected: false,
      };
    }

    const context = owned.handle;
    await s.write(s.base + 0x3200, idBytes(rightsApplication));

    if (!owned.applications.has(rightsApplication)) {
      const selected = await s.ipc('Select export title rights', context, 2, Buffer.alloc(0), {
        send: [{ address: s.base + 0x3200, size: 8, mode: 0 }],
      });

      if (selected.result) throw resultError('Select export title rights', selected.result);

      owned.applications.add(rightsApplication);
    }

    // ask for title rights on all accounts
    const selectAccounts = async () => {
      const selected = await s.ipc('Request export title account rights', context, 17, Buffer.from([1]), {
        send: [
          { address: s.base + 0x3200, size: 8, mode: 0 },
          { address: s.base + 0x3400, size: 8, mode: 0 },
        ],
      });

      if (selected.result) throw resultError('Request export title account rights', selected.result);
    };
    await selectAccounts();

    const evaluated = await s.ipc('Evaluate export title rights', context, 3);

    if (evaluated.result) throw resultError('Evaluate export title rights', evaluated.result);

    result = await prepare();

    if ([0x1491, 0x691].includes(result.result & 0x3fffff) && !owned.accountSelected) {
      // didn't work? try using individual users rights
      const accounts = await linkedAccounts(s, domain, service);
      await s.write(s.base + 0x3400, Buffer.concat(accounts));

      const selectedAccount = await s.ipc('Select export account rights', context, 1, Buffer.from([0]), {
        send: [{ address: s.base + 0x3400, size: accounts.length * 8, mode: 0 }],
      });

      if (selectedAccount.result) throw resultError('Select export account rights', selectedAccount.result);

      owned.accountSelected = true;
      await selectAccounts();

      const reevaluated = await s.ipc('Evaluate selected export account rights', context, 3);

      if (reevaluated.result) {
        throw resultError('Evaluate selected export account rights', reevaluated.result);
      }

      result = await prepare();
    }
  }

  if (result.result) throw resultError('ES prepare installed title license', result.result);

  //patch for nso, actually activate the title
  const context = s.installedLicenseContext?.handle;

  if (context && s.handles.has(context)) {
    success(
      await s.ipc('Activate prepared title keys', context, 102),
      'Activate prepared title keys',
    );
  }

  return true;
}


// try to use license, if fail, try to grab license and go again
async function withUpdateLicenses({ attachment, title, source, originalSource, operation }) {
  const attempted = new Set();

  for (;;) {
    let missing;

    try {
      return await operation();
    } catch (error) {
      if (error.nativeResult?.canonical !== 0x7d802) throw error;

      missing = error;
    }

    let prepared = false;

    for (const candidate of [source, originalSource].filter(Boolean)) {
      if (attempted.has(candidate)) continue;

      attempted.add(candidate);

      let license;

      try {
        license = await prepareInstalledLicense({ ...attachment, title, source: candidate });
      } catch (error) {
        if (
          candidate === source &&
          error.code === 'GAME_ORIGINAL_CONTENT_REQUIRED'
        ) {
          continue;
        }

        throw error;
      }

      if (!license) continue;

      prepared = true;
      break;
    }

    if (!prepared) throw missing;
  }
}


// pick the right archives for mounting
async function readLocation(a, resolver, programId, command = 0) {
  const address = a.s.base + 0x3800;
  const size = 0x300;

  const r = await a.domain.send(
    a.s,
    'Resolve selected update location',
    resolver,
    fixedOutput(command, idBytes(programId), address, size),
  );

  const absent = command === 0 || command === 16 ? [0x408, 0x1408] : [0xc08];
  if (absent.includes(r.result & 0x3fffff)) return null;

  if (r.result) throw resultError('Resolve selected update location', r.result);

  const b = await a.s.readOwned(address, size);
  const end = b.indexOf(0);
  return {
    contentPath: new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(0, end)),
    attributes: r.data.subarray(0, 16).toString('hex'),
  };
}

function contentLocation(source) {
  const attributes = Buffer.alloc(16);
  attributes[0] = source.attributes;
  return { contentPath: source.contentPath, attributes: attributes.toString('hex') };
}

async function writeLocation(a, resolver, programId, title, location, command = 1, label = 'Select content location') {
  const input = Buffer.alloc(32);
  idBytes(programId).copy(input);
  idBytes(title).copy(input, 8);
  Buffer.from(location.attributes, 'hex').copy(input, 16);
  const filename = Buffer.alloc(0x300);
  filename.write(location.contentPath);
  await a.s.write(a.s.base + 0x4000, filename);
  success(await a.domain.send(a.s, label, resolver,
    pathRequest(command, input, a.s.base + 0x4000, 0x300)), label);
}

async function selectPatch({ attachment: a, title, source, originalSource, operation }) {
  const runtimeProgramId = source.runtimeProgramId;
  const indexedUpdate = source.selection === 'update' && Boolean(source.programIndex);
  const resolvers = new Map();
  const originalPaths = [];
  let registered;
  let attempted = false;
  let previous;

  return withCleanup(async () => {
    if (indexedUpdate && originalSource?.programIndex !== source.programIndex) {
      throw new Error('No matching base program found for update index ' + source.programIndex);
    }
    originalSource ||= await findOriginalContent({
      s: a.s,
      domain: a.domain,
      service: a.service,
      title,
    });

    const lr = await a.service('lr');
    let original = originalSource;
    let patch = { ...source, ...contentLocation(source) };
    if (source.selection === 'update') {
      const storages = indexedUpdate ? [originalSource.storage] : [originalSource.storage, source.storage];
      for (const storage of storages) {
        if (resolvers.has(storage)) continue;
        const opened = success(await a.s.ipc('Open original location resolver', lr, 0, Buffer.from([storage])),
          'Open original location resolver');
        resolvers.set(storage, a.domain.oneHandle(opened));
      }
      if (!indexedUpdate) {
        original = { ...await readLocation(a, resolvers.get(originalSource.storage), title), storage: originalSource.storage };
        patch = { ...await readLocation(a, resolvers.get(source.storage), source.contentTitle), storage: source.storage };
      }
    }

    const opened = await a.s.ipc('Open registered patch resolver', lr, 1);

    if (opened.result) throw resultError('Open registered patch resolver', opened.result);

    registered = a.domain.oneHandle(opened);
    previous = await readLocation(a, registered, runtimeProgramId);
    
    attempted = true;
    await writeLocation(a, registered, runtimeProgramId, title, patch, 1, 'Register owned patch location');

    if (indexedUpdate) {
      const resolver = resolvers.get(originalSource.storage);
      const programId = originalSource.runtimeProgramId;
      const selected = contentLocation(originalSource);
      for (const path of [{ read: 0, write: 10, erase: 12 }, { read: 16, write: 18, erase: 19 }]) {
        path.previous = await readLocation(a, resolver, programId, path.read);
        originalPaths.push(path);
      }
      for (const path of originalPaths) {
        if (path.previous?.contentPath === selected.contentPath && path.previous.attributes === selected.attributes) continue;
        path.changed = true;
        await writeLocation(a, resolver, programId, title, selected, path.write, 'Select original program location');
      }
    }

    const mount = () =>
      operation({ runtimeProgramId, original, patch, originalContent: originalSource });
    const result =
      runtimeProgramId === title
        ? await mount()
        : await withProgramIndexMap({
            attachment: a,
            title,
            runtimeProgramId,
            programIndex: source.programIndex,
            operation: mount,
          });

    return result;
  }, () => cleanup(originalPaths.map(path => async () => {
    if (!path.changed) return;
    const resolver = resolvers.get(originalSource.storage);
    const programId = originalSource.runtimeProgramId;
    // Restore normal before debug so the debug fallback sees the restored path.
    success(await a.s.ipc('Remove temporary original program location', resolver,
      path.erase, idBytes(programId)), 'Remove temporary original program location');
    if (!path.previous) return;
    const restored = await readLocation(a, resolver, programId, path.read);
    if (restored?.contentPath !== path.previous.contentPath || restored.attributes !== path.previous.attributes) {
      await writeLocation(a, resolver, programId, title, path.previous, path.write, 'Restore original program location');
    }
  })), async () => {
    if (!attempted) return;
    if (previous) {
      await writeLocation(a, registered, runtimeProgramId, title, previous, 1, 'Restore previous program location');
      return;
    }
    const actual = await readLocation(a, registered, runtimeProgramId);
    if (!actual) return;
    success(await a.s.ipc('Remove owned patch location', registered, 2, idBytes(runtimeProgramId)),
      'Remove owned patch location');
  }, () => closeHandles(a.s, [...resolvers.values(), registered].filter(Boolean)));
}

// special handling for manuals. they mount weird.
async function withManualPaths({ attachment: a, title, source, originalSource, programId, operation }) {
  const resolvers = [];
  return withCleanup(async () => {
    const lr = await a.service('lr');
    // grab original manual, then grab updated manual
    for (const spec of [
      { command: 0, input: Buffer.from([originalSource.storage]), read: 3, write: 6, erase: 14, source: originalSource },
      { command: 1, input: Buffer.alloc(0), read: 4, write: 5, erase: 6, source },
    ]) {
      const handle = a.domain.oneHandle(success(await a.s.ipc('Open game manual resolver', lr,
        spec.command, spec.input), 'Open game manual resolver'));
      const resolver = { ...spec, handle };
      resolvers.push(resolver);
      resolver.previous = await readLocation(a, handle, programId, spec.read);
      const selected = contentLocation(spec.source);
      if (resolver.previous?.contentPath === selected.contentPath &&
          resolver.previous.attributes === selected.attributes) continue;
      resolver.changed = true;
      await writeLocation(a, handle, programId, title, selected, spec.write);
    }
    return operation();
  }, () => cleanup([...resolvers].reverse().map(resolver => async () => {
    if (!resolver.changed) return;
    success(await a.s.ipc('Remove temporary game manual location', resolver.handle,
      resolver.erase, idBytes(programId)), 'Remove temporary game manual location');
    if (!resolver.previous) return;
    const restored = await readLocation(a, resolver.handle, programId, resolver.read);
    if (restored?.contentPath !== resolver.previous.contentPath ||
        restored.attributes !== resolver.previous.attributes) {
      await writeLocation(a, resolver.handle, programId, title, resolver.previous, resolver.write);
    }
  })), () => closeHandles(a.s, resolvers.map(resolver => resolver.handle)));
}

function createProgramMounts(attachment) {
  const { s, domain, fs: gameFs, run, live } = attachment;
  const engine = path.join(run, 'switch2');
  const read = (file) => fs.readFile(file, 'utf8').then(JSON.parse);
  let loader;
  const openCodeRaw = async ({ title, storage, attributes }) => {
    if (!loader) {
      const evidence = await read(path.join(engine, 'ro', live.session + '-loader-root-copy.json'));
      const handle = domain.oneHandle(
        await domain.send(
          s,
          'Clone held loader root for game CodeFS',
          evidence.copy.handle,
          domain.wire.control(2),
        ),
      );
      try { loader = await gameFs.convert(handle, 'Convert game CodeFS loader'); }
      catch (error) { await cleanup([() => s.close(handle)], error); }
    }

    const input = Buffer.alloc(16);
    input[0] = attributes;
    input[1] = storage;
    input.writeBigUInt64LE(BigInt('0x' + title), 8);

    const size = 0x1a4;
    const address = s.base + 0x4000;

    return gameFs.open(loader, 'Open selected game CodeFS', 0, input, {
      receive: [{ address, size, mode: 0 }],
    });
  };

  const openCode = (args) => args.source.programIndex || args.source.selection === 'dlc' ? selectPatch({
    attachment,
    title: args.source.applicationTitle,
    source: args.source,
    originalSource: args.source,
    operation: () => withUpdateLicenses({
      attachment,
      title: args.source.applicationTitle,
      source: args.source,
      operation: () => openCodeRaw(args),
    }),
  }) : openCodeRaw(args);

  const readPolicy = code => withCleanup(async () => {
    const mode = Buffer.alloc(4);
    mode.writeUInt32LE(1);
    const file = await gameFs.openPath(code, 'Open program policy', 8, mode, '/main.npdm');
    return withCleanup(async () => {
      const size = Number(await gameFs.size(file));
      return gameFs.read(file, 0, size, true);
    }, () => gameFs.close(file));
  }, () => gameFs.close(code));

  const openUpdate = (args) => selectPatch({
    attachment,
    title: args.title,
    source: args.source,
    originalSource: args.originalSource,
    operation: (selection) => withUpdateLicenses({
      attachment,
      title: args.title,
      source: args.source,
      originalSource: selection.originalContent,
      operation: async () => {
        // base app and other parts can be on different devices (internal / sd). work that out
        const mountArgs = {
          title: selection.runtimeProgramId,
          storage: selection.original.storage,
          attributes: parseInt(selection.patch.attributes.slice(0, 2), 16),
        };
        if (args.section === 'exefs') return openCodeRaw(mountArgs);

        const policy = await readPolicy(await openCodeRaw(mountArgs));
        return openProgramRomfs({
          attachment, title: selection.runtimeProgramId, storage: selection.original.storage, policy,
        });
      },
    }),
  });

  const openManualPatch = async ({ title, source, originalSource, programSource, originalProgramSource }) => {
    const code = await (programSource.selection === 'update'
      ? openUpdate({ title, storage: programSource.storage, source: programSource,
        originalSource: originalProgramSource, section: 'exefs' })
      : withUpdateLicenses({ attachment, title, source: programSource,
        operation: () => openCode({ title: programSource.runtimeProgramId, storage: programSource.storage,
          attributes: programSource.attributes, source: programSource }) }));
    const policy = await readPolicy(code);
    // manuals use this magic value for "unspecified"
    const programId = source.runtimeProgramId === originalSource.runtimeProgramId
      ? source.runtimeProgramId : 'ffffffffffffffff';
    let handle;
    try {
      return await withUpdateLicenses({ attachment, title, source, originalSource,
        operation: () => withManualPaths({ attachment, title, source, originalSource, programId,
          operation: async () => {
            handle = await openProgramManual({ attachment, title: programId,
              storage: originalSource.storage, policy });
            return handle;
          } }) });
    } catch (error) {
      await cleanup([() => handle && gameFs.close(handle)], error);
    }
  };
  return { openCode, openUpdate, openManualPatch };
}

module.exports = { createProgramMounts, prepareInstalledLicense, withUpdateLicenses };
