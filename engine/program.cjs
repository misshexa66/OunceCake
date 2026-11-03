const fs = require('node:fs/promises');
const path = require('node:path');
const { idBytes, fixedOutput, pathRequest, resultError, success, withCleanup, closeHandles } = require('./protocol.cjs');
const { findOriginalContent, isInstalledUpdate, programMatchesApplication } = require('./content.cjs');
const { withProgramIndexMap, openProgramRomfs } = require('./fs-context.cjs');

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
async function readLocation(a, resolver, programId) {
  const address = a.s.base + 0x3800;
  const size = 0x300;

  const r = await a.domain.send(
    a.s,
    'Resolve selected update location',
    resolver,
    fixedOutput(0, idBytes(programId), address, size),
  );

  // either of these mean no program, return null
  if ([0x408, 0x1408].includes(r.result & 0x3fffff)) return null;

  if (r.result) throw resultError('Resolve selected update location', r.result);

  const b = await a.s.readOwned(address, size);
  const end = b.indexOf(0);
  return {
    contentPath: new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(0, end)),
    attributes: r.data.subarray(0, 16).toString('hex'),
  };
}

async function selectPatch({ attachment: a, title, source, originalSource, operation }) {
  const runtimeProgramId = source.runtimeProgramId;
  const resolvers = new Map();
  let original;
  let registered;
  let attempted = false;
  let patch;

  async function writeLocation(label, handle, input, location) {
    const filename = Buffer.alloc(0x300);
    filename.write(location.contentPath);
    await a.s.write(a.s.base + 0x4000, filename);

    const reply = await a.domain.send(a.s, label, handle, pathRequest(1, input, a.s.base + 0x4000, 0x300));

    if (reply.result) throw resultError(label, reply.result);
  }

  return withCleanup(async () => {
    originalSource ||= await findOriginalContent({
      s: a.s,
      domain: a.domain,
      service: a.service,
      title,
    });

    const lr = await a.service('lr');

    async function resolver(storage) {
      if (resolvers.has(storage)) return resolvers.get(storage);

      const reply = await a.s.ipc('Open original location resolver', lr, 0, Buffer.from([storage]));

      if (reply.result) throw resultError('Open original location resolver', reply.result);

      const handle = a.domain.oneHandle(reply);
      resolvers.set(storage, handle);
      return handle;
    }

    original = await resolver(originalSource.storage);

    const patchResolver = await resolver(source.storage);
    const basePath = await readLocation(a, original, title);
    const patchPath = await readLocation(a, patchResolver, source.contentTitle);

    const base = { ...basePath, storage: originalSource.storage };
    patch = { ...patchPath, storage: source.storage };

    if (runtimeProgramId !== title) {
    }

    const opened = await a.s.ipc('Open registered patch resolver', lr, 1);

    if (opened.result) throw resultError('Open registered patch resolver', opened.result);

    registered = a.domain.oneHandle(opened);
    
    const input = Buffer.alloc(32);
    idBytes(runtimeProgramId).copy(input);
    idBytes(title).copy(input, 8);
    Buffer.from(patch.attributes, 'hex').copy(input, 16);
    attempted = true;
    await writeLocation('Register owned patch location', registered, input, patch);

    const actual = await readLocation(a, registered, runtimeProgramId);

    const mount = () =>
      operation({ runtimeProgramId, original: base, patch, originalContent: originalSource });
    const result =
      runtimeProgramId === title
        ? await mount()
        : await withProgramIndexMap({
            attachment: a,
            title,
            runtimeProgramId,
            operation: mount,
          });

    return result;
  }, async () => {
    if (!attempted) return;
    const actual = await readLocation(a, registered, runtimeProgramId);
    if (!actual) return;
    success(await a.s.ipc('Remove owned patch location', registered, 2, idBytes(runtimeProgramId)),
      'Remove owned patch location');
  }, () => closeHandles(a.s, [...resolvers.values(), registered].filter(Boolean)));
}

function createProgramMounts(attachment) {
  const { s, domain, filesystem, service, run, live, current } = attachment;
  const engine = path.join(run, 'switch2');
  const read = (file) => fs.readFile(file, 'utf8').then(JSON.parse);
  let loader;
  const openCodeRaw = async ({ title, storage, attributes }) => {
    if (!loader) {
      const evidence = await read(path.join(engine, 'ro', live.session + '-loader-root-copy.json'));
      loader = domain.oneHandle(
        await domain.send(
          s,
          'Clone held loader root for game CodeFS',
          evidence.copy.handle,
          domain.wire.control(2),
        ),
      );
    }

    const input = Buffer.alloc(16);
    input[0] = attributes;
    input[1] = storage;
    input.writeBigUInt64LE(BigInt('0x' + title), 8);

    const size = 0x1a4;
    const address = s.base + 0x4000;

    const reply = await s.ipc('Open selected game CodeFS', loader, 0, input, {
      receive: [{ address, size, mode: 0 }],
    });

    if (reply.result) {
      throw resultError('Open selected game CodeFS', reply.result);
    }

    return domain.oneHandle(reply);
  };

  async function assertNoPatch(title) {
    const lr = await service('lr');
    const opened = await s.ipc('Check base CodeFS selection', lr, 1);

    if (opened.result) {
      throw resultError('Check base CodeFS selection', opened.result);
    }

    const resolver = domain.oneHandle(opened);

    try {
    } finally {
      await s.close(resolver);
    }
  }

  const openCode = async (args) => {
    await assertNoPatch(args.title);
    return openCodeRaw(args);
  };

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

        const code = await openCodeRaw(mountArgs);
        const policy = await withCleanup(async () => {
          const opened = await filesystem.openFile(s, code, '/main.npdm');
          success(opened, 'Mounted program policy');
          return withCleanup(async () => {
            const size = Number(await filesystem.fileSize(s, opened.handle));
            return filesystem.readFile(s, opened.handle, 0, size);
          }, () => s.close(opened.handle));
        }, () => s.close(code));
        return openProgramRomfs({
          attachment, title: selection.runtimeProgramId, storage: selection.original.storage, policy,
        });
      },
    }),
  });
  return { openCode, openUpdate };
}

module.exports = { createProgramMounts, prepareInstalledLicense };
