// dedicated file for handling dlc, it's messy and annoying 
const crypto = require('node:crypto');
const { success, idBytes, withCleanup } = require('./protocol.cjs');
const { withUpdateLicenses } = require('./program.cjs');

async function openDlcPatch({ attachment: a, title, source, originalSource }) {
  if (source.dataTitle !== originalSource.contentTitle ||
      (originalSource.dataPatchTitle && originalSource.dataPatchTitle !== source.contentTitle)) {
    throw new Error('DLC update does not match its original DLC');
  }
  const { s, domain, service, root } = a;
  const dataId = originalSource.runtimeProgramId || originalSource.contentTitle;
  const lr = await service('lr');
  const resolver = domain.oneHandle(success(await s.ipc('Open DLC resolver', lr, 3), 'Open DLC resolver'));
  const owner = 'f0' + crypto.randomBytes(7).toString('hex');
  const addresses = [s.base + 0x4000, s.base + 0x4400];
  let previous;
  let previousAttributes;
  let registered = false;

  return withCleanup(async () => {
    const saved = await s.ipc('Read existing DLC paths', resolver, 5, idBytes(dataId), {
      receive: addresses.map(address => ({ address, size: 0x300, mode: 0 })),
    });
    if (!saved.result) {
      previous = [];
      previousAttributes = Buffer.from(saved.data.subarray(0, 32));
      for (const address of addresses) previous.push(await s.readOwned(address, 0x300));
    } else if ((saved.result & 0x3fffff) !== 0xe08) {
      success(saved, 'Read existing DLC paths');
    }

    for (let i = 0; i < addresses.length; i++) {
      const path = Buffer.alloc(0x300);
      // resolver wants the patch BEFORE the base dlc?? sure why tf not
      path.write([source, originalSource][i].contentPath);
      await s.write(addresses[i], path);
    }
    const input = Buffer.alloc(48);
    idBytes(dataId).copy(input);
    idBytes(owner).copy(input, 8);
    input[16] = source.attributes;
    input[32] = originalSource.attributes;
    registered = true;
    success(await s.ipc('Register DLC and patch paths', resolver, 7, input, {
      send: addresses.map(address => ({ address, size: 0x300, mode: 0 })),
    }), 'Register DLC and patch paths');

    return withUpdateLicenses({
      attachment: a, title, source, originalSource,
      operation: async () => {
        const input = Buffer.alloc(16);
        idBytes(dataId).copy(input, 8);
        return domain.oneHandle(success(
          await s.ipc('Open patched DLC storage', root, 202, input),
          'Open patched DLC storage',
        ));
      },
    });
  }, async () => {
    if (!registered) return;
    success(await s.ipc('Remove temporary DLC paths', resolver, 4, idBytes(owner)), 'Remove temporary DLC paths');
  }, async () => {
    if (!registered || !previous) return;
    for (let i = 0; i < addresses.length; i++) await s.write(addresses[i], previous[i]);
    const input = Buffer.concat([idBytes(dataId), idBytes(title), previousAttributes]);
    success(await s.ipc('Restore existing DLC paths', resolver, 7, input, {
      send: addresses.map(address => ({ address, size: 0x300, mode: 0 })),
    }), 'Restore existing DLC paths');
  }, () => s.close(resolver));
}

module.exports = { openDlcPatch };
