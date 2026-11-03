#!/usr/bin/env node
const path = require('node:path');
const { createInterface } = require('node:readline');
const { titleId, withCleanup } = require('./engine/protocol.cjs');
const { attachGame } = require('./engine/session.cjs');
const { discoverGames } = require('./engine/content.cjs');
const { prepareGame } = require('./engine/mounts.cjs');
const { deployFtp, readImage } = require('./engine/ftp.cjs');
const { packNup } = require('./engine/nup.cjs');

const USAGE = 'Usage: node ouncecake.cjs <run-directory> [title-id] [--port 2121] [--nup <out.nup> --ip <switch 2 ip>]\n' +
              'Use the run dir given by ns2jb (Run folder: <whatever>)\n' +
              'You can also provide a title ID to skip the selection menu and just mount a specific game\n' +
              'With --nup, OunceCake downloads everything itself and writes a .nup instead of leaving the FTP up\n';

function getArgs(argv) {
  const args = [];
  let port = 2121;
  let nup;
  let ip;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];

    if (a === '--help') {
      return { help: true };
    }

    if (a === '--port') {
      port = Number(argv[++i]);
      if (!Number.isInteger(port) || port < 1024 || port > 65535) {
        throw new Error('Invalid --port value\n' + USAGE);
      }
      continue;
    }

    if (a === '--nup') {
      nup = argv[++i];
      if (!nup || nup.startsWith('--')) throw new Error('--nup needs an output file\n' + USAGE);
      continue;
    }

    if (a === '--ip') {
      ip = argv[++i];
      if (!ip || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) throw new Error('--ip needs an IPv4 address\n' + USAGE);
      continue;
    }

    if (a.startsWith('--')) {
      throw new Error('Unknown option: ' + a + '\n' + USAGE);
    }

    args.push(a);
  }

  if (args.length < 1 || args.length > 2) {
    throw new Error(USAGE);
  }

  if (args.length === 1 && /^(?:0x)?[0-9a-fA-F]{16}$/.test(args[0])) {
    throw new Error('You need to add a run directory\n' + USAGE);
  }

  if (Boolean(nup) !== Boolean(ip)) {
    throw new Error('--nup and --ip go together (OunceCake needs your Switch 2\'s IP to download from it)\n' + USAGE);
  }

  const title = args.length === 2 ? titleId(args[1]) : undefined;
  return { run: path.resolve(args[0]), title, port, nup: nup && path.resolve(nup), ip };
}

const storageNames = { 2: 'Game card', 4: 'Internal', 5: 'SD' };

function gameMenu(games) {
  const width = String(games.length).length;
  return games
    .map((game, i) => {
      const number = String(i + 1).padStart(width);
      const name = game.name || 'Unknown title';
      const storages = game.storages.map((id) => storageNames[id]).join(', ');
      return number + '. ' + name + '  [' + game.title.toUpperCase() + ']  (' + storages + ')';
    })
    .join('\n');
}

async function pickGame(games, signal) {
  const input = process.stdin;
  const output = process.stdout;

  if (!games.length) {
    throw new Error('No games were found. How did you even run this?');
  }

  output.write(gameMenu(games) + '\n');

  const rl = createInterface({ input, output, terminal: Boolean(input.isTTY && output.isTTY) });
  const lines = rl[Symbol.asyncIterator]();
  const close = () => rl.close();
  rl.once('SIGINT', close);
  signal.addEventListener('abort', close, { once: true });

  const prompt = () => output.write('Choose a game: ');

  try {
    if (signal.aborted) return null;

    prompt();

    for await (const line of lines) {
      if (signal.aborted) return null;

      const value = line.trim();

      if (/^q(?:uit)?$/i.test(value)) return null;

      if (/^[0-9]+$/.test(value)) {
        const number = Number(value);

        if (Number.isSafeInteger(number) && number >= 1 && number <= games.length) return games[number - 1];
      }

      output.write('Enter a number from 1 to ' + games.length + ', or q.\n');
      prompt();
    }

    return null;
  } finally {
    signal.removeEventListener('abort', close);
    rl.close();
  }
}

async function main(argv = process.argv.slice(2)) {
  const options = getArgs(argv);
  if (options.help) {
    console.log(USAGE);
    return;
  }
  const image = await readImage();
  const { port, run, nup, ip } = options;
  let { title } = options;
  let name;
  const cancellation = new AbortController();
  const stop = () => cancellation.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let attachment;
  let server;
  await withCleanup(async () => {
    attachment = await attachGame(run);
    const shouldStop = () => cancellation.signal.aborted;
    if (!title) {
      const selected = await pickGame(await discoverGames({ ...attachment, shouldStop }), cancellation.signal);
      if (!selected || shouldStop()) return;
      title = selected.title;
      name = selected.name;
    }
    const prepared = await prepareGame({ attachment, title, images: Boolean(nup), shouldStop });
    if (shouldStop()) return;
    server = await deployFtp({ attachment, image, ...prepared, port });

    if (nup) {
      console.log('FTP up, downloading into ' + nup);
      await packNup({ host: ip, port, views: prepared.views, title, name, output: nup, shouldStop });
      return;
    }

    console.log('FTP up! ftp://<switch 2 ip>:' + port);
    console.log('Ctrl-C to stop the server');
    
    while (!shouldStop()) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }, () => server?.close(), () => attachment?.close(), () => {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { getArgs, pickGame, main };
