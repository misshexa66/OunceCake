#!/usr/bin/env node
const path = require('node:path');
const { createInterface } = require('node:readline');
const { titleId, withCleanup } = require('./engine/protocol.cjs');
const { attachGame } = require('./engine/session.cjs');
const { discoverGames } = require('./engine/content.cjs');
const { prepareGame } = require('./engine/mounts.cjs');
const { deployFtp, readImage } = require('./engine/ftp.cjs');

const USAGE = 'Usage: node ouncecake.cjs <run-directory> [title-id] [--port 2121] [--tar]\n' +
              'Use the run dir given by ns2jb (Run folder: <whatever>)\n' +
              'You can also provide a title ID to skip the selection menu and just mount a specific game\n' +
              '--tar exposes the data as tar files instead of raw files, allowing for faster downloads\n';

function getArgs(argv) {
  const args = [];
  let port = 2121;
  let tar = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];

    if (a === '--help') {
      return { help: true };
    }

    if (a === '--tar') {
      tar = true;
      continue;
    }

    if (a === '--port') {
      port = Number(argv[++i]);
      if (!Number.isInteger(port) || port < 1024 || port > 65535) {
        throw new Error('Invalid --port value\n' + USAGE);
      }
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

  const title = args.length === 2 ? titleId(args[1]) : undefined;
  return { run: path.resolve(args[0]), title, port, tar };
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
  const { port, run } = options;
  let { title } = options;
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
    }
    const prepared = await prepareGame({ attachment, title, shouldStop, tar: options.tar });
    if (shouldStop()) return;
    server = await deployFtp({ attachment, image, ...prepared, port });
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
