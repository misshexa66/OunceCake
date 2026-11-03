#!/usr/bin/env node
// rebuild ftp native code
// bit weird to have it as a node script but this lets me call it from other code :)
// ^ i now no longer do this to make the base tool a bit more compatible
// works on windows too now if you have llvm (clang, ld.lld, llvm-objcopy) on PATH
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const has = (tool) => {
  try {
    execFileSync(tool, ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};

// gnu cross toolchain if it's there, otherwise clang + lld (works on windows too)
function toolchain() {
  if (has('aarch64-linux-gnu-gcc')) {
    return { cc: ['aarch64-linux-gnu-gcc'], ld: 'aarch64-linux-gnu-ld', objcopy: 'aarch64-linux-gnu-objcopy' };
  }

  if (has('clang') && has('ld.lld') && has('llvm-objcopy')) {
    return { cc: ['clang', '--target=aarch64-none-elf'], ld: 'ld.lld', objcopy: 'llvm-objcopy' };
  }

  throw new Error('Need aarch64-linux-gnu-gcc/ld/objcopy or clang/ld.lld/llvm-objcopy');
}

function main() {
  const directory = path.join(__dirname, 'oz-code');
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ns2-ftp-build-'));
  const tools = toolchain();
  try {
    const object = path.join(temporary, 'native.o');
    const elf = path.join(temporary, 'native.elf');
    const binary = path.join(temporary, 'native.bin');
    execFileSync(
      tools.cc[0],
      [
        ...tools.cc.slice(1),
        '-c',
        '-Os',
        '-ffreestanding',
        '-fno-builtin',
        '-fPIC',
        '-fno-stack-protector',
        '-fno-asynchronous-unwind-tables',
        '-fno-unwind-tables',
        '-fno-jump-tables',
        '-ffunction-sections',
        '-mgeneral-regs-only',
        '-mno-outline-atomics',
        path.join(directory, 'native.c'),
        '-o',
        object,
      ],
      { stdio: 'inherit' },
    );
    execFileSync(tools.ld, ['-T', path.join(directory, 'layout.ld'), object, '-o', elf], {
      stdio: 'inherit',
    });

    execFileSync(tools.objcopy, ['-O', 'binary', elf, binary], { stdio: 'inherit' });
    fs.copyFileSync(binary, path.join(directory, 'native.bin'));
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
