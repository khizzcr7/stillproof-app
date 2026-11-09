import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { claimId, parseSignedClaim } from '../protocol/claim';
import type * as Captures from '../captures';
import type { DeviceKey } from '../keys';

// --- In-memory expo-file-system -------------------------------------------------

type FsEntry = { bytes: Uint8Array } | { dir: true };

const mockFs = new Map<string, FsEntry>();
const norm = (p: string) => p.replace(/\/+$/, '');

class MockFile {
  uri: string;

  constructor(parent: string | { uri: string }, name?: string) {
    const base = typeof parent === 'string' ? parent : parent.uri;
    this.uri = name === undefined ? norm(base) : `${norm(base)}/${name}`;
  }

  get name(): string {
    return this.uri.split('/').pop()!;
  }

  get extension(): string {
    const n = this.name;
    const i = n.lastIndexOf('.');
    return i >= 0 ? n.slice(i + 1) : '';
  }

  get exists(): boolean {
    return mockFs.has(this.uri);
  }

  textSync(): string {
    const e = mockFs.get(this.uri);
    if (!e || !('bytes' in e)) throw new Error(`no such file: ${this.uri}`);
    return new TextDecoder().decode(e.bytes);
  }

  writeSync(text: string): void {
    mockFs.set(this.uri, { bytes: new TextEncoder().encode(text) });
  }

  async bytes(): Promise<Uint8Array> {
    const e = mockFs.get(this.uri);
    if (!e || !('bytes' in e)) throw new Error(`no such file: ${this.uri}`);
    return e.bytes;
  }

  copySync(dest: MockFile): void {
    const e = mockFs.get(this.uri);
    if (!e || !('bytes' in e)) throw new Error(`no such file: ${this.uri}`);
    mockFs.set(dest.uri, { bytes: e.bytes });
  }

  rename(newName: string): void {
    const e = mockFs.get(this.uri);
    if (!e) throw new Error(`no such file: ${this.uri}`);
    mockFs.delete(this.uri);
    const parts = this.uri.split('/');
    parts[parts.length - 1] = newName;
    this.uri = parts.join('/');
    mockFs.set(this.uri, e);
  }

  delete(): void {
    mockFs.delete(this.uri);
  }
}

class MockDirectory {
  uri: string;

  constructor(parent: string | { uri: string }, name?: string) {
    const base = typeof parent === 'string' ? parent : parent.uri;
    this.uri = name === undefined ? norm(base) : `${norm(base)}/${name}`;
  }

  get exists(): boolean {
    return mockFs.has(this.uri);
  }

  create(_opts?: { intermediates?: boolean }): void {
    mockFs.set(this.uri, { dir: true });
  }
}

// --- Mocks ----------------------------------------------------------------------

const mockSubmitClaim = jest.fn(async (signed: string) => claimId(parseSignedClaim(signed)));
const mockFetchReceipt = jest.fn();

function hardwareKey(): DeviceKey {
  const privateKey = p256.utils.randomSecretKey();
  const pub = bytesToHex(p256.getPublicKey(privateKey, false));
  return {
    level: 'tee',
    claimed: 'tee',
    registration: { status: 'registered' },
    publicKey: () => pub,
    attestation: async () => null,
    sign: async (message: Uint8Array) => {
      const sig = p256.sign(sha256(message), privateKey, { prehash: false, lowS: true, format: 'compact' });
      return sig;
    },
  };
}

function loadCaptures(): typeof Captures {
  jest.resetModules();
  jest.doMock('expo-file-system', () => ({ Directory: MockDirectory, File: MockFile, Paths: { document: 'file:///doc' } }));
  jest.doMock('../keys', () => ({ deviceKey: jest.fn(async () => hardwareKey()) }));
  jest.doMock('../api', () => ({ submitClaim: mockSubmitClaim, fetchReceipt: mockFetchReceipt }));
  return jest.requireActual<typeof Captures>('../captures');
}

beforeEach(() => {
  mockFs.clear();
  mockSubmitClaim.mockClear();
  mockFetchReceipt.mockClear();
  mockFs.set('file:///tmp/photo.jpg', { bytes: new Uint8Array([1, 2, 3, 4, 5]) });
});

it('stores the key level at signing time', async () => {
  const { createCapture } = loadCaptures();
  const capture = await createCapture('file:///tmp/photo.jpg', 1700000000000);
  expect(capture.level).toBe('tee');
  // The stored index holds the level too, so a later app start still shows it.
  const indexEntry = mockFs.get('file:///doc/captures/captures.json');
  expect(indexEntry && 'bytes' in indexEntry).toBe(true);
  const index = JSON.parse(new TextDecoder().decode((indexEntry as { bytes: Uint8Array }).bytes)) as { level?: string }[];
  expect(index).toHaveLength(1);
  expect(index[0].level).toBe('tee');
});

it('stores software for a software key', async () => {
  jest.resetModules();
  jest.doMock('expo-file-system', () => ({ Directory: MockDirectory, File: MockFile, Paths: { document: 'file:///doc' } }));
  jest.doMock('../keys', () => ({
    deviceKey: jest.fn(async () => {
      const key = hardwareKey();
      return { ...key, level: 'software' as const, claimed: 'software' as const, registration: { status: 'none' as const } };
    }),
  }));
  jest.doMock('../api', () => ({ submitClaim: mockSubmitClaim, fetchReceipt: mockFetchReceipt }));
  const { createCapture } = jest.requireActual<typeof Captures>('../captures');
  const capture = await createCapture('file:///tmp/photo.jpg', 1700000000000);
  expect(capture.level).toBe('software');
});
