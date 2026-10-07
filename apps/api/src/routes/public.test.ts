import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import fsp from 'node:fs/promises';
import path from 'node:path';
import request from 'supertest';
import { config } from '../config';
import { hashPassword } from '../services/authService';

/**
 * 集成测试：真实 express app + 模拟的 Prisma 层，验证「带密码的分享链接，
 * 未验证口令不得从媒体端点取走媒体」。
 */

const state = vi.hoisted(() => ({
  link: null as null | {
    id: string;
    familyId: string;
    passwordHash: string | null;
    label: string | null;
    expiresAt: Date;
    revokedAt: Date | null;
  },
  media: null as null | {
    id: string;
    itemId: string;
    storageKey: string;
    transcodeKey: string | null;
    thumbKey: string | null;
    waveformKey: string | null;
    mimeType: string;
    originalName: string;
    deletedAt: null;
  },
}));

vi.mock('../db', () => ({
  prisma: {
    shareLink: {
      findUnique: vi.fn(async () =>
        state.link ? { ...state.link, family: { id: state.link.familyId, name: '测试之家' } } : null,
      ),
      update: vi.fn(async () => state.link),
    },
    item: {
      findMany: vi.fn(async () => []),
    },
    itemMedia: {
      findFirst: vi.fn(async () => state.media),
    },
    $queryRaw: vi.fn(async () => [{ 1: 1 }]),
  },
}));

import { createApp } from '../app';

const SHARE_PASSWORD = 'wedding-2026';
const TOKEN = 'test-share-token';
const MEDIA_BYTES = Buffer.from('fake-png-bytes-for-test');

let app: ReturnType<typeof createApp>;

beforeAll(async () => {
  const storageKey = 'families/fam-1/objects/ab/testmedia.png';
  await fsp.mkdir(path.dirname(path.join(config.STORAGE_ROOT, storageKey)), { recursive: true });
  await fsp.writeFile(path.join(config.STORAGE_ROOT, storageKey), MEDIA_BYTES);

  state.media = {
    id: 'media-1',
    itemId: 'item-1',
    storageKey,
    transcodeKey: null,
    thumbKey: null,
    waveformKey: null,
    mimeType: 'image/png',
    originalName: 'photo.png',
    deletedAt: null,
  };

  app = createApp();
});

afterAll(async () => {
  await fsp.rm(config.STORAGE_ROOT, { recursive: true, force: true });
});

beforeEach(async () => {
  state.link = {
    id: 'link-1',
    familyId: 'fam-1',
    passwordHash: await hashPassword(SHARE_PASSWORD),
    label: null,
    expiresAt: new Date(Date.now() + 86_400_000),
    revokedAt: null,
  };
});

const mediaUrl = () => `/api/v1/public/share/${TOKEN}/media/media-1/raw`;

describe('带密码的分享链接：媒体端点访问控制', () => {
  it('未提供口令时只返回 requiresPassword，不签发媒体通行证', async () => {
    const res = await request(app).post(`/api/v1/public/share/${TOKEN}`).send({});
    expect(res.status).toBe(200);
    expect(res.body.share.requiresPassword).toBe(true);
    expect(res.body.share.mediaToken).toBeNull();
    expect(res.body.share.items).toEqual([]);
  });

  it('没有媒体通行证时，媒体端点一律 401（不得绕过口令取走媒体）', async () => {
    const res = await request(app).get(mediaUrl());
    expect(res.status).toBe(401);
  });

  it('伪造的媒体通行证被拒绝', async () => {
    const res = await request(app).get(`${mediaUrl()}?st=forged-token`);
    expect(res.status).toBe(401);
  });

  it('口令错误不签发通行证', async () => {
    const res = await request(app).post(`/api/v1/public/share/${TOKEN}`).send({ password: 'wrong' });
    expect(res.status).toBe(401);
  });

  it('口令正确 → 签发通行证 → 凭通行证可取到媒体字节', async () => {
    const open = await request(app).post(`/api/v1/public/share/${TOKEN}`).send({ password: SHARE_PASSWORD });
    expect(open.status).toBe(200);
    const grant = open.body.share.mediaToken;
    expect(typeof grant).toBe('string');

    const res = await request(app).get(`${mediaUrl()}?st=${encodeURIComponent(grant)}`);
    expect(res.status).toBe(200);
    expect(Buffer.from(res.body)).toEqual(MEDIA_BYTES);
  });

  it('A 链接的通行证不能用于 B 链接', async () => {
    const open = await request(app).post(`/api/v1/public/share/${TOKEN}`).send({ password: SHARE_PASSWORD });
    const grant = open.body.share.mediaToken as string;

    state.link = { ...state.link!, id: 'link-2' };
    const res = await request(app).get(`${mediaUrl()}?st=${encodeURIComponent(grant)}`);
    expect(res.status).toBe(401);
  });
});

describe('无密码的分享链接', () => {
  beforeEach(() => {
    state.link = { ...state.link!, passwordHash: null };
  });

  it('媒体端点无需通行证即可访问', async () => {
    const res = await request(app).get(mediaUrl());
    expect(res.status).toBe(200);
    expect(Buffer.from(res.body)).toEqual(MEDIA_BYTES);
  });

  it('视图接口直接返回内容与通行证', async () => {
    const res = await request(app).post(`/api/v1/public/share/${TOKEN}`).send({});
    expect(res.status).toBe(200);
    expect(res.body.share.requiresPassword).toBe(false);
    expect(typeof res.body.share.mediaToken).toBe('string');
  });
});
