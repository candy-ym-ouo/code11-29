import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppError } from '../http/errors';
import { signShareMediaToken } from './tokenService';
import type { ShareLink } from '@prisma/client';

// 不连数据库：mock 掉 prisma 客户端。vi.hoisted 让 mock 变量可被提前到文件顶部的 vi.mock 使用
const mocks = vi.hoisted(() => ({
  findUnique: vi.fn(),
  findFirst: vi.fn(),
  findMany: vi.fn(),
  update: vi.fn(),
}));

vi.mock('../db', () => ({
  prisma: {
    shareLink: { findUnique: mocks.findUnique, update: mocks.update },
    itemMedia: { findFirst: mocks.findFirst },
    item: { findMany: mocks.findMany },
  },
}));

// argon2 很重，口令校验直接桩掉
vi.mock('./authService', () => ({
  hashPassword: vi.fn(async () => 'hash'),
  verifyPassword: vi.fn(async (pwd: string) => pwd === 'correct-horse'),
}));

import * as shareService from './shareService';

const { findUnique, findFirst, findMany, update } = mocks;

function makeLink(overrides: Partial<ShareLink> = {}): ShareLink {
  return {
    id: 'link-1',
    familyId: 'fam-1',
    tokenHash: 'th',
    passwordHash: null,
    label: null,
    expiresAt: new Date(Date.now() + 86_400_000),
    revokedAt: null,
    accessCount: 0,
    lastAccessAt: null,
    createdBy: 'user-1',
    createdAt: new Date(),
    ...overrides,
  } as ShareLink;
}

const linkWithFamily = (link: ShareLink) => ({ ...link, family: { id: 'fam-1', name: '张家' } });

describe('assertPublicMedia 访客媒体访问校验', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    findFirst.mockResolvedValue({ id: 'media-1', itemId: 'item-1', deletedAt: null });
    update.mockResolvedValue(undefined);
    findMany.mockResolvedValue([]);
  });

  it('未携带访客媒体凭证：即使链接无密码也拒绝（修复前可直接取走媒体）', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink()));
    await expect(shareService.assertPublicMedia(undefined, 'share-token', 'media-1')).rejects.toMatchObject({
      status: 401,
    });
    expect(findFirst).not.toHaveBeenCalled();
  });

  it('链接带密码但从未验证口令：没有可用凭证，拒绝', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink({ passwordHash: 'hash' })));
    await expect(shareService.assertPublicMedia(undefined, 'share-token', 'media-1')).rejects.toBeInstanceOf(AppError);
  });

  it('凭证绑定的是另一条链接：拒绝（防止拿 A 链接的凭证开 B 链接的媒体）', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink({ id: 'link-2' })));
    const grantFromOtherLink = signShareMediaToken('link-1');
    await expect(
      shareService.assertPublicMedia(grantFromOtherLink, 'share-token', 'media-1'),
    ).rejects.toMatchObject({ status: 401 });
    expect(findFirst).not.toHaveBeenCalled();
  });

  it('伪造凭证：拒绝，且不查媒体', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink()));
    await expect(shareService.assertPublicMedia('forged', 'share-token', 'media-1')).rejects.toBeInstanceOf(AppError);
    expect(findFirst).not.toHaveBeenCalled();
  });

  it('链接已撤销：持有效凭证也拒绝（撤销即时生效，不依赖凭证过期）', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink({ revokedAt: new Date() })));
    const grant = signShareMediaToken('link-1');
    await expect(shareService.assertPublicMedia(grant, 'share-token', 'media-1')).rejects.toMatchObject({
      status: 404,
    });
  });

  it('凭证有效且绑定本链接、媒体属于本链接条目：放行', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink()));
    const grant = signShareMediaToken('link-1');
    const media = await shareService.assertPublicMedia(grant, 'share-token', 'media-1');
    expect(media.id).toBe('media-1');
  });

  it('媒体不属于本链接覆盖的条目：404', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink()));
    findFirst.mockResolvedValue(null);
    const grant = signShareMediaToken('link-1');
    await expect(shareService.assertPublicMedia(grant, 'share-token', 'other-media')).rejects.toMatchObject({
      status: 404,
    });
  });
});

describe('viewShareLink 口令探测', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    update.mockResolvedValue(undefined);
    findMany.mockResolvedValue([]);
    findFirst.mockResolvedValue({ id: 'media-1', itemId: 'item-1', deletedAt: null });
  });

  it('需要密码且未提供口令：只回元数据，不下发媒体凭证', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink({ passwordHash: 'hash' })));
    const view = await shareService.viewShareLink('share-token');
    expect(view.requiresPassword).toBe(true);
    expect(view.mediaToken).toBeNull();
    expect(view.items).toEqual([]);
    expect(findMany).not.toHaveBeenCalled();
  });

  it('口令正确：下发访客媒体凭证', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink({ passwordHash: 'hash' })));
    const view = await shareService.viewShareLink('share-token', 'correct-horse');
    expect(view.requiresPassword).toBe(false);
    expect(view.mediaToken).toBeTruthy();
    // 下发的凭证应当能通过媒体端点的校验
    await expect(
      shareService.assertPublicMedia(view.mediaToken!, 'share-token', 'media-1'),
    ).resolves.toBeTruthy();
  });

  it('口令错误：401', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink({ passwordHash: 'hash' })));
    await expect(shareService.viewShareLink('share-token', 'wrong')).rejects.toMatchObject({ status: 401 });
  });

  it('无密码链接：正常打开时也下发凭证（媒体端点统一要求凭证）', async () => {
    findUnique.mockResolvedValue(linkWithFamily(makeLink()));
    const view = await shareService.viewShareLink('share-token');
    expect(view.requiresPassword).toBe(false);
    expect(view.mediaToken).toBeTruthy();
  });
});
