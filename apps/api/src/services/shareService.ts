import type { Prisma } from '@prisma/client';
import jwt from 'jsonwebtoken';
import { prisma } from '../db';
import { config } from '../config';
import { notFound, unauthenticated } from '../http/errors';
import { randomToken, sha256Hex } from '../utils/crypto';
import { hashPassword, verifyPassword } from './authService';
import * as audit from './auditService';
import { shareMediaUrl, toItemDto, toShareLinkDto } from '../serializers';
import { itemWithAccess, type FamilyContext } from './permissionService';

export interface ActorMeta {
  ip?: string | null;
  userAgent?: string | null;
}

export async function createShareLink(
  userId: string,
  ctx: FamilyContext,
  input: { itemIds: string[]; expiresInDays: number; password?: string | null; label?: string | null },
  meta: ActorMeta,
) {
  // 只能分享自己有权看到的条目，避免借分享链接绕过可见性
  for (const itemId of input.itemIds) {
    await itemWithAccess(userId, ctx, itemId);
  }

  const token = randomToken(24);
  const passwordHash = input.password ? await hashPassword(input.password) : null;
  const expiresAt = new Date(Date.now() + input.expiresInDays * 86_400_000);

  const link = await prisma.$transaction(async (tx) => {
    const created = await tx.shareLink.create({
      data: {
        familyId: ctx.familyId,
        tokenHash: sha256Hex(token),
        passwordHash,
        label: input.label ?? null,
        expiresAt,
        createdBy: userId,
        items: { create: input.itemIds.map((itemId) => ({ itemId })) },
      },
    });
    await audit.record(
      {
        familyId: ctx.familyId,
        actorId: userId,
        action: 'share.create',
        targetType: 'share_link',
        targetId: created.id,
        diff: { itemCount: input.itemIds.length, expiresAt: expiresAt.toISOString() } as Prisma.InputJsonValue,
        ...meta,
      },
      tx,
    );
    return created;
  });

  return { ...toShareLinkDto(link, token), token };
}

export async function listShareLinks(ctx: FamilyContext) {
  const links = await prisma.shareLink.findMany({
    where: { familyId: ctx.familyId },
    orderBy: { createdAt: 'desc' },
    take: 100,
  });
  return links.map((l) => toShareLinkDto(l));
}

export async function revokeShareLink(actorId: string, ctx: FamilyContext, linkId: string, meta: ActorMeta) {
  const link = await prisma.shareLink.findFirst({ where: { id: linkId, familyId: ctx.familyId } });
  if (!link) throw notFound('分享链接不存在');
  await prisma.$transaction(async (tx) => {
    await tx.shareLink.update({ where: { id: linkId }, data: { revokedAt: new Date() } });
    await audit.record(
      {
        familyId: ctx.familyId,
        actorId,
        action: 'share.revoke',
        targetType: 'share_link',
        targetId: linkId,
        ...meta,
      },
      tx,
    );
  });
}

export interface PublicShareView {
  familyName: string;
  label: string | null;
  expiresAt: string;
  requiresPassword: boolean;
  /** 媒体通行证：口令验证通过后签发，访客凭它取媒体字节（<img>/<audio> 无法走 POST 带口令） */
  mediaToken: string | null;
  items: ReturnType<typeof toItemDto>[];
}

/**
 * 媒体通行证：短期 JWT，绑定具体分享链接与口令哈希指纹。
 * 口令一旦更换，旧通行证立即失效；链接撤销/过期则由 loadLink 在每次请求时把关。
 */
const MEDIA_GRANT_TTL_S = 12 * 3600;

interface MediaGrantPayload {
  scope: 'share-media';
  shareId: string;
  ph: string;
}

type GrantLink = { id: string; passwordHash: string | null };

// 导出供单元测试与路由层复用；签发只发生在 viewShareLink 口令校验通过之后
export function signMediaGrant(link: GrantLink): string {
  const payload: MediaGrantPayload = {
    scope: 'share-media',
    shareId: link.id,
    ph: sha256Hex(link.passwordHash ?? ''),
  };
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn: MEDIA_GRANT_TTL_S });
}

export function verifyMediaGrant(grant: string, link: GrantLink): boolean {
  try {
    const decoded = jwt.verify(grant, config.JWT_SECRET);
    if (typeof decoded === 'string') return false;
    const p = decoded as jwt.JwtPayload & Partial<MediaGrantPayload>;
    return p.scope === 'share-media' && p.shareId === link.id && p.ph === sha256Hex(link.passwordHash ?? '');
  } catch {
    return false;
  }
}

async function loadLink(token: string) {
  const link = await prisma.shareLink.findUnique({
    where: { tokenHash: sha256Hex(token) },
    include: { family: { select: { id: true, name: true } } },
  });
  if (!link) throw notFound('分享链接不存在或已被撤销');
  if (link.revokedAt) throw notFound('分享链接已被撤销');
  if (link.expiresAt.getTime() < Date.now()) throw notFound('分享链接已过期');
  return link;
}

export async function viewShareLink(token: string, password?: string): Promise<PublicShareView> {
  const link = await loadLink(token);

  if (link.passwordHash) {
    if (!password) {
      return { familyName: link.family.name, label: link.label, expiresAt: link.expiresAt.toISOString(), requiresPassword: true, mediaToken: null, items: [] };
    }
    const ok = await verifyPassword(password, link.passwordHash);
    if (!ok) throw unauthenticated('访问密码不正确');
  }

  const rows = await prisma.item.findMany({
    where: { shareLinks: { some: { shareLinkId: link.id } }, deletedAt: null, status: { not: 'trashed' } },
    include: {
      media: { where: { deletedAt: null }, orderBy: { sortOrder: 'asc' } },
      people: { include: { person: true } },
      _count: { select: { notes: true, media: true } },
    },
    orderBy: { sortAt: 'desc' },
  });

  await prisma.shareLink.update({
    where: { id: link.id },
    data: { accessCount: { increment: 1 }, lastAccessAt: new Date() },
  });

  return {
    familyName: link.family.name,
    label: link.label,
    expiresAt: link.expiresAt.toISOString(),
    requiresPassword: false,
    mediaToken: signMediaGrant(link),
    // 访客媒体一律走公开端点，由它统一校验口令通行证
    items: rows.map((r) => toItemDto(r, link.familyId, (mediaId, kind) => shareMediaUrl(token, mediaId, kind))),
  };
}

/**
 * 访客读媒体：与 viewShareLink 同一道门——链接带密码时，必须持有口令换来的媒体通行证，
 * 否则一律 401，不允许绕过口令直接取走媒体。
 */
export async function assertPublicMedia(token: string, mediaId: string, grant?: string) {
  const link = await loadLink(token);
  if (link.passwordHash && (!grant || !verifyMediaGrant(grant, link))) {
    throw unauthenticated('请先通过访问密码验证');
  }
  const media = await prisma.itemMedia.findFirst({
    where: { id: mediaId, deletedAt: null, item: { shareLinks: { some: { shareLinkId: link.id } } } },
  });
  if (!media) throw notFound('媒体不存在');
  return media;
}

