import type { Prisma } from '@prisma/client';
import { prisma } from '../db';
import { notFound, unauthenticated } from '../http/errors';
import { randomToken, sha256Hex } from '../utils/crypto';
import { hashPassword, verifyPassword } from './authService';
import * as audit from './auditService';
import { toItemDto, toShareLinkDto } from '../serializers';
import { itemWithAccess, type FamilyContext } from './permissionService';
import { signShareMediaToken, verifyShareMediaToken } from './tokenService';

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
  /** 通过访问校验（含口令）后下发的访客媒体凭证；未通过时为 null，媒体端点一律拒绝 */
  mediaToken: string | null;
  items: ReturnType<typeof toItemDto>[];
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

/** 与查看分享完全相同的访问校验：链接有效 + 口令（如有）正确。 */
async function assertShareAccess(
  token: string,
  password?: string,
): Promise<{ ok: true; link: Awaited<ReturnType<typeof loadLink>> } | { ok: false; requiresPassword: true; link: Awaited<ReturnType<typeof loadLink>> }> {
  const link = await loadLink(token);
  if (link.passwordHash) {
    if (!password) return { ok: false, requiresPassword: true, link };
    const ok = await verifyPassword(password, link.passwordHash);
    if (!ok) throw unauthenticated('访问密码不正确');
  }
  return { ok: true, link };
}

export async function viewShareLink(token: string, password?: string): Promise<PublicShareView> {
  const access = await assertShareAccess(token, password);
  const link = access.link;

  if (!access.ok) {
    return {
      familyName: link.family.name,
      label: link.label,
      expiresAt: link.expiresAt.toISOString(),
      requiresPassword: true,
      mediaToken: null,
      items: [],
    };
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
    mediaToken: signShareMediaToken(link.id),
    items: rows.map((r) => toItemDto(r, link.familyId)),
  };
}

/**
 * 访客读媒体：必须证明 (1) 已通过与查看分享相同的访问校验——这里具体表现为
 * 持有口令校验通过后签发、且绑定本链接的访客媒体凭证；(2) 该媒体属于本链接
 * 覆盖的未删除条目。未验证口令（或无密码链接未取过凭证）一律不放行。
 */
export async function assertPublicMedia(grantToken: string | undefined, shareToken: string, mediaId: string) {
  const link = await loadLink(shareToken);
  if (!grantToken) throw unauthenticated('请先通过分享访问校验');

  const grant = verifyShareMediaToken(grantToken);
  if (grant.linkId !== link.id) throw unauthenticated('分享访问凭证无效');

  const media = await prisma.itemMedia.findFirst({
    where: {
      id: mediaId,
      deletedAt: null,
      item: {
        shareLinks: { some: { shareLinkId: link.id } },
        deletedAt: null,
        status: { not: 'trashed' },
      },
    },
  });
  if (!media) throw notFound('媒体不存在');
  return media;
}

