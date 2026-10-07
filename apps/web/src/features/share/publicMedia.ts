import type { Media } from '../../api/types';

/**
 * 公开分享页的媒体地址统一走访客端点。
 *
 * 安全约定：这些地址必须带上口令校验通过后服务端下发的访客媒体凭证（st），
 * 媒体端点复用与查看分享相同的访问校验，未验证口令不会返回任何字节。
 * 因此这里**不能**再附加登录 access token（见 mediaSrc），二者是不同凭证。
 */

const VARIANT_SUFFIX = /\/(raw|thumb|waveform|download)$/;

function publicMediaBase(token: string, mediaId: string, variant: string): string {
  return `/api/v1/public/share/${token}/media/${mediaId}/${variant}`;
}

function withGrant(url: string, grant: string): string {
  return `${url}${url.includes('?') ? '&' : '?'}st=${encodeURIComponent(grant)}`;
}

/** 从服务端返回的家庭域媒体地址推断 variant，改写到公开分享端点并附上访客凭证。 */
export function toPublicMediaUrl(token: string, mediaId: string, familyUrl: string | null, grant: string): string | null {
  if (!familyUrl) return null;
  const variant = VARIANT_SUFFIX.exec(familyUrl)?.[1] ?? 'raw';
  return withGrant(publicMediaBase(token, mediaId, variant), grant);
}

/** 把分享视图里的媒体 DTO 全部改写成带访客凭证的公开地址。 */
export function toPublicMedia(token: string, media: Media, grant: string): Media {
  return {
    ...media,
    rawUrl: toPublicMediaUrl(token, media.id, media.rawUrl, grant) ?? media.rawUrl,
    thumbUrl: toPublicMediaUrl(token, media.id, media.thumbUrl, grant),
    waveformUrl: toPublicMediaUrl(token, media.id, media.waveformUrl, grant),
  };
}
