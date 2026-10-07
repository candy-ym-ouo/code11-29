import { describe, expect, it } from 'vitest';
import { signAccessToken, signShareMediaToken, verifyShareMediaToken } from './tokenService';
import { AppError } from '../http/errors';

describe('访客媒体凭证', () => {
  it('签发后可验签，且 payload 绑定 linkId', () => {
    const token = signShareMediaToken('link-123');
    const payload = verifyShareMediaToken(token);
    expect(payload).toEqual({ kind: 'share-media', linkId: 'link-123' });
  });

  it('登录 access token 不能当作访客媒体凭证使用', () => {
    // access token 没有 kind: 'share-media' 声明，必须被拒绝，堵住凭证混用
    const accessToken = signAccessToken({ id: 'user-1', systemRole: 'user' });
    expect(() => verifyShareMediaToken(accessToken)).toThrowError(AppError);
  });

  it('伪造/篡改的 token 被拒绝', () => {
    const token = signShareMediaToken('link-123');
    const tampered = token.slice(0, -2) + (token.endsWith('a') ? 'b' : 'a');
    expect(() => verifyShareMediaToken(tampered)).toThrowError(AppError);
    expect(() => verifyShareMediaToken('not-a-jwt')).toThrowError(AppError);
  });

  it('他人链接签发的凭证无法通过当前链接的绑定校验（由调用方比对 linkId）', () => {
    const token = signShareMediaToken('link-A');
    const payload = verifyShareMediaToken(token);
    expect(payload.linkId).not.toBe('link-B');
  });
});
