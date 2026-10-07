import { describe, expect, it } from 'vitest';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { signMediaGrant, verifyMediaGrant } from './shareService';
import { signAccessToken } from './tokenService';

const protectedLink = { id: 'link-1', passwordHash: 'argon2-hash-of-password' };
const openLink = { id: 'link-2', passwordHash: null };

describe('分享链接媒体通行证', () => {
  it('签发的通行证可以校验通过', () => {
    const grant = signMediaGrant(protectedLink);
    expect(verifyMediaGrant(grant, protectedLink)).toBe(true);
  });

  it('通行证不能串用到别的分享链接', () => {
    const grant = signMediaGrant(protectedLink);
    expect(verifyMediaGrant(grant, { ...protectedLink, id: 'link-other' })).toBe(false);
    expect(verifyMediaGrant(grant, openLink)).toBe(false);
  });

  it('口令更换后旧通行证立即失效', () => {
    const grant = signMediaGrant(protectedLink);
    const rotated = { ...protectedLink, passwordHash: 'argon2-hash-of-new-password' };
    expect(verifyMediaGrant(grant, rotated)).toBe(false);
  });

  it('登录用的 access token 不能冒充媒体通行证', () => {
    const accessToken = signAccessToken({ id: 'user-1', systemRole: 'member' });
    expect(verifyMediaGrant(accessToken, protectedLink)).toBe(false);
  });

  it('伪造/损坏的通行证被拒绝', () => {
    expect(verifyMediaGrant('not-a-jwt', protectedLink)).toBe(false);
    const forged = jwt.sign(
      { scope: 'share-media', shareId: protectedLink.id, ph: 'wrong-fingerprint' },
      config.JWT_SECRET,
    );
    expect(verifyMediaGrant(forged, protectedLink)).toBe(false);
    const wrongSecret = jwt.sign(
      { scope: 'share-media', shareId: protectedLink.id, ph: 'whatever' },
      'some-other-secret-that-is-long-enough',
    );
    expect(verifyMediaGrant(wrongSecret, protectedLink)).toBe(false);
  });

  it('过期的通行证被拒绝', () => {
    const expired = jwt.sign(
      { scope: 'share-media', shareId: protectedLink.id, ph: 'whatever' },
      config.JWT_SECRET,
      { expiresIn: -10 },
    );
    expect(verifyMediaGrant(expired, protectedLink)).toBe(false);
  });
});
