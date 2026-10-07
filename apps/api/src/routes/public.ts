import { Router } from 'express';
import { asyncHandler } from '../http/asyncHandler';
import { publicLimiter } from '../middleware/rateLimit';
import * as shareService from '../services/shareService';
import { mediaFileTarget } from '../services/mediaService';
import { sendStoredFile } from '../http/sendFile';
import { notFound } from '../http/errors';

export const publicRouter = Router();

publicRouter.post(
  '/share/:token',
  publicLimiter,
  asyncHandler(async (req, res) => {
    const password = typeof req.body?.password === 'string' ? req.body.password : undefined;
    res.json({ share: await shareService.viewShareLink(req.params.token!, password) });
  }),
);

publicRouter.get(
  '/share/:token/media/:mediaId/:variant',
  publicLimiter,
  asyncHandler(async (req, res) => {
    const variant = req.params.variant!;
    if (!['raw', 'thumb', 'waveform', 'download'].includes(variant)) throw notFound('媒体不存在');
    // <img>/<audio> 无法带自定义头，访客媒体凭证通过查询参数传递；
    // 凭证必须是口令校验通过后由 /share/:token 下发、且绑定本链接的短时签名
    const grant = typeof req.query.st === 'string' && req.query.st.length > 0 ? req.query.st : undefined;
    const media = await shareService.assertPublicMedia(grant, req.params.token!, req.params.mediaId!);
    const target = await mediaFileTarget(media, variant as 'raw' | 'thumb' | 'waveform' | 'download');
    sendStoredFile(req, res, {
      key: target.key,
      size: target.size,
      mimeType: target.mimeType,
      filename: media.originalName,
      download: variant === 'download',
    });
  }),
);

