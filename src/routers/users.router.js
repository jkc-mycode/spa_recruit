import express from 'express';
import authMiddleware from '../middlewares/auth.access.token.middleware.js';
import { HTTP_STATUS } from '../constants/http-status.constant.js';
import { MESSAGES } from '../constants/message.constant.js';

const router = express.Router();

// 내 정보 조회 API
router.get('/', authMiddleware, async (req, res) => {
    const user = req.user;

    return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.USER.READ.SUCCEED, data: { user } });
});

export default router;
