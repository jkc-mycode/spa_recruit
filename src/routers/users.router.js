import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import authMiddleware from '../middlewares/auth.access.token.middleware.js';
import { HTTP_STATUS } from '../constants/http-status.constant.js';
import { MESSAGES } from '../constants/message.constant.js';

const router = express.Router();

// 내 정보 조회 API
router.get('/users', authMiddleware, async (req, res) => {
    const { userId } = req.user;

    const user = await prisma.users.findFirst({
        where: { userId },
        select: {
            userId: true,
            email: true,
            name: true,
            role: true,
            createdAt: true,
            updatedAt: true,
        },
    });

    return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.USERS.READ.SUCCEED, data: { user } });
});

export default router;
