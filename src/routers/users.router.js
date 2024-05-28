import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import authMiddleware from '../middlewares/auth.access.token.middleware.js';

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

    return res.status(200).json({ message: '내 정보 조회에 성공했습니다.', data: { user } });
});

export default router;
