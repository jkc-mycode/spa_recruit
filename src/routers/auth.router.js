import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import jwt from 'jsonwebtoken';
import authRefreshTokenMiddleware from '../middlewares/auth.refresh.token.middleware.js';

const router = express.Router();

// 토큰 재발급 API
router.post('/auth/refresh', authRefreshTokenMiddleware, async (req, res, next) => {
    try {
        // 사용자 정보 가져옴
        const user = req.user;

        // Access Token 재발급 (12시간)
        const AccessToken = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET_KEY, { expiresIn: '12h' });

        // Refresh Token 재발급 (7일)
        const RefreshToken = jwt.sign({ userId: user.userId }, process.env.REFRESH_TOKEN_SECRET_KEY, { expiresIn: '7d' });
        await prisma.refreshTokens.update({
            where: { UserId: user.userId },
            data: {
                token: RefreshToken,
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                createdAt: new Date(Date.now()),
            },
        });

        return res.status(201).json({ status: 201, message: '토큰 재발급에 성공했습니다.', data: { AccessToken, RefreshToken } });
    } catch (err) {
        next(err);
    }
});

export default router;
