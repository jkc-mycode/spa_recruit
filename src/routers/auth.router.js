import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import authRefreshTokenMiddleware from '../middlewares/auth.refresh.token.middleware.js';

import { signUpSchema, signInSchema } from '../schemas/joi.schema.js';
import { HTTP_STATUS } from '../constants/http-status.constant.js';
import { MESSAGES } from '../constants/message.constant.js';

const router = express.Router();

// 회원가입 API
router.post('/auth/sign-up', async (req, res, next) => {
    try {
        // 사용자 입력 유효성 검사
        const validation = await signUpSchema.validateAsync(req.body);
        const { email, password, passwordConfirm, name, age, gender, profileImage } = validation;

        // 이메일 중복 확인
        const isExistUser = await prisma.user.findFirst({ where: { email } });
        if (isExistUser) {
            return res.status(HTTP_STATUS.CONFLICT).json({ status: HTTP_STATUS.CONFLICT, message: MESSAGES.AUTH.COMMON.EMAIL.DUPLICATED });
        }

        // 비밀번호 확인 결과
        if (password !== passwordConfirm) {
            return res
                .status(HTTP_STATUS.BAD_REQUEST)
                .json({ status: HTTP_STATUS.BAD_REQUEST, message: MESSAGES.AUTH.COMMON.PASSWORD_CONFIRM.INCONSISTENT });
        }

        // 비밀번호 암호화
        const hashedPassword = await bcrypt.hash(password, 10);

        // 사용자 생성
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                name,
                age,
                gender: gender.toUpperCase(),
                profileImage,
            },
        });

        const { password: pw, ...userData } = user;

        return res.status(HTTP_STATUS.CREATED).json({ status: HTTP_STATUS.CREATED, message: MESSAGES.AUTH.SIGN_UP.SUCCEED, data: { userData } });
    } catch (err) {
        next(err);
    }
});

// 로그인 API
router.post('/auth/sign-in', async (req, res, next) => {
    try {
        const validation = await signInSchema.validateAsync(req.body);
        const { email, password } = validation;

        // 입력받은 이메일로 사용자 조회
        const user = await prisma.user.findFirst({ where: { email } });
        if (!user) {
            return res.status(HTTP_STATUS.UNAUTHORIZED).json({ status: HTTP_STATUS.UNAUTHORIZED, message: MESSAGES.AUTH.COMMON.UNAUTHORIZED });
        }

        // 사용자 비밀번호와 입력한 비밀번호 일치 확인
        if (!(await bcrypt.compare(password, user.password))) {
            return res.status(HTTP_STATUS.UNAUTHORIZED).json({ status: HTTP_STATUS.UNAUTHORIZED, message: MESSAGES.AUTH.COMMON.UNAUTHORIZED });
        }

        // 로그인 성공하면 JWT 토큰 발급
        const AccessToken = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET_KEY, { expiresIn: '12h' });
        const RefreshToken = jwt.sign({ userId: user.userId }, process.env.REFRESH_TOKEN_SECRET_KEY, { expiresIn: '7d' });
        // res.setHeader('authorization', `Bearer ${AccessToken}`);

        // 현재 사용자의 Refresh토큰이 DB에 있는지 조회
        const refreshToken = await prisma.refreshToken.findFirst({ where: { UserId: user.userId } });
        if (!refreshToken) {
            // 없으면 새로운 토큰 생성
            await prisma.refreshToken.create({
                data: {
                    UserId: user.userId,
                    token: RefreshToken,
                    ip: req.ip,
                    userAgent: req.headers['user-agent'],
                },
            });
        } else {
            // 있으면 토큰 갱신
            await prisma.refreshToken.update({
                where: { UserId: user.userId },
                data: {
                    token: RefreshToken,
                    ip: req.ip,
                    userAgent: req.headers['user-agent'],
                    createdAt: new Date(Date.now()),
                },
            });
        }

        return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.AUTH.SIGN_IN, data: { AccessToken, RefreshToken } });
    } catch (err) {
        next(err);
    }
});

// 토큰 재발급 API
router.post('/auth/refresh', authRefreshTokenMiddleware, async (req, res, next) => {
    try {
        // 사용자 정보 가져옴
        const user = req.user;

        // Access Token 재발급 (12시간)
        const AccessToken = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET_KEY, { expiresIn: '12h' });

        // Refresh Token 재발급 (7일)
        const RefreshToken = jwt.sign({ userId: user.userId }, process.env.REFRESH_TOKEN_SECRET_KEY, { expiresIn: '7d' });
        await prisma.refreshToken.update({
            where: { UserId: user.userId },
            data: {
                token: RefreshToken,
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                createdAt: new Date(Date.now()),
            },
        });

        return res
            .status(HTTP_STATUS.CREATED)
            .json({ status: HTTP_STATUS.CREATED, message: MESSAGES.AUTH.TOKEN_REFRESH.SUCCEED, data: { AccessToken, RefreshToken } });
    } catch (err) {
        next(err);
    }
});

// 로그아웃 API
router.post('/auth/sign-out', authRefreshTokenMiddleware, async (req, res, next) => {
    try {
        // 사용자 정보 가져옴
        const user = req.user;

        // DB에서 Refresh Token 삭제
        const deletedUserId = await prisma.refreshToken.delete({
            where: { UserId: user.userId },
            select: { UserId: true },
        });

        return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.AUTH.SIGN_OUT.SUCCEED, data: { deletedUserId } });
    } catch (err) {
        next(err);
    }
});

export default router;
