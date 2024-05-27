import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import { signUpSchema, signInSchema } from '../schemas/joi.schema.js';

const router = express.Router();

// 회원가입 API
router.post('/auth/sign-up', async (req, res, next) => {
    try {
        // 사용자 입력 유효성 검사
        const validation = await signUpSchema.validateAsync(req.body);
        const { email, password, passwordConfirm, name, age, gender, profileImage } = validation;

        // 이메일 중복 확인
        const isExistUser = await prisma.users.findFirst({ where: { email } });
        if (isExistUser) {
            return res.status(400).json({ status: 400, message: '이미 가입 된 사용자입니다.' });
        }

        // 비밀번호 확인 결과
        if (password !== passwordConfirm) {
            return res.status(400).json({ status: 400, message: '입력 한 두 비밀번호가 일치하지 않습니다.' });
        }

        // 비밀번호 암호화
        const hashedPassword = await bcrypt.hash(password, 10);

        // 사용자 생성
        const user = await prisma.users.create({
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

        return res.status(201).json({ status: 201, message: '회원가입에 성공했습니다.', data: { userData } });
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
        const user = await prisma.users.findFirst({ where: { email } });
        if (!user) {
            return res.status(401).json({ status: 401, message: '인증 정보가 유효하지 않습니다.' });
        }

        // 사용자 비밀번호와 입력한 비밀번호 일치 확인
        if (!(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ status: 401, message: '인증 정보가 유효하지 않습니다.' });
        }

        // 로그인 성공하면 JWT 토큰 발급
        const AccessToken = jwt.sign({ userId: user.userId }, process.env.CUSTOMIZED_SECRET_KEY, { expiresIn: '12h' });
        res.cookie('Authorization', `Bearer ${AccessToken}`);

        return res.status(200).json({ status: 200, message: '로그인에 성공했습니다.', data: { AccessToken } });
    } catch (err) {
        next(err);
    }
});

export default router;
