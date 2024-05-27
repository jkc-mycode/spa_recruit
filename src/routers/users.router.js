import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import bcrypt from 'bcrypt';

import Joi from 'joi';
import { USER_GENDER } from '../constants/user.gender.constant.js';

const router = express.Router();

const signUpSchema = Joi.object({
    email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'kr'] } })
        .required()
        .messages({
            'string.base': '이메일은 문자열이어야 합니다.',
            'string.empty': '이메일을 입력해주세요.',
            'string.email': '이메일의 형식이 올바르지 않습니다',
            'any.required': '이메일을 입력해주세요.',
        }),
    password: Joi.string().required().pattern(new RegExp('^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{6,15}$')).messages({
        'string.base': '비밀번호는 문자열이어야 합니다.',
        'string.empty': '비밀번호를 입력해주세요.',
        'any.required': '비밀번호를 입력해주세요.',
        'string.pattern.base': '비밀번호가 형식에 맞지 않습니다. (영문, 숫자, 특수문자 포함 6~15자)',
    }),
    passwordConfirm: Joi.string().required().pattern(new RegExp('^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{6,15}$')).messages({
        'string.base': '비밀번호 확인은 문자열이어야 합니다.',
        'string.empty': '비밀번호 확인을 입력해주세요.',
        'any.required': '비밀번호 확인을 입력해주세요.',
        'string.pattern.base': '비밀번호 확인의 형식이 맞지 않습니다. (영문, 숫자, 특수문자 포함 6~15자)',
    }),
    name: Joi.string().required().messages({
        'string.base': '이름은 문자열이어야 합니다.',
        'string.empty': '이름을 입력해주세요.',
        'any.required': '이름을 입력해주세요.',
    }),
    age: Joi.number().integer().required().messages({
        'number.base': '나이는 정수를 입력해주세요.',
        'any.required': '나이를 입력해주세요.',
    }),
    gender: Joi.string()
        .valid(...Object.values(USER_GENDER))
        .required()
        .messages({
            'string.base': '성별은 문자열이어야 합니다.',
            'any.only': '성별은 [MALE, FEMALE] 중 하나여야 합니다.',
        }),
    profileImage: Joi.string().required().messages({
        'string.base': '프로필 사진은 문자열이어야 합니다.',
        'string.empty': '프로필 사진을 입력해주세요.',
        'any.required': '프로필 사진을 입력해주세요.',
    }),
});

// 회원가입 API
router.post('/auth/sign-up', async (req, res, next) => {
    try {
        // 사용자 입력 유효성 검사
        const validation = await signUpSchema.validateAsync(req.body);
        const { email, password, passwordConfirm, name, age, gender, profileImage } = validation;

        // 이메일 중복 확인
        const isExistUser = await prisma.users.findFirst({ where: { email } });
        if (isExistUser) {
            return res.status(400).json({ message: '이미 가입 된 사용자입니다.' });
        }

        // 비밀번호 확인 결과
        if (password !== passwordConfirm) {
            return res.status(400).json({ message: '입력 한 두 비밀번호가 일치하지 않습니다.' });
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

        return res.status(201).json({ message: '회원가입에 성공했습니다.', data: { userData } });
    } catch (err) {
        next(err);
    }
});

export default router;
