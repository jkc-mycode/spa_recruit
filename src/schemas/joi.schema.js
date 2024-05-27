import Joi from 'joi';
import { USER_GENDER } from '../constants/user.gender.constant.js';

// 회원가입 유효성 검사
export const signUpSchema = Joi.object({
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

// 로그인 유효성 검사
export const signInSchema = Joi.object({
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
});

// 이력서 작성 유효성 검사
export const resumeWriteSchema = Joi.object({
    title: Joi.string().required().messages({
        'string.base': '제목은 문자열이어야 합니다.',
        'string.empty': '제목을 입력해주세요.',
        'any.required': '제목을 입력해주세요.',
    }),
    introduce: Joi.string().min(150).required().messages({
        'string.base': '제목은 문자열이어야 합니다.',
        'string.min': '자기소개는 150자 이상 작성해야 합니다.',
        'string.empty': '제목을 입력해주세요.',
        'any.required': '제목을 입력해주세요.',
    }),
});
