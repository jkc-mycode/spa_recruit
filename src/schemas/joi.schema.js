import Joi from 'joi';
import { USER_GENDER } from '../constants/user.gender.constant.js';
import { RESUME_STATE } from '../constants/resume.state.constant.js';
import { MESSAGES } from '../constants/message.constant.js';

// 회원가입 유효성 검사
export const signUpSchema = Joi.object({
    email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'kr'] } })
        .required()
        .messages({
            'string.base': MESSAGES.AUTH.COMMON.EMAIL.BASE,
            'string.empty': MESSAGES.AUTH.COMMON.EMAIL.REQUIRED,
            'string.email': MESSAGES.AUTH.COMMON.EMAIL.EMAIL,
            'any.required': MESSAGES.AUTH.COMMON.EMAIL.REQUIRED,
        }),
    password: Joi.string().required().pattern(new RegExp('^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{6,15}$')).messages({
        'string.base': MESSAGES.AUTH.COMMON.PASSWORD.BASE,
        'string.empty': MESSAGES.AUTH.COMMON.PASSWORD.REQUIRED,
        'any.required': MESSAGES.AUTH.COMMON.PASSWORD.REQUIRED,
        'string.pattern.base': MESSAGES.AUTH.COMMON.PASSWORD.PATTERN,
    }),
    passwordConfirm: Joi.string().required().pattern(new RegExp('^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{6,15}$')).messages({
        'string.base': MESSAGES.AUTH.COMMON.PASSWORD_CONFIRM.BASE,
        'string.empty': MESSAGES.AUTH.COMMON.PASSWORD_CONFIRM.REQUIRED,
        'any.required': MESSAGES.AUTH.COMMON.PASSWORD_CONFIRM.REQUIRED,
        'string.pattern.base': MESSAGES.AUTH.COMMON.PASSWORD_CONFIRM.PATTERN,
    }),
    name: Joi.string().required().messages({
        'string.base': MESSAGES.AUTH.COMMON.NAME.BASE,
        'string.empty': MESSAGES.AUTH.COMMON.NAME.REQUIRED,
        'any.required': MESSAGES.AUTH.COMMON.NAME.REQUIRED,
    }),
    age: Joi.number().integer().required().messages({
        'number.base': MESSAGES.AUTH.COMMON.AGE.BASE,
        'any.required': MESSAGES.AUTH.COMMON.AGE.REQUIRED,
    }),
    gender: Joi.string()
        .valid(...Object.values(USER_GENDER))
        .required()
        .messages({
            'string.base': MESSAGES.AUTH.COMMON.GENDER.BASE,
            'any.only': MESSAGES.AUTH.COMMON.GENDER.ONLY,
        }),
    profileImage: Joi.string().required().messages({
        'string.base': MESSAGES.AUTH.COMMON.PROFILE_IMAGE.BASE,
        'string.empty': MESSAGES.AUTH.COMMON.PROFILE_IMAGE.REQUIRED,
        'any.required': MESSAGES.AUTH.COMMON.PROFILE_IMAGE.REQUIRED,
    }),
});

// 로그인 유효성 검사
export const signInSchema = Joi.object({
    email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'kr'] } })
        .required()
        .messages({
            'string.base': MESSAGES.AUTH.COMMON.EMAIL.BASE,
            'string.empty': MESSAGES.AUTH.COMMON.EMAIL.REQUIRED,
            'string.email': MESSAGES.AUTH.COMMON.EMAIL.EMAIL,
            'any.required': MESSAGES.AUTH.COMMON.EMAIL.REQUIRED,
        }),
    password: Joi.string().required().pattern(new RegExp('^(?=.*[a-zA-Z])(?=.*[!@#$%^*+=-])(?=.*[0-9]).{6,15}$')).messages({
        'string.base': MESSAGES.AUTH.COMMON.PASSWORD.BASE,
        'string.empty': MESSAGES.AUTH.COMMON.PASSWORD.REQUIRED,
        'any.required': MESSAGES.AUTH.COMMON.PASSWORD.REQUIRED,
        'string.pattern.base': MESSAGES.AUTH.COMMON.PASSWORD.PATTERN,
    }),
});

// 이력서 작성 유효성 검사
export const resumeWriteSchema = Joi.object({
    title: Joi.string().required().messages({
        'string.base': MESSAGES.RESUMES.COMMON.TITLE,
        'string.empty': MESSAGES.RESUMES.COMMON.TITLE.REQUIRED,
        'any.required': MESSAGES.RESUMES.COMMON.TITLE.REQUIRED,
    }),
    introduce: Joi.string().min(150).required().messages({
        'string.base': MESSAGES.RESUMES.COMMON.INTRODUCE.BASE,
        'string.min': MESSAGES.RESUMES.COMMON.INTRODUCE.MIN,
        'string.empty': MESSAGES.RESUMES.COMMON.INTRODUCE.REQUIRED,
        'any.required': MESSAGES.RESUMES.COMMON.INTRODUCE.REQUIRED,
    }),
});

// 이력서 상태 변경 유효성 검사
export const resumeStateSchema = Joi.object({
    state: Joi.string()
        .valid(...Object.values(RESUME_STATE))
        .required()
        .messages({
            'string.base': MESSAGES.RESUMES.COMMON.STATE.BASE,
            'string.empty': MESSAGES.RESUMES.COMMON.STATE.REQUIRED,
            'any.required': MESSAGES.RESUMES.COMMON.STATE.REQUIRED,
            'any.only': MESSAGES.RESUMES.COMMON.STATE.ONLY,
        }),
    reason: Joi.string().required().messages({
        'string.base': MESSAGES.RESUMES.COMMON.REASON.BASE,
        'string.empty': MESSAGES.RESUMES.COMMON.REASON.REQUIRED,
        'any.required': MESSAGES.RESUMES.COMMON.REASON.REQUIRED,
    }),
});
