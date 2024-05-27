import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import authMiddleware from '../middlewares/auth.middleware.js';

import { resumeWriteSchema } from '../schemas/joi.schema.js';

const router = express.Router();

//이력서 생성 API
router.post('/resumes', authMiddleware, async (req, res, next) => {
    try {
        // 사용자 ID를 가져옴
        const { userId } = req.user;
        // 사용자가 입력한 제목과 자기소개에 대한 유효성 검사
        const validation = await resumeWriteSchema.validateAsync(req.body);
        const { title, introduce } = validation;

        // 이력서 생성
        const resume = await prisma.resumes.create({
            data: {
                title,
                introduce,
                UserId: +userId,
            },
        });

        return res.status(201).json({ status: 201, message: '이력서 생성에 성공했습니다.', data: { resume } });
    } catch (err) {
        next(err);
    }
});

// 이력서 목록 조회 API
router.get('/resumes', authMiddleware, async (req, res) => {
    // 사용자 ID를 가져옴
    const { userId } = req.user;
    // 정렬 조건을 req.query로 가져옴
    const sortType = req.query.sort.toLowerCase();

    const resumes = await prisma.resumes.findMany({
        where: { UserId: +userId },
        select: {
            resumeId: true,
            User: { select: { name: true } },
            title: true,
            introduce: true,
            state: true,
            createdAt: true,
            updatedAt: true,
        },
        orderBy: { createdAt: sortType },
    });

    return res.status(200).json({ status: 200, message: '이력서 목록 조회에 성공했습니다.', data: { resumes } });
});

// 이력서 상세 조회 API
router.get('/resumes/:resumeId', authMiddleware, async (req, res) => {
    // 사용자 ID를 가져옴
    const { userId } = req.user;
    // 이력서 ID를 가져옴
    const { resumeId } = req.params;

    // 이력서 ID, 작성자 ID가 모두 일치한 이력서 조회
    const resume = await prisma.resumes.findFirst({
        where: { resumeId: +resumeId, UserId: +userId },
        select: {
            resumeId: true,
            User: { select: { name: true } },
            title: true,
            introduce: true,
            state: true,
            createdAt: true,
            updatedAt: true,
        },
    });
    if (!resume) {
        return res.status(401).json({ status: 401, message: '이력서가 존재하지 않습니다.' });
    }

    return res.status(200).json({ status: 200, message: '이력서 상세 조회에 성공했습니다.', data: { resume } });
});

export default router;
