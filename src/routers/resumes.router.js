import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import authMiddleware from '../middlewares/auth.middleware.js';
import { requiredRoles } from '../middlewares/role.middleware.js';

import { resumeWriteSchema, resumeStateSchema } from '../schemas/joi.schema.js';
import { Prisma } from '@prisma/client';

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
    // 사용자를 가져옴
    const user = req.user;
    // 정렬 조건을 req.query로 가져옴
    const sortType = req.query.sort.toLowerCase();
    // 필터링 조건을 가져옴
    const stateFilter = req.query.status.toUpperCase();

    const resumes = await prisma.resumes.findMany({
        where: {
            // AND 배열 연산을 통해서 필터링
            AND: [user.role === 'RECRUITER' ? {} : { UserId: +user.userId }, stateFilter === '' ? {} : { state: stateFilter }],
        },
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
    // 사용자를 가져옴
    const user = req.user;
    // 이력서 ID를 가져옴
    const { resumeId } = req.params;

    // 이력서 ID, 작성자 ID가 모두 일치한 이력서 조회
    const resume = await prisma.resumes.findFirst({
        where: user.role === 'RECRUITER' ? { resumeId: +resumeId } : { resumeId: +resumeId, UserId: +user.userId },
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

// 이력서 수정 API
router.patch('/resumes/:resumeId', authMiddleware, async (req, res, next) => {
    try {
        // 사용자 ID를 가져옴
        const { userId } = req.user;
        // 이력서 ID를 가져옴
        const { resumeId } = req.params;
        // 제목, 자기소개를 가져옴 (유효성 검사 진행)
        const validation = await resumeWriteSchema.validateAsync(req.body);
        const { title, introduce } = validation;

        // 이력서 ID, 작성자 ID가 모두 일치한 이력서 조회
        const resume = await prisma.resumes.findFirst({
            where: { resumeId: +resumeId, UserId: +userId },
        });
        if (!resume) {
            return res.status(401).json({ status: 401, message: '이력서가 존재하지 않습니다.' });
        }

        // 이력서 수정
        const updatedResume = await prisma.resumes.update({
            where: { resumeId: +resumeId, UserId: +userId },
            data: { title, introduce },
        });

        return res.status(201).json({ status: 201, message: '이력서 수정이 성공했습니다.', data: { updatedResume } });
    } catch (err) {
        next(err);
    }
});

// 이력서 삭제 API
router.delete('/resumes/:resumeId', authMiddleware, async (req, res, next) => {
    try {
        // 사용자 ID를 가져옴
        const { userId } = req.user;
        // 이력서 ID를 가져옴
        const { resumeId } = req.params;

        // 이력서 ID, 작성자 ID가 모두 일치한 이력서 조회
        const resume = await prisma.resumes.findFirst({
            where: { resumeId: +resumeId, UserId: +userId },
        });
        if (!resume) {
            return res.status(401).json({ status: 401, message: '이력서가 존재하지 않습니다.' });
        }
        const deletedResume = await prisma.resumes.delete({
            where: { resumeId: +resumeId, UserId: +userId },
            select: { resumeId: true },
        });

        return res.status(201).json({ status: 201, message: '이력서 삭제가 성공했습니다.', data: { deletedResume } });
    } catch (err) {
        next(err);
    }
});

// 이력서 지원 상태 변경 API
router.patch('/resumes/:resumeId/state', authMiddleware, requiredRoles(['RECRUITER']), async (req, res, next) => {
    try {
        // 사용자 정보 가져옴
        const { userId } = req.user;
        // 이력서 ID 가져옴
        const { resumeId } = req.params;
        //지원 상태, 사유 가져옴
        const validation = await resumeStateSchema.validateAsync(req.body);
        const { state, reason } = validation;

        // 이력서가 존재하는지 조회
        const resume = await prisma.resumes.findFirst({ where: { resumeId: +resumeId } });
        if (!resume) {
            return res.status(401).json({ status: 401, message: '이력서가 존재하지 않습니다.' });
        }

        let resumeLog; // 이력서 변경 로그

        // 트랜젝션을 통해서 작업의 일관성 유지
        await prisma.$transaction(
            async (tx) => {
                // 이력서 수정
                const updatedResume = await tx.resumes.update({ where: { resumeId: +resumeId }, data: { state } });

                // 이력서 변경 로그 생성
                resumeLog = await tx.resumeHistories.create({
                    data: {
                        RecruiterId: +userId,
                        ResumeId: +resumeId,
                        oldState: resume.state,
                        newState: updatedResume.state,
                        reason,
                    },
                });
            },
            {
                isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
            },
        );

        return res.status(201).json({ status: 201, message: '지원 상태 변경에 성공했습니다.', data: { resumeLog } });
    } catch (err) {
        next(err);
    }
});

// 이력서 로그 목록 조회 API
router.get('/resumes/:resumeId/log', authMiddleware, requiredRoles(['RECRUITER']), async (req, res, next) => {
    // 이력서 ID 가져옴
    const { resumeId } = req.params;

    // 이력서 로그 조회
    const resumeLogs = await prisma.resumeHistories.findMany({
        where: { ResumeId: +resumeId },
        select: {
            resumeLogId: true,
            Resume: {
                select: {
                    User: {
                        select: {
                            name: true,
                        },
                    },
                },
            },
            ResumeId: true,
            oldState: true,
            newState: true,
            reason: true,
            createdAt: true,
        },
        orderBy: { createdAt: 'desc' },
    });

    return res.status(200).json({ status: 200, message: '이력서 로그 목록 조회에 성공했습니다.', data: { resumeLogs } });
});

export default router;
