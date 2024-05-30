import express from 'express';
import { prisma } from '../utils/prisma.util.js';
import authMiddleware from '../middlewares/auth.access.token.middleware.js';
import { requiredRoles } from '../middlewares/role.middleware.js';

import { USER_ROLE } from '../constants/user.role.constant.js';
import { resumeWriteSchema, resumeStateSchema } from '../schemas/joi.schema.js';
import { Prisma } from '@prisma/client';
import { HTTP_STATUS } from '../constants/http-status.constant.js';
import { MESSAGES } from '../constants/message.constant.js';

const router = express.Router();

//이력서 생성 API
router.post('/', async (req, res, next) => {
    try {
        // 사용자 ID를 가져옴
        const { userId } = req.user;
        // 사용자가 입력한 제목과 자기소개에 대한 유효성 검사
        const validation = await resumeWriteSchema.validateAsync(req.body);
        const { title, introduce } = validation;

        // 이력서 생성
        const resume = await prisma.resume.create({
            data: {
                title,
                introduce,
                UserId: +userId,
            },
        });

        return res.status(HTTP_STATUS.CREATED).json({ status: HTTP_STATUS.CREATED, message: MESSAGES.RESUMES.CREATE.SUCCEED, data: { resume } });
    } catch (err) {
        next(err);
    }
});

// 이력서 목록 조회 API
router.get('/', async (req, res) => {
    // 사용자를 가져옴
    const user = req.user;
    // 정렬 조건을 req.query로 가져옴
    let sortType = req.query.sort.toLowerCase();

    if (sortType !== 'desc' || sortType !== 'asc') {
        sortType = 'desc';
    }

    const whereCondition = {};
    // 채용 담당자인 경우
    if (user.role === USER_ROLE.RECRUITER) {
        // 필터링 조건을 가져옴
        const stateFilter = req.query.status.toUpperCase();

        if (stateFilter) {
            whereCondition.state = stateFilter;
        }
    }
    // 채용 담당자가 아닌 경우
    else {
        whereCondition.UserId = user.userId;
    }

    let resumes = await prisma.resume.findMany({
        where: whereCondition,
        include: {
            User: true,
        },
        orderBy: { createdAt: sortType },
    });

    resumes = resumes.map((resume) => {
        return {
            resumeId: resume.resumeId,
            userName: resume.User.name,
            title: resume.title,
            introduce: resume.introduce,
            state: resume.state,
            createdAt: resume.createdAt,
            updatedAt: resume.updatedAt,
        };
    });

    return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.RESUMES.READ.LIST.SUCCEED, data: { resumes } });
});

// 이력서 상세 조회 API
router.get('/:resumeId', async (req, res) => {
    // 사용자를 가져옴
    const user = req.user;
    // 이력서 ID를 가져옴
    const { resumeId } = req.params;

    const whereCondition = { resumeId: +resumeId };
    // 채용 담당자가 아닌 경우
    if (user.role !== USER_ROLE.RECRUITER) {
        whereCondition.UserId = user.userId;
    }

    // 이력서 ID, 작성자 ID가 모두 일치한 이력서 조회
    let resume = await prisma.resume.findFirst({
        where: whereCondition,
        include: {
            User: true,
        },
    });
    if (!resume) {
        return res.status(HTTP_STATUS.NOT_FOUND).json({ status: HTTP_STATUS.NOT_FOUND, message: MESSAGES.RESUMES.COMMON.NOT_FOUND });
    }

    resume = {
        resumeId: resume.resumeId,
        userName: resume.User.name,
        title: resume.title,
        introduce: resume.introduce,
        state: resume.state,
        createdAt: resume.createdAt,
        updatedAt: resume.updatedAt,
    };

    return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.RESUMES.READ.DETAIL.SUCCEED, data: { resume } });
});

// 이력서 수정 API
router.patch('/:resumeId', async (req, res, next) => {
    try {
        // 사용자 ID를 가져옴
        const { userId } = req.user;
        // 이력서 ID를 가져옴
        const { resumeId } = req.params;
        // 제목, 자기소개를 가져옴 (유효성 검사 진행)
        const validation = await resumeWriteSchema.validateAsync(req.body);
        const { title, introduce } = validation;

        // 이력서 ID, 작성자 ID가 모두 일치한 이력서 조회
        const resume = await prisma.resume.findFirst({
            where: { resumeId: +resumeId, UserId: +userId },
        });
        if (!resume) {
            return res.status(HTTP_STATUS.NOT_FOUND).json({ status: HTTP_STATUS.NOT_FOUND, message: MESSAGES.RESUMES.COMMON.NOT_FOUND });
        }

        // 이력서 수정
        const updatedResume = await prisma.resume.update({
            where: { resumeId: +resumeId, UserId: +userId },
            data: {
                ...(title && { title }),
                ...(introduce && { introduce }),
            },
        });

        return res
            .status(HTTP_STATUS.CREATED)
            .json({ status: HTTP_STATUS.CREATED, message: MESSAGES.RESUMES.UPDATE.SUCCEED, data: { updatedResume } });
    } catch (err) {
        next(err);
    }
});

// 이력서 삭제 API
router.delete('/:resumeId', async (req, res, next) => {
    try {
        // 사용자 ID를 가져옴
        const { userId } = req.user;
        // 이력서 ID를 가져옴
        const { resumeId } = req.params;

        // 이력서 ID, 작성자 ID가 모두 일치한 이력서 조회
        const resume = await prisma.resume.findFirst({
            where: { resumeId: +resumeId, UserId: +userId },
        });
        if (!resume) {
            return res.status(HTTP_STATUS.NOT_FOUND).json({ status: HTTP_STATUS.NOT_FOUND, message: MESSAGES.RESUMES.COMMON.NOT_FOUND });
        }

        // 이력서 삭제
        const deletedResume = await prisma.resume.delete({
            where: { resumeId: +resumeId, UserId: +userId },
            select: { resumeId: true },
        });

        return res
            .status(HTTP_STATUS.CREATED)
            .json({ status: HTTP_STATUS.CREATED, message: MESSAGES.RESUMES.DELETE.SUCCEED, data: { deletedResume } });
    } catch (err) {
        next(err);
    }
});

// 이력서 지원 상태 변경 API
router.patch('/:resumeId/state', requiredRoles([USER_ROLE.RECRUITER]), async (req, res, next) => {
    try {
        // 사용자 정보 가져옴
        const { userId } = req.user;
        // 이력서 ID 가져옴
        const { resumeId } = req.params;
        //지원 상태, 사유 가져옴
        const validation = await resumeStateSchema.validateAsync(req.body);
        const { state, reason } = validation;

        // 이력서가 존재하는지 조회
        const resume = await prisma.resume.findFirst({ where: { resumeId: +resumeId } });
        if (!resume) {
            return res.status(HTTP_STATUS.NOT_FOUND).json({ status: HTTP_STATUS.NOT_FOUND, message: MESSAGES.RESUMES.COMMON.NOT_FOUND });
        }

        let resumeLog; // 이력서 변경 로그

        // 트랜젝션을 통해서 작업의 일관성 유지
        await prisma.$transaction(
            async (tx) => {
                // 이력서 수정
                const updatedResume = await tx.resume.update({ where: { resumeId: +resumeId }, data: { state } });

                // 이력서 변경 로그 생성
                resumeLog = await tx.resumeHistory.create({
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

        return res.status(HTTP_STATUS.CREATED).json({ status: HTTP_STATUS.CREATED, message: MESSAGES.RESUMES.STATE.SUCCEED, data: { resumeLog } });
    } catch (err) {
        next(err);
    }
});

// 이력서 로그 목록 조회 API
router.get('/:resumeId/log', requiredRoles([USER_ROLE.RECRUITER]), async (req, res, next) => {
    // 이력서 ID 가져옴
    const { resumeId } = req.params;

    // 이력서가 존재하는지 조회
    const resume = await prisma.resume.findFirst({ where: { resumeId: +resumeId } });
    if (!resume) {
        return res.status(HTTP_STATUS.NOT_FOUND).json({ status: HTTP_STATUS.NOT_FOUND, message: MESSAGES.RESUMES.COMMON.NOT_FOUND });
    }

    // 이력서 로그 조회
    let resumeLogs = await prisma.resumeHistory.findMany({
        where: { ResumeId: +resumeId },
        include: {
            User: true,
        },
        orderBy: { createdAt: 'desc' },
    });

    resumeLogs = resumeLogs.map((log) => {
        return {
            resumeLogId: log.resumeLogId,
            userName: log.User.name,
            resumeId: log.ResumeId,
            oldState: log.oldState,
            newState: log.newState,
            reason: log.reason,
            createdAt: log.createdAt,
        };
    });

    return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.RESUMES.LOG.READ.LIST.SUCCEED, data: { resumeLogs } });
});

export default router;
