import { prisma } from '../utils/prisma.util.js';
import jwt from 'jsonwebtoken';
import { HTTP_STATUS } from '../constants/http-status.constant.js';
import { MESSAGES } from '../constants/message.constant.js';

// RefreshToken 인증 미들웨어
export default async (req, res, next) => {
    try {
        // 헤더에서 Refresh 토큰 가져옴
        const authorization = req.headers['authorization'];
        if (!authorization) throw new Error(MESSAGES.AUTH.COMMON.JWT.NO_TOKEN);

        // Refresh 토큰이 Bearer 형식인지 확인
        const [tokenType, token] = authorization.split(' ');
        if (tokenType !== 'Bearer') throw new Error(MESSAGES.AUTH.COMMON.JWT.NOT_SUPPORTED_TYPE);

        // 서버에서 발급한 JWT가 맞는지 검증
        const decodedToken = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET_KEY);
        const userId = decodedToken.userId;

        // JWT에서 꺼낸 userId로 실제 사용자가 있는지 확인
        const user = await prisma.user.findFirst({ where: { userId: +userId }, omit: { password: true } });
        if (!user) {
            return res.status(HTTP_STATUS.UNAUTHORIZED).json({ status: HTTP_STATUS.UNAUTHORIZED, message: MESSAGES.AUTH.COMMON.JWT.NO_USER });
        }

        // DB에 저장된 RefreshToken를 조회
        const refreshToken = await prisma.refreshToken.findFirst({ where: { UserId: user.userId } });
        // DB에 저장 된 RefreshToken이 없거나 전달 받은 값과 일치하지 않는 경우
        if (!refreshToken || refreshToken.token !== token) {
            return res.status(HTTP_STATUS.UNAUTHORIZED).json({ status: HTTP_STATUS.UNAUTHORIZED, message: MESSAGES.AUTH.COMMON.JWT.DISCARDED_TOKEN });
        }

        // 조회된 사용자 정보를 req.user에 넣음
        req.user = user;
        // 다음 동작 진행
        next();
    } catch (err) {
        switch (err.name) {
            case 'TokenExpiredError':
                return res.status(HTTP_STATUS.UNAUTHORIZED).json({ status: HTTP_STATUS.UNAUTHORIZED, message: MESSAGES.AUTH.COMMON.JWT.EXPIRED });
            case 'JsonWebTokenError':
                return res.status(HTTP_STATUS.UNAUTHORIZED).json({ status: HTTP_STATUS.UNAUTHORIZED, message: MESSAGES.AUTH.COMMON.JWT.INVALID });
            default:
                return res
                    .status(HTTP_STATUS.UNAUTHORIZED)
                    .json({ status: HTTP_STATUS.UNAUTHORIZED, message: err.message ?? MESSAGES.AUTH.COMMON.JWT.ETC });
        }
    }
};
