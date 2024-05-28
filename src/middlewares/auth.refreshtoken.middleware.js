import { prisma } from '../utils/prisma.util.js';
import jwt from 'jsonwebtoken';

// RefreshToken 인증 미들웨어
export default async (req, res, next) => {
    try {
        // 헤더에서 Refresh 토큰 가져옴
        const authorization = req.headers['authorization'];
        console.log(req.headers);
        if (!authorization) throw new Error('인증 정보가 없습니다.');

        // Refresh 토큰이 Bearer 형식인지 확인
        const [tokenType, token] = authorization.split(' ');
        if (tokenType !== 'Bearer') throw new Error('지원하지 않는 인증 방식입니다.');

        // 서버에서 발급한 JWT가 맞는지 검증
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET_KEY);
        const userId = decodedToken.userId;

        // JWT에서 꺼낸 userId로 실제 사용자가 있는지 확인
        const user = await prisma.users.findFirst({ where: { userId: +userId } });
        if (!user) {
            return res.status(401).json({ status: 401, message: '인증 정보와 일치하는 사용자가 없습니다.' });
        }

        // DB에 저장된 RefreshToken를 조회
        const refreshToken = await prisma.refreshTokens.findFirst({ where: { UserId: user.userId } });
        // DB에 저장 된 RefreshToken이 없거나 전달 받은 값과 일치하지 않는 경우
        if (!refreshToken || refreshToken.token !== token) {
            return res.status(401).json({ status: 401, message: '폐기 된 인증 정보입니다.' });
        }

        // 조회된 사용자 정보를 req.user에 넣음
        req.user = user;
        // 다음 동작 진행
        next();
    } catch (err) {
        switch (err.name) {
            case 'TokenExpiredError':
                return res.status(401).json({ status: 401, message: '인증 정보가 만료되었습니다.' });
            case 'JsonWebTokenError':
                return res.status(401).json({ status: 401, message: '인증 정보가 유효하지 않습니다.' });
            default:
                return res.status(401).json({ status: 401, message: err.message ?? '비정상적인 요청입니다.' });
        }
    }
};
