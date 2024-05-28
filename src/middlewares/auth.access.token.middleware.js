import { prisma } from '../utils/prisma.util.js';
import jwt from 'jsonwebtoken';

// AccessToken 인증 미들웨어
export default async (req, res, next) => {
    try {
        // 헤더에서 Access 토큰 가져옴
        const authorization = req.headers['authorization'];
        if (!authorization) throw new Error('인증 정보가 없습니다.');

        // Access 토큰이 Bearer 형식인지 확인
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
