// 미들웨어는 req, res, next를 필요로 하는 함수
// 그렇기에 매개변수를 사용할 수 있는 미들웨어를 만들기 위해 미들웨어를 리턴하는 함수를 만듦
export const requiredRoles = (roles) => {
    return async (req, res, next) => {
        // 현재 사용자의 역할을 가져옴
        const { role } = req.user;

        // 배열로 받아온 roles에 현재 사용자의 역할이 포함되는지 확인
        if (roles.includes(role)) {
            // 역할이 포함되면 다음으로 진행
            return next();
        }
        return res.status(401).json({ status: 401, message: '접근 권한이 없습니다.' });
    };
};
