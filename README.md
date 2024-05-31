# 🖥️ 나만의 채용 서비스 백엔드 서버 만들기
![썸네일](./imgs/thumbnail.png)

## 프로젝트 소개
- 프로젝트 이름 : SPA_Recruit
- 내용 : Express.js, MySQL을 활용해 나만의 채용 서비스 백엔드 서버 만들기
- 구분 : 개인 프로젝트
- 배포 : https://www.mymycode.shop/api/... (API 명세서 참조)
    <details>
    <summary>RECRUITER 정보</summary>
    <div markdown="1">
    <ul>
    <li>email : spartan@spartacodingclub.kr</li>
    <li>password : aaaa4321!!</li>
    </ul>
    </div>
    </details>

<br>


## 1. 개발 기간
- 2024.05.27 ~ 2024.05.29
- 2024.05.30 1차 수정

<br>

## 2. 개발 환경
- BackEnd : Node.js, Express, MySQL(Prisma)
- Tool : AWS, Insomnia, MySQL Workbench

<br>

## 3. API 명세서 및 ERD
 - API 명세서 : https://west-territory-778.notion.site/Node-js-API-ec55e0bdd9c24242a75c99766c90589e?pvs=4
 - ERD : https://drawsql.app/teams/nodejs-express/diagrams/spa-recruit

<br>

## 4. 주요 기능 및 설명
### 4-1. DB 연결, 스키마 작성, 테이블 생성
- 데이터베이스 연결
```javascript
// src/utils/prisma.util.js

import { PrismaClient } from '@prisma/client';

export const prisma = new PrismaClient({
    // Prisma를 이용해 데이터베이스를 접근할 때, SQL을 출력해줍니다.
    log: ['query', 'info', 'warn', 'error'],

    // 에러 메시지를 평문이 아닌, 개발자가 읽기 쉬운 형태로 출력해줍니다.
    errorFormat: 'pretty',
}); // PrismaClient 인스턴스를 생성합니다.

try {
    await prisma.$connect();
    console.log('DB 연결에 성공했습니다.');
} catch (error) {
    console.error('DB 연결에 실패했습니다.', error);
}
```
- 스키마 작성 및 테이블 생성
```javascript
// This is your Prisma schema file,
// learn more about it in the docs: https://pris.ly/d/prisma-schema

// Looking for ways to speed up your queries, or scale easily with your serverless or edge functions?
// Try Prisma Accelerate: https://pris.ly/cli/accelerate-init

generator client {
  provider        = "prisma-client-js"
  previewFeatures = ["omitApi"]
}

datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

model User {
  userId       Int      @id @default(autoincrement()) @map("user_id")
  email        String   @unique @map("email")
  password     String   @map("password")
  name         String   @map("name")
  age          Int      @map("age")
  gender       String   @map("gender")
  role         String   @default("APPLICANT") @map("role")
  profileImage String   @map("profile_image")
  createdAt    DateTime @default(now()) @map("created_at")
  updatedAt    DateTime @updatedAt @map("updated_at")

  Resume       Resume[] // 1명의 사용자는 여러 개의 이력서 작성 가능 (1:N 관계 형성)
  ResumeHistory ResumeHistory[]
  RefreshToken RefreshToken?

  @@map("users")
}

model Resume {
  resumeId  Int      @id @default(autoincrement()) @map("resume_id")
  UserId    Int      @map("user_id") // User 테이블을 참조하는 외래키
  title     String   @map("title")
  introduce String   @map("introduce") @db.Text
  state     String   @default("APPLY") @map("state")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  ResumeHistory ResumeHistory[] // 1개의 이력서에는 여러 개의 이력서 로그 기록이 존재 (1:N 관계 형성)

  // User 테이블과의 관계 설정
  User User @relation(fields: [UserId], references: [userId], onDelete: Cascade)

  @@map("resumes")
}

model ResumeHistory {
  resumeLogId Int      @id @default(autoincrement()) @map("resume_log_id")
  ResumeId    Int      @map("resume_id") // Resume 테이블을 참조하는 외래키
  RecruiterId Int      @map("recruiter_id")
  oldState    String   @map("old_state")
  newState    String   @map("new_state")
  reason      String   @map("reason")
  createdAt   DateTime @default(now()) @map("created_at")

  // User 테이블과의 관계 설정
  User User @relation(fields: [RecruiterId], references: [userId], onDelete: Cascade)

  // Resume 테이블과의 관계 설정
  Resume Resume @relation(fields: [ResumeId], references: [resumeId], onDelete: Cascade)

  @@map("resume_histories")
}

model RefreshToken {
  tokenId   Int      @id @default(autoincrement()) @map("token_id")
  UserId    Int      @unique @map("user_id")
  token     String   @map("token")
  ip        String   @map("ip")
  userAgent String   @map("user_agent")
  createdAt DateTime @default(now()) @map("created_at")

  User User @relation(fields: [UserId], references: [userId], onDelete: Cascade)

  @@map("refresh_tokens")
}

```

<br>

### 4-2. 유효성 검증 (Joi)
- 회원가입, 로그인, 이력서 작성 등 사용하는 유효성 검사가 달라서 따로 구현
- (수정) 기존의 메시지 문자열을 constant로 만들어서 따로 관리
```javascript
// src/schemas/joi.schema.js

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

```

<br>

### 4-3. 회원가입 API
- 이메일, 비밀번호, 비밀번호 확인, 이름을 Request Body(`req.body`)로 전달 받음

- **Joi**를 통한 유효성 검사

- 사용자 ID, 역할, 생성일시, 수정일시는 자동 생성됨

- 보안을 위해 **비밀번호**는 평문(Plain Text)으로 저장하지 않고 **Hash** 된 값을 저장

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리
```javascript
// src/routers/auth.router.js

// 회원가입 API
router.post('/sign-up', async (req, res, next) => {
    try {
        // 사용자 입력 유효성 검사
        const validation = await signUpSchema.validateAsync(req.body);
        const { email, password, passwordConfirm, name, age, gender, profileImage } = validation;

        // 이메일 중복 확인
        const isExistUser = await prisma.user.findFirst({ where: { email } });
        if (isExistUser) {
            return res.status(HTTP_STATUS.CONFLICT).json({ status: HTTP_STATUS.CONFLICT, message: MESSAGES.AUTH.COMMON.EMAIL.DUPLICATED });
        }

        // 비밀번호 확인 결과
        if (password !== passwordConfirm) {
            return res
                .status(HTTP_STATUS.BAD_REQUEST)
                .json({ status: HTTP_STATUS.BAD_REQUEST, message: MESSAGES.AUTH.COMMON.PASSWORD_CONFIRM.INCONSISTENT });
        }

        // 비밀번호 암호화
        const hashedPassword = await bcrypt.hash(password, HASH_SALT);

        // 사용자 생성
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                name,
                age,
                gender: gender.toUpperCase(),
                profileImage,
            },
        });

        const { password: pw, ...userData } = user; // == user.password = undefined;

        return res.status(HTTP_STATUS.CREATED).json({ status: HTTP_STATUS.CREATED, message: MESSAGES.AUTH.SIGN_UP.SUCCEED, data: { userData } });
    } catch (err) {
        next(err);
    }
});

```

<br>

### 4-4. 로그인 API
- 이메일, 비밀번호를 Request Body(`req.body`)로 전달 받음

- **Joi**를 통한 유효성 검사

- **AccessToken**(Payload에 `사용자 ID`를 포함하고, 유효기한이 `12시간`)을 생성

- **RefreshToken**(Payload에 `사용자 ID`를 포함하고, 유효기한이 `7일`)을 생성

- 데이터베이스에 **RefreshToken**을 **생성** 또는 **갱신**

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리

- (수정) Prisma upsert()를 통해 조건문 대체
```javascript
// src/routers/auth.router.js

// 로그인 API
router.post('/sign-in', async (req, res, next) => {
    try {
        const validation = await signInSchema.validateAsync(req.body);
        const { email, password } = validation;

        // 입력받은 이메일로 사용자 조회
        const user = await prisma.user.findFirst({ where: { email } });

        // 사용자 비밀번호와 입력한 비밀번호 일치 확인
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(HTTP_STATUS.UNAUTHORIZED).json({ status: HTTP_STATUS.UNAUTHORIZED, message: MESSAGES.AUTH.COMMON.UNAUTHORIZED });
        }

        // 로그인 성공하면 JWT 토큰 발급
        const AccessToken = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRED_IN });
        const RefreshToken = jwt.sign({ userId: user.userId }, process.env.REFRESH_TOKEN_SECRET_KEY, { expiresIn: REFRESH_TOKEN_EXPIRED_IN });
        // res.setHeader('authorization', `Bearer ${AccessToken}`);

        // prisma upsert를 통해서 기존 토큰이 있으면 업데이트 없으면 생성
        await prisma.refreshToken.upsert({
            where: { UserId: user.userId },
            update: {
                token: RefreshToken,
                createdAt: new Date(Date.now()),
            },
            create: {
                UserId: user.userId,
                token: RefreshToken,
                ip: req.ip,
                userAgent: req.headers['user-agent'],
            },
        });

        // 현재 사용자의 Refresh토큰이 DB에 있는지 조회
        /* 
        const refreshToken = await prisma.refreshToken.findFirst({ where: { UserId: user.userId } });
        if (!refreshToken) {
            // 없으면 새로운 토큰 생성
            await prisma.refreshToken.create({
                data: {
                    UserId: user.userId,
                    token: RefreshToken,
                    ip: req.ip,
                    userAgent: req.headers['user-agent'],
                },
            });
        } else {
            // 있으면 토큰 갱신
            await prisma.refreshToken.update({
                where: { UserId: user.userId },
                data: {
                    token: RefreshToken,
                    ip: req.ip,
                    userAgent: req.headers['user-agent'],
                    createdAt: new Date(Date.now()),
                },
            });
        }*/

        return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.AUTH.SIGN_IN, data: { AccessToken, RefreshToken } });
    } catch (err) {
        next(err);
    }
});
```


<br>

### 4-5. AccessToken 인증 Middleware
- **AccessToken**을 **Request Header**의 Authorization 값(`req.headers.authorization`)으로 전달 받음

- 조건문과 `try ~ catch문`을 이용해서 유효성 검사

- Payload에 담긴 **사용자 ID**를 이용하여 **사용자 정보를 조회**

- 조회 된 사용자 정보를 `req.user`에 담고, 다음 동작을 진행

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리

- (수정) 데이터베이스에서 사용자 정보 중 `password`를 제외한 데이터를 가져오기 위해 Prisma `omit` 기능 사용
```javascript
// src/middlewares/auth.access.token.middleware.js

import { HTTP_STATUS } from '../constants/http-status.constant.js';
import { MESSAGES } from '../constants/message.constant.js';
import { prisma } from '../utils/prisma.util.js';
import jwt from 'jsonwebtoken';

// AccessToken 인증 미들웨어
export default async (req, res, next) => {
    try {
        // 헤더에서 Access 토큰 가져옴
        const authorization = req.headers['authorization'];
        if (!authorization) throw new Error(MESSAGES.AUTH.COMMON.JWT.NO_TOKEN);

        // Access 토큰이 Bearer 형식인지 확인
        const [tokenType, token] = authorization.split(' ');
        if (tokenType !== 'Bearer') throw new Error(MESSAGES.AUTH.COMMON.JWT.NOT_SUPPORTED_TYPE);

        // 서버에서 발급한 JWT가 맞는지 검증
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET_KEY);
        const userId = decodedToken.userId;

        // JWT에서 꺼낸 userId로 실제 사용자가 있는지 확인
        const user = await prisma.user.findFirst({ where: { userId: +userId }, omit: { password: true } });
        if (!user) {
            return res.status(HTTP_STATUS.UNAUTHORIZED).json({ status: HTTP_STATUS.UNAUTHORIZED, message: MESSAGES.AUTH.COMMON.JWT.NO_USER });
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

```

<br>

### 4-6. 내 정보 조회 API
- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- ~~userId값으로 **Users 테이블**에서 사용자 정보를 조회~~

- **사용자 ID, 이메일, 이름, 역할, 생성일시, 수정일시**를 반환

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리

- `authMiddleware`를 통해서 사용자 검증을 거치기 때문에 DB에서 사용자 검색을 할 필요가 없음
```javascript
// src/routers/users.router.js

import express from 'express';
import authMiddleware from '../middlewares/auth.access.token.middleware.js';
import { HTTP_STATUS } from '../constants/http-status.constant.js';
import { MESSAGES } from '../constants/message.constant.js';

const router = express.Router();

// 내 정보 조회 API
router.get('/', authMiddleware, async (req, res) => {
    const user = req.user;

    return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.USER.READ.SUCCEED, data: { user } });
});

export default router;

```


<br>

### 4-7. 이력서 생성 API
- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- 제목, 자기소개는 Request Body(`req.body`)로 전달 받음

- **Joi**를 통한 유효성 검사

- 이력서 ID, 지원 상태, 생성일시, 수정일시는 자동 생성

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리
```javascript
// src/routers/resumes.router.js

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
```

<br>

### 4-8. 이력서 목록 조회 API
- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- Query Parameters(`req.query`)으로 정렬 조건을 받음

- Query Parameters(`req.query`)으로 필터링 조건을 받음

- 지원 상태 별 필터링 조건을 받음 ex) `sort=desc&status=APPLY`

- **현재 로그인 한 사용자**가 작성한 이력서 목록만 조회

- **역할**이 `RECRUITER` 인 경우 **모든 사용자의 이력서를 조회**할 수 있음

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리

- (수정) `where절`에는 객체가 들어가기에 `whereCondition`이라는 객체를 만들어서 조건문을 통해서 값을 결정함

- (수정) `sort` 쿼리에 `desc`, `acs` 둘 다 아닐 경우에 대해서 처리하지 않아서 추가함
```javascript
// src/routers/resumes.router.js

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
```

<br>

### 4-9.이력서 상세 조회 API
- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- 이력서 ID를 Path Parameters(`req.params`)로 전달 받음

- **현재 로그인 한 사용자가 작성한 이력서만** 조회

- **역할**이 `RECRUITER` 인 경우 **이력서 작성 사용자와 일치하지 않아도** 이력서를 조회할 수 있음

- **작성자 ID가 아닌 작성자 이름을 반환**하기 위해 스키마에 정의 한 **Relation을 활용**해 조회 (중첩 SELECT 문법 사용)

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리

- (수정) `where절`에는 객체가 들어가기에 `whereCondition`이라는 객체를 만들어서 조건문을 통해서 값을 결정함
```javascript
// src/routers/resumes.router.js

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
```

<br>

### 4-10. 이력서 수정 API
- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- 이력서 ID를 Path Parameters(`req.params`)로 전달 받음

- 제목, 자기소개를 Request Body(`req.body`)로 전달 받음

- **Joi**를 통한 유효성 검사

- **현재 로그인 한 사용자가 작성한 이력서**만 수정할 수 있음

- 이력서 조회 시 **이력서 ID, 작성자 ID가 모두 일치**해야 함

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리

- (수정) 제목, 자기소개가 수정이 될 수도 안될 수도 있기에 `...` 연산자를 통해서 구현
```javascript
// src/routers/resumes.router.js

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
```

<br>

### 4-11. 이력서 삭제 API
- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- 이력서 ID를 Path Parameters(`req.params`)로 전달 받음

- **현재 로그인 한 사용자가 작성한 이력서만** 삭제

- 이력서 조회 시 **이력서 ID, 작성자 ID가 모두 일치**해야 함

- DB에서 이력서 정보를 직접 삭제

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리
```javascript
// src/routers/resumes.router.js

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
```

<br>

### 4-12. 역할 인가 Middleware
- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- 허용 역할은 Middleware 사용 시 배열로 전달 받음

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리
```javascript
// src/middlewares/role.middleware.js

// 미들웨어는 req, res, next를 필요로 하는 함수

import { HTTP_STATUS } from '../constants/http-status.constant.js';
import { MESSAGES } from '../constants/message.constant.js';

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
        return res.status(HTTP_STATUS.FORBIDDEN).json({ status: HTTP_STATUS.FORBIDDEN, message: MESSAGES.AUTH.COMMON.FORBIDDEN });
    };
};
```

<br>

### 4-13. 이력서 지원 상태 변경 API
- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- **이력서 ID**를 Path Parameters(`req.params`)로 전달 받음

-  **지원 상태, 사유**를 **Request Body**(**`req.body`**)로 전달 받음

- 이력서 정보 수정과 이력서 로그 생성을 **Transaction**으로 묶어서 실행

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리
```javascript
// src/routers/resumes.router.js

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
```

<br>

### 4-14. 이력서 로그 목록 조회 API
- **이력서 ID**를 Path Parameters(`req.params`)로 전달 받음

- **생성일시** 기준 **최신순**으로 조회

- **채용 담당자 이름**을 반환하기 위해 스키마에 정의 한 **Relation**을 활용해 조회

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리

- (수정) 중첩 SELECT가 아니라 `include`를 사용해서 참조된 User 정보를 가져옴
```javascript
// src/routers/resumes.router.js

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
```

<br>

### 4-15. RefreshToken 인증 Middleware
- **AccessToken** 인증 미들웨어와 거의 동일함

- **RefreshToken**을 **Request Header의 Authorization** 값(**`req.headers.authorization`**)으로 전달 받음

- Payload에 담긴 **사용자 ID**를 이용하여 **사용자 정보를 조회**

- 이 때, RefreshToken은 DB에 보관하기 때문에 DB에 접근해서 조회

- Payload에 담긴 사용자 ID와 일치하는 사용자가 없는 경우에는 `폐기 된 인증 정보입니다` 라고 출력

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리

- (수정) 데이터베이스에서 사용자 정보 중 `password`를 제외한 데이터를 가져오기 위해 Prisma `omit` 기능 사용
```javascript
// src/middlewares/auth.refresh.token.middleware.js

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
```

<br>

### 4-16. 토큰 재발급 API
- AccessToken 만료 시 RefreshToken을 활용해 재발급

- **RefreshToken**(JWT)을 **Request Header의 Authorization** 값(**`req.headers.authorization`**)으로 전달 받음

- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음 

- **AccessToken(Payload**에 `사용자 ID`를 포함하고, **유효기한**이 `12시간`)을 재발급

- **RefreshToken** (**Payload**: **사용자 ID** 포함, **유효기한**: **`7일`**)을 재발급

- RefreshToken은 **DB에서 보관**하기 때문에 DB의 데이터를 갱신

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리
```javascript
// src/routers/auth.router.js

// 토큰 재발급 API
router.post('/refresh', authRefreshTokenMiddleware, async (req, res, next) => {
    try {
        // 사용자 정보 가져옴
        const user = req.user;

        // Access Token 재발급 (12시간)
        const AccessToken = jwt.sign({ userId: user.userId }, process.env.ACCESS_TOKEN_SECRET_KEY, { expiresIn: ACCESS_TOKEN_EXPIRED_IN });

        // Refresh Token 재발급 (7일)
        const RefreshToken = jwt.sign({ userId: user.userId }, process.env.REFRESH_TOKEN_SECRET_KEY, { expiresIn: REFRESH_TOKEN_EXPIRED_IN });
        await prisma.refreshToken.update({
            where: { UserId: user.userId },
            data: {
                token: RefreshToken,
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                createdAt: new Date(Date.now()),
            },
        });

        return res
            .status(HTTP_STATUS.CREATED)
            .json({ status: HTTP_STATUS.CREATED, message: MESSAGES.AUTH.TOKEN_REFRESH.SUCCEED, data: { AccessToken, RefreshToken } });
    } catch (err) {
        next(err);
    }
});
```

<br>

### 4-17. 로그아웃 API
- **RefreshToken**(JWT)을 **Request Header의 Authorization** 값(**`req.headers.authorization`**)으로 전달 받음

- 사용자 정보는 인증 Middleware(`req.user`)를 통해서 전달 받음

- RefreshToken은 **DB에서 보관**하기 때문에 DB의 데이터를 삭제

- 실제로는 AccessToken이 만료되기 전까지는 AccessToken이 필요한 API는 사용 가능함

- (수정) 상태 코드와 에러 메시지 문자열을 constant로 따로 관리
```javascript
// src/routers/auth.router.js

// 로그아웃 API
router.post('/auth/sign-out', authRefreshTokenMiddleware, async (req, res, next) => {
    try {
        // 사용자 정보 가져옴
        const user = req.user;

        // DB에서 Refresh Token 삭제
        const deletedUserId = await prisma.refreshToken.delete({
            where: { UserId: user.userId },
            select: { UserId: true },
        });

        return res.status(HTTP_STATUS.OK).json({ status: HTTP_STATUS.OK, message: MESSAGES.AUTH.SIGN_OUT.SUCCEED, data: { deletedUserId } });
    } catch (err) {
        next(err);
    }
});
```

<br>

## 5. 테스트 사진 첨부
- 회원가입 API
![회원가입 API](./imgs/sign-up.png)

- 로그인 API
![로그인 API](./imgs/sign-in.png)

- 내 정보 조회 API
![내 정보 조회 API](./imgs/user_info.png)

- 이력서 생성 API
![이력서 생성 API](./imgs/resume_create.png)

- 이력서 목록 조회 API
![이력서 목록 조회 API](./imgs/resume_list.png)

- 이력서 상세 조회 API
![이력서 상세 조회 API](./imgs/resume_detail.png)

- 이력서 수정 API
![이력서 수정 API](./imgs/resume_update.png)

- 이력서 삭제 API
![이력서 삭제 API](./imgs/resume_delete.png)

- 이력서 지원 상태 변경 API
![이력서 지원 상태 변경 API](./imgs/resume_change_state.png)

- 이력서 로그 목록 조회 API
![이력서 로그 목록 조회 API](./imgs/resume_log_list.png)

- 토큰 재발급 API
![토큰 재발급 API](./imgs/token_refresh.png)

- 로그아웃 API
![로그아웃 API](./imgs/sign-out.png)

<br>

## 6. 어려웠던 점
> 이번 과제는 코드 구현의 어려움보다는 이게 왜 이렇게 되는지를 이해하는게 어려웠음
<br>

### 6-1. 토큰 생성 시 req.headers에 authorization이 자동으로 만들어짐
- 기존에 쿠키에 AccessToken을 넣는 방식에서 헤더에 넣는 방식으로 변경함

- 헤더에 토큰을 넣는 방식은 직접 Insomnia에서 Auth메뉴에 토큰을 복붙하는 방식임

- 로그인 후 auth.middleware를 사용하는 API에서 req.headers를 출력하니 authorization이라는 이름의 토큰이 생성되었음
![req.headers 출력](https://velog.velcdn.com/images/my_code/post/d3f7279a-7e95-4f70-a320-72fe969aa2cd/image.png)

- 생각해보면 나는 헤더에 authorization이라는 이름의 값을 넣어준 적이 없음

- 그냥 Insomnia의 Auth에 로그인 후 반환된 토큰값을 넣어줬음

- 팀원들에게 물어보니 정답을 찾을 수 있었음

- https://docs.insomnia.rest/insomnia/authentication#bearer-token

![인섬니아 docs](https://velog.velcdn.com/images/my_code/post/ef4479d0-3b81-4921-aa9b-99a0ec359a9e/image.png)

- 결과적으로 저 authorization은 Insomnia에서 자동으로 만들어서 header에 넣어준 것임

- 그냥 Insomnia에서 편의성을 제공해준 것임


<br>

### 6-2. 로그아웃을 해도 기능들을 사용할 수 있음
- 처음에는 로그아웃을 통해 RefreshToken을 삭제하면 진짜 로그아웃 기능처럼 다른 기능들을 사용할 수 없는 줄 알았음

- 하지만 정상적으로 로그아웃 기능을 구현 후 로그아웃을 진행해도 다른 API들을 사용할 수 있었음

- 너무 단순하게 생각했음

- 이번 과제에서 구현한 방식은 AccessToken과 RefreshToken을 사용하는 인증 방식임

- AccessToken에는 만료 시간을 짧게 하고, RefreshToken에는 만료 시간을 비교적 길게 만듦

- 이를 통해 AccessToken이 만료되면 다시 DB에 있는 RefreshToken를 통해 토큰들을 재발급 받는 구조임

- 여기서 AccessToken은 백엔드에서 처리할 수 있는 토큰이 아님

- 로그인을 하면 클라이언트에게 AccessToken을 넘겨줌

- 이후 AccessToken은 클라이언트에서 다뤄지는 데이터임

- 그렇기에 서버측에서는 AccessToken을 삭제하는 것이 불가능 

<br>

### 6-3. 리눅스 서버에 Prisma 스키마 변경하고 데이터베이스 실행 안됨
- 기존에 데이터베이스에서 파스칼 케이스, 카멜 케이스를 혼용에서 사용함

- 그래서 해설 강의를 기반으로 데이터베이스를 싹 뜯어 고침

- 데이터가 날라가는 건 어쩔 수 없다고 생각하고 Prisma 스키마를 수정함

- 전부 수정 후 리눅스 서버에서도 git pull로 최신화 함

![](https://velog.velcdn.com/images/my_code/post/46a2757b-2d9a-4a9c-9fa0-3ca5e4ee687d/image.png)

- 그러고 코드를 수정하니 위와 같은 에러가 발생함

- 분명 제대로 수정된 스키마로 최신화 했고, DB도 바뀐 컬럼으로 적용되었는데 똑같은 에러가 발생했음

- 로컬에서 진행했던 과정을 다시 살펴보니 정말 간단한 이유였음

- 바로 `npx prisma db push`를 리눅스 서버에서 실행시켜주지 않아서 발생한 문제였음

- 근데 생각해보면 `npx prisma db push` 를 통해서 DB가 업데이트 되었는데 리눅스 서버에서도 이 과정이 필요한 걸까?

- 로컬 서버, 리눅스 서버 모두 AWS의 RDS에 연결되어 있는데?

- 인터넷과 Chat-GPT를 사용해서 이유를 찾아봤지만 뚜렷한 해답은 없었음

- 인터넷과 Chat-GPT에서 말하는 이유는 다음과 같음
  - Prisma 클라이언트 라이브러리 버전 불일치
  - 캐시된 스키마 파일 사용
  - 코드 또는 환경 설정 누락
  - 리눅스 서버의 Prisma 스키마 동기화 지연

- **결론**, 같은 클라우드 DB를 사용해서 위와 같은 에러가 발생하면 리눅스 서버에서도 한 번 더 동기화 시켜주는 게 좋음

- 그리고 동기화 작업 시 `npx prisma db push` 보다는 `npx prisma migrate` 명령이 더 좋다고 함

- (추가) 팀원분께서 비슷한 상황에 대해서 말씀해 주셨음

- https://www.prisma.io/docs/orm/prisma-client/setup-and-configuration/generating-prisma-client

- 스키마 같은 경우 node_module 밑에 Prisma client에 있는데 여길 통해서 쿼리 작업이 진행됨

- 그런데 단지 pull를 통해서 최신을 받아오면 node_module은 받아오지 않기 때문에 쿼리 작업을 담당하는 Prisma client는 리눅스 서버에서 최신화되지 않는다는 이야기 같음