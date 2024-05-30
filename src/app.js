import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

import UserRouter from './routers/users.router.js';
import ResumeRouter from './routers/resumes.router.js';
import AuthRouter from './routers/auth.router.js';
import apiRouter from './routers/index.js';

import errorHandingMiddleware from './middlewares/error-handing.middleware.js';
import { HTTP_STATUS } from './constants/http-status.constant.js';

dotenv.config();

const app = express();
const SERVER_PORT = process.env.SERVER_PORT;

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    return res.status(HTTP_STATUS.OK).json({ message: '테스트' });
});

app.use('/api', [apiRouter]);
app.use(errorHandingMiddleware);

app.listen(SERVER_PORT, () => {
    console.log(SERVER_PORT, '포트로 서버가 열렸어요!');
});
