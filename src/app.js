import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

import UserRouter from './routers/users.router.js';
import ResumeRouter from './routers/resumes.router.js';

import errorHandingMiddleware from './middlewares/error-handing.middleware.js';

dotenv.config();

const app = express();
const SERVER_PORT = process.env.SERVER_PORT;

app.use(express.json());
app.use(cookieParser());

app.use('/api', [UserRouter, ResumeRouter]);
app.use(errorHandingMiddleware);

app.listen(SERVER_PORT, () => {
    console.log(SERVER_PORT, '포트로 서버가 열렸어요!');
});
