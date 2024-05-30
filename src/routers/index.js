import express from 'express';
import authRouter from './auth.router.js';
import usersRouter from './users.router.js';
import resumesRouter from './resumes.router.js';

import authMiddleware from '../middlewares/auth.access.token.middleware.js';

const apiRouter = express.Router();

apiRouter.use('/auth', authRouter);
apiRouter.use('/users', usersRouter);
apiRouter.use('/resumes', authMiddleware, resumesRouter);

export default apiRouter;
