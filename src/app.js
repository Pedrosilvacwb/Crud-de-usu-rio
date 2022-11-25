import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { hash, compare } from 'bcryptjs';
import users from './database';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

const port = 3000;

// Midleware
const verifyUserExistsMidleWare = (req, res, next) => {
  const { email } = req.body;
  const user = users.find((u) => u.email === email);

  if (user) {
    return res.status(409).json({ message: 'Email already exists.' });
  }

  return next();
};

const findUserMidleware = (req, res, next) => {
  const user = users.find((u) => u.email === req.body.email);

  if (!user) {
    return res.status(401).json({ message: 'Invalid Email/password' });
  }

  return next();
};

// Services
const createUserService = async (data) => {
  const hashedPassword = await hash(data.password, 10);
  const user = {
    ...data,
    password: hashedPassword,
    createdOn: new Date(),
    updatedOn: new Date(),
    uuid: uuidv4(),
  };

  users.push(user);

  const userDisplay = { ...user };
  delete userDisplay.password;

  return [201, userDisplay];
};

const loginUserService = async ({ email, password }) => {
  const user = users.find((u) => u.email === email);

  const passwordMatch = await compare(password, user.password);

  if (!passwordMatch) {
    return [401, { message: 'Email/Password invalid.' }];
  }

  const token = jwt.sign({ email }, 'SECRET_KEY', {
    expiresIn: '24h',
    subject: user.uuid,
  });

  return [200, { token }];
};

// Controller
const createUserController = async (req, res) => {
  const [status, data] = await createUserService(req.body);

  return res.status(status).json(data);
};

const loginUserController = async (req, res) => {
  const [status, data] = await loginUserService(req.body);

  return res.status(status).json(data);
};

// Routes
app.post('/users', verifyUserExistsMidleWare, createUserController);
app.post('/login', findUserMidleware, loginUserController);

app.listen(port, () => {
  console.log(`Rodando na porta ${port}`);
});

export default app;
