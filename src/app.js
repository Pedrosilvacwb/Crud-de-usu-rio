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

const validateTokenMidleWare = (req, res, next) => {
  const authToken = req.headers.authorization;

  if (!authToken) {
    return res.status(401).json({ message: 'Missing Token' });
  }
  const token = authToken.split(' ')[1];

  return jwt.verify(token, 'SECRET_KEY', (error, decode) => {
    if (error) {
      return res.status(401).json({ message: error.message });
    }
    const user = users.find((u) => u.email === decode.email);

    if (!user) {
      return res.status(401).json({ message: 'Invalid Token' });
    }
    req.user = user;
    return next();
  });
};

const validateUserAdminMidleware = (req, res, next) => {
  if (!req.user.isAdm) {
    return res.status(403).json({ message: 'Unauthorized' });
  }

  return next();
};

const validateUserAdminEditMidleware = (req, res, next) => {
  const paramsId = req.params.id;
  const user = users.find((u) => u.uuid === paramsId);
  const sameUsers = paramsId === req.user.uuid;

  if (!req.user.isAdm && !sameUsers) {
    return res.status(403).json({ message: 'Unauthorized' });
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

const getUsersService = () => {
  return [200, users];
};

const retrieveUserService = (req) => {
  const { user } = req;

  const userDisplay = { ...user };
  delete userDisplay.password;

  return [200, userDisplay];
};

const editUserService = (req) => {
  const user = users.find((u) => u.uuid === req.params.id);

  const newUser = { ...user, ...req.body, updatedOn: new Date() };
  const index = users.findIndex((u) => u === user);
  users.splice(index, 1, newUser);
  const userDisplay = { ...newUser };
  delete userDisplay.password;

  return [200, userDisplay];
};

const deleteUserService = (id) => {
  const user = users.find((u) => u.uuid === id);
  const index = users.findIndex((u) => u === user);
  users.splice(index, 1);

  return [204];
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

const getUsersController = (req, res) => {
  const [status, data] = getUsersService();

  return res.status(status).json(data);
};

const retrieveUserController = (req, res) => {
  const [status, data] = retrieveUserService(req);

  return res.status(status).json(data);
};

const editUserController = (req, res) => {
  const [status, data] = editUserService(req);

  return res.status(status).json(data);
};

const deleteUserController = (req, res) => {
  const id = req.params.id;
  const [status, data] = deleteUserService(id);

  return res.status(status).json(data);
};
// Routes
app.post('/users', verifyUserExistsMidleWare, createUserController);
app.post('/login', findUserMidleware, loginUserController);

app.get(
  '/users',
  validateTokenMidleWare,
  validateUserAdminMidleware,
  getUsersController,
);
app.get('/users/profile', validateTokenMidleWare, retrieveUserController);

app.patch(
  '/users/:id',
  validateTokenMidleWare,
  validateUserAdminEditMidleware,
  editUserController,
);

app.delete(
  '/users/:id',
  validateTokenMidleWare,
  validateUserAdminEditMidleware,
  deleteUserController,
);

app.listen(port, () => {
  console.log(`Rodando na porta ${port}`);
});

export default app;
