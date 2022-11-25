import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { hash } from 'bcryptjs';
import users from './database';

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

// Controller
const createUserController = async (req, res) => {
  const [status, data] = await createUserService(req.body);

  return res.status(status).json(data);
};

// Routes
app.post('/users', verifyUserExistsMidleWare, createUserController);

app.listen(port, () => {
  console.log(`Rodando na porta ${port}`);
});

export default app;
