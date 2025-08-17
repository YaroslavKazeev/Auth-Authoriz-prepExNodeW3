import express from "express";
import { hash, compare } from "bcrypt";
import { database } from "./users.js";
import jsonwebtoken from "jsonwebtoken";
// TODO Use below import statement for importing middlewares from users.js for your routes
// TODO import { ....... } from "./users.js";

const app = express();
app.use(express.json());
const userDatabase = [];
let hashedPasswordObj;
let user;
const saltRounds = 12;

// TODO: Create routes here, e.g. app.post("/register", .......)
app.post("/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      res
        .status(401)
        .json({ error: "Registration misses username or password." });
    } else {
      const hashedPassword = await hash(password, saltRounds);
      hashedPasswordObj = database.create({ password: hashedPassword });
      user = { id: hashedPasswordObj.id, username };
      userDatabase.push(user);

      res.status(201).json({ id: hashedPasswordObj.id, username });
    }
  } catch (error) {
    res.status(400).json({ message: "Authentication error" });
    console.log(error.message);
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    user = userDatabase.find((user) => user.username === username);
    if (!username || !password || !user) {
      res.status(401).json({ error: "User's credentials are invalid." });
    } else {
      const id = user.id;
      hashedPasswordObj = database.getById(id);
      const isPasswordCorrect = await compare(
        password,
        hashedPasswordObj.password
      );
      if (!isPasswordCorrect) {
        res.status(401).json({ error: "User's credentials are invalid." });
      } else {
        const SECRET = "H6AIgu0wsGCH2mC6ypyRubiPoPSpV4t1";
        const token = jsonwebtoken.sign(id, SECRET);
        res.status(201).json({ token });
      }
    }
  } catch (error) {
    res.status(400).json({ message: "Authentication error" });
    console.log(error.message);
  }
});

// Serve the front-end application from the `client` folder
app.use(express.static("client"));

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
