import express from "express";
import { hash, compare } from "bcrypt";
import { database } from "./users.js";
import jsonwebtoken from "jsonwebtoken";

const app = express();
app.use(express.json());
const userDatabase = [];
let hashedPasswordObj;
let user;
const SECRET = "H6AIgu0wsGCH2mC6ypyRubiPoPSpV4t1";
let token;
const saltRounds = 12;

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
    res.status(500).json({ message: "Internal server error" });
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
        token = jsonwebtoken.sign(id, SECRET);
        res.status(201).json({ token });
      }
    }
  } catch (error) {
    res.status(400).json({ message: "Authentication error" });
    console.log(error.message);
  }
});

app.get("/auth/profile", async (req, res) => {
  try {
    token = req.headers.authorization.split(" ")[1];
    if (!token) {
      res.status(401).json({ error: "Unauthorized." });
    } else {
      const decodedID = jsonwebtoken.verify(token, SECRET);
      user = userDatabase.find((user) => user.id === decodedID);
      if (!decodedID || !user) {
        res
          .status(400)
          .json({ message: "User not found or the token is invalid" });
      } else {
        res.status(201).json({ username: user.username });
      }
    }
  } catch (error) {
    res.status(400).json({ message: "Authentication error" });
    console.log(error.message);
  }
});

app.post("/auth/logout", async (req, res) => {
  res.status(204).json({ message: "No content" });
});

// Serve the front-end application from the `client` folder
app.use(express.static("client"));

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
