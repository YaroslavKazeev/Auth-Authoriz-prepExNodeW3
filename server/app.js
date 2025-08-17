import express from "express";
import { hash, compare } from "bcrypt";
import { database } from "./users.js";
// TODO Use below import statement for importing middlewares from users.js for your routes
// TODO import { ....... } from "./users.js";

const app = express();
app.use(express.json());
const userDatabase = [];

// TODO: Create routes here, e.g. app.post("/register", .......)
app.post("/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      res
        .status(401)
        .json({ error: "Registration misses username or password." });
    } else {
      const userIDobject = database.create({ username });
      const saltRounds = 12;

      const hashedPassword = await hash(password, saltRounds);
      const user = { id: userIDobject.id, password: hashedPassword };
      userDatabase.push(user);

      res.status(201).json({ id: userIDobject.id, username });
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
