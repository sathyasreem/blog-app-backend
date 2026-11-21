const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

const User = mongoose.model(
  "User",
  new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
  })
);

const Blog = mongoose.model(
  "Blog",
  new mongoose.Schema(
    {
      title: String,
      content: String,
      author: String,
      userId: String,
    },
    { timestamps: true }
  )
);

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ message: "Please login first" });
  }
}

app.get("/", (req, res) => res.send("Blog API running"));

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: "All fields required" });
    const exists = await User.findOne({ email });
    if (exists)
      return res.status(400).json({ message: "Email already registered" });
    const hashed = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashed });
    res.status(201).json({ message: "Registered successfully" });
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid email or password" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok)
      return res.status(400).json({ message: "Invalid email or password" });
    const token = jwt.sign(
      { id: user._id, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.json({ message: "Login successful", token, name: user.name });
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/blogs", auth, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content)
      return res.status(400).json({ message: "Title and content required" });
    const blog = await Blog.create({
      title,
      content,
      author: req.user.name,
      userId: req.user.id,
    });
    res.status(201).json(blog);
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/blogs", async (req, res) => {
  const blogs = await Blog.find().sort({ createdAt: -1 });
  res.json(blogs);
});
app.get("/api/blogs/:id", async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);
    if (!blog) return res.status(404).json({ message: "Blog not found" });
    res.json(blog);
  } catch (e) {
    res.status(404).json({ message: "Blog not found" });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on " + PORT));
