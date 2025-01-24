const express = require("express");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");

dotenv.config();

const app = express();
connectDB();

app.use(bodyParser.json());
app.use("/api/auth", authRoutes);

module.exports = app;
