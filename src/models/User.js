const mongoose = require("mongoose");
const validator = require("validator");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    validate: [validator.isEmail, "Email không hợp lệ"],
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  isVerified: { type: Boolean, default: false },
  otp: { type: String}, 
  otpExpires: { type: Date },
  refreshToken: { type: String },
});

module.exports = mongoose.model("User", userSchema);

