const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("../models/User");
const sendEmail = require("../utils/email");
const generateOtp = require("../utils/generateOtp");

// Đăng ký tài khoản
exports.register = async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Email đã tồn tại." });

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000); // OTP hết hạn sau 15 phút

    const user = new User({ email, password: hashedPassword, otp, otpExpires });
    await user.save();

    await sendEmail(email, "Kích hoạt tài khoản", `Mã OTP của bạn là: ${otp}`);

    res.status(200).json({ message: "Đăng ký thành công. Kiểm tra email để kích hoạt tài khoản." });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Kích hoạt tài khoản
exports.activateAccount = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email, otp });
    if (!user || user.otpExpires < Date.now())
      return res.status(400).json({ message: "OTP không hợp lệ hoặc đã hết hạn." });

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Tài khoản đã được kích hoạt thành công!" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Đăng nhập
exports.login = async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(404).json({ message: "Email không tồn tại." });
      if (!user.isVerified) return res.status(400).json({ message: "Tài khoản chưa được kích hoạt." });
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ message: "Mật khẩu không đúng." });
  
      // Tạo access token
      const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
      // Tạo refresh token
      const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRATION });
  
      // Lưu refresh token vào cơ sở dữ liệu hoặc cookie
      user.refreshToken = refreshToken;
      await user.save();
  
      res.status(200).json({ message: "Đăng nhập thành công!", accessToken, refreshToken });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  
  // Refresh access token
  exports.refreshToken = async (req, res) => {
    const { refreshToken } = req.body;
  
    try {
      if (!refreshToken) return res.status(401).json({ message: "Token không hợp lệ!" });
  
      const user = await User.findOne({ refreshToken });
      if (!user) return res.status(403).json({ message: "Refresh token không hợp lệ!" });
  
      jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Refresh token hết hạn!" });
  
        // Tạo một access token mới
        const newAccessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  
        res.status(200).json({ accessToken: newAccessToken });
      });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  

// Quên mật khẩu
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "Email không tồn tại." });

    const otp = generateOtp();
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 15 * 60 * 1000); // OTP hết hạn sau 15 phút
    await user.save();

    await sendEmail(email, "Quên mật khẩu", `Mã OTP để đặt lại mật khẩu: ${otp}`);

    res.status(200).json({ message: "Mã OTP đã được gửi qua email." });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Đặt lại mật khẩu
exports.resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ email, otp });
    if (!user || user.otpExpires < Date.now())
      return res.status(400).json({ message: "OTP không hợp lệ hoặc đã hết hạn." });

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Đặt lại mật khẩu thành công!" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
exports.logout = async (req, res) => {
    const { refreshToken } = req.body;
  
    try {
      const user = await User.findOne({ refreshToken });
      if (!user) return res.status(403).json({ message: "Refresh token không hợp lệ!" });
  
      user.refreshToken = null; // Xóa refresh token khỏi DB
      await user.save();
  
      res.clearCookie("refreshToken"); // Xóa cookie nếu sử dụng
      res.status(200).json({ message: "Đăng xuất thành công!" });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  };
  