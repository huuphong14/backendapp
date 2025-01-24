const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const User = require("../models/User");
const sendEmail = require("../utils/email");
const generateOtp = require("../utils/generateOtp");

// Kiểm tra biến môi trường
if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error("Thiếu biến môi trường JWT_SECRET hoặc JWT_REFRESH_SECRET");
}

// Hàm validate email
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// Đăng ký tài khoản
exports.register = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email và mật khẩu là bắt buộc." });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ message: "Email không hợp lệ." });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email đã tồn tại." });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const otp = generateOtp();
    const otpExpires = Date.now() + 15 * 60 * 1000; // OTP hết hạn sau 15 phút

    const user = new User({
      email,
      password: hashedPassword,
      otp: crypto.createHash("sha256").update(otp).digest("hex"), // Hash OTP
      otpExpires,
    });
    await user.save();

    await sendEmail(email, "Kích hoạt tài khoản", `Mã OTP của bạn là: ${otp}`);

    res.status(200).json({
      message: "Đăng ký thành công. Kiểm tra email để kích hoạt tài khoản.",
    });
  } catch (error) {
    res.status(500).json({ message: "Lỗi server", error: error.stack });
  }
};

// Kích hoạt tài khoản
exports.activateAccount = async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: "Email và OTP là bắt buộc." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !user.otpExpires || user.otpExpires < Date.now()) {
      return res.status(400).json({
        message: "OTP không hợp lệ hoặc đã hết hạn.",
      });
    }

    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");
    if (hashedOtp !== user.otp) {
      return res.status(400).json({ message: "OTP không đúng." });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Tài khoản đã được kích hoạt thành công!" });
  } catch (error) {
    res.status(500).json({ message: "Lỗi server", error: error.stack });
  }
};

// Đăng nhập
exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email và mật khẩu là bắt buộc." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Email không tồn tại." });
    }

    if (!user.isVerified) {
      return res.status(400).json({ message: "Tài khoản chưa được kích hoạt." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Mật khẩu không đúng." });
    }

    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, {
      expiresIn: process.env.JWT_REFRESH_EXPIRATION,
    });

    user.refreshToken = refreshToken;
    await user.save();

    res.status(200).json({
      message: "Đăng nhập thành công!",
      accessToken,
      refreshToken,
    });
  } catch (error) {
    res.status(500).json({ message: "Lỗi server", error: error.stack });
  }
};

// Refresh access token
exports.refreshToken = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ message: "Token không hợp lệ!" });
  }

  try {
    const user = await User.findOne({ refreshToken });
    if (!user) {
      return res.status(403).json({ message: "Refresh token không hợp lệ!" });
    }

    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
      if (err) {
        user.refreshToken = null; // Xóa refresh token khi hết hạn
        user.save();
        return res.status(403).json({ message: "Refresh token hết hạn!" });
      }

      const newAccessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
      res.status(200).json({ accessToken: newAccessToken });
    });
  } catch (error) {
    res.status(500).json({ message: "Lỗi server", error: error.stack });
  }
};

// Quên mật khẩu
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email là bắt buộc." });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ message: "Email không hợp lệ." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Email không tồn tại." });
    }

    const otp = generateOtp();
    user.otp = crypto.createHash("sha256").update(otp).digest("hex");
    user.otpExpires = Date.now() + 15 * 60 * 1000; // OTP hết hạn sau 15 phút
    await user.save();

    await sendEmail(email, "Quên mật khẩu", `Mã OTP để đặt lại mật khẩu: ${otp}`);

    res.status(200).json({ message: "Mã OTP đã được gửi qua email." });
  } catch (error) {
    res.status(500).json({ message: "Lỗi server", error: error.stack });
  }
};

// Đặt lại mật khẩu
exports.resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ message: "Email, OTP và mật khẩu mới là bắt buộc." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !user.otpExpires || user.otpExpires < Date.now()) {
      return res.status(400).json({
        message: "OTP không hợp lệ hoặc đã hết hạn.",
      });
    }

    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");
    if (hashedOtp !== user.otp) {
      return res.status(400).json({ message: "OTP không đúng." });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Đặt lại mật khẩu thành công!" });
  } catch (error) {
    res.status(500).json({ message: "Lỗi server", error: error.stack });
  }
};

// Đăng xuất
exports.logout = async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token là bắt buộc." });
  }

  try {
    const user = await User.findOne({ refreshToken });
    if (!user) {
      return res.status(403).json({ message: "Refresh token không hợp lệ!" });
    }

    user.refreshToken = null;
    await user.save();

    res.clearCookie("refreshToken", { secure: true, httpOnly: true }); // Đảm bảo cookie bảo mật
    res.status(200).json({ message: "Đăng xuất thành công!" });
  } catch (error) {
    res.status(500).json({ message: "Lỗi server", error: error.stack });
  }
};

