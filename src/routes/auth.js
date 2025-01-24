const express = require("express");
const router = express.Router();
const {
  register,
  activateAccount,
  login,
  forgotPassword,
  resetPassword,
  refreshToken,
  logout
} = require("../controllers/authController");

router.post("/register", register);
router.post("/activate", activateAccount);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);
router.post("/refresh-token", refreshToken);
router.post("/logout", logout);

module.exports = router;
