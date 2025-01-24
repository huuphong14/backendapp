const generateOtp = () => {
    return Math.floor(100000 + Math.random() * 900000).toString(); // Tạo OTP 6 chữ số
  };
  
  module.exports = generateOtp;
  