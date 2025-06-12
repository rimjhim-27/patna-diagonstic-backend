// Backend: middleware/auth.js
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization');
  // JWT verification logic
};