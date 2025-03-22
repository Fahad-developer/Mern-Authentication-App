import express from "express"
import { register, login, logout, sendVerifyOtp, verifyEmail, isAuthenticated, sendResetOtp, resetPassword } from "../controllers/authController.js"
import userAuth from "../middleware/userAuth.js"

const authRouter = express.Router()


authRouter.post('/register', register)
authRouter.post('/login', login)
authRouter.post('/logout', userAuth, logout)

// Verification Routes.

authRouter.post('/send-verify-otp', userAuth, sendVerifyOtp)
authRouter.post('/verify-account', userAuth, verifyEmail)
authRouter.get('/is-auth', userAuth, isAuthenticated)

// Reset Routes.

authRouter.post('/send-reset-otp', sendResetOtp)
authRouter.post('/reset-password', resetPassword)

export default authRouter