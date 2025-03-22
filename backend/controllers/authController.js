import bcrypt, { hash } from "bcryptjs"
import jwt from "jsonwebtoken"
import userModel from "../models/userModel.js"
import transporter from "../config/nodemailer.js"

import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js'


export const register = async (req, res) => {
    const { email, name, password } = req.body

    if (!name || !email || !password) {
        return res.json({ success: false, message: 'Missing Details.' })
    }

    try {
        const exsistingUser = await userModel.findOne({email})

        if (exsistingUser) {
            return res.json({ success: false, message: 'User already exsist.' })
        }
        
        const hashedPassword = await bcrypt.hash(password, 10)

        const user = new userModel({
            name,
            email,
            password: hashedPassword,
        })

        await user.save()

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'})

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        // sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Muhammad Fahad Authentication App',
            text: `Welcome to my Authentication website. Your account has been created with email id: ${email}.`
        }

        await transporter.sendMail(mailOptions)

        return res.json({success: true})
        
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}


export const login = async (req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        return res.json({ success: false, message: "Email and Password Both are required." })
    }

    try {

        const user = await userModel.findOne({email})

        if (!user) {
            return res.json({ success: false, message: "User did'nt exsist." })
        }

        const isMatch = await bcrypt.compare(password, user.password) 

        if (!isMatch) {
            return res.json({ success: false, message: "Invalid Email or Password." })
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d'})

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })


        return res.json({success: true})
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        })
    }
}


export const logout = async (req, res) => {
    try {

        // deleting Cookies to logout.
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
        })

        return res.json({success: true, message: "Logged Out"})
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        })
    }
}


// Send verification OTP to the user's Email.
export const sendVerifyOtp = async (req, res) => {
    try {
        // we will recieve user id from the token.
        const { userId } = req.body

        const user = await userModel.findById(userId)

        if (user.isAccountVerified) {
            return res.json({success: false, message: "Account Already Verified."})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000))

        user.verifyOtp = otp
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000

        await user.save()

        // sending OTP.
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP.',
            // text: `Your OTP is ${otp}, Verify your account using this OTP.`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }

        await transporter.sendMail(mailOptions)

        res.json({ success: true, message: "Verification OTP sent Successfully."})
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        })
    }
}


// Verify the Email using OTP.
export const verifyEmail = async (req, res) => {
    // we will recieve user id from the token.
    const {userId, otp} = req.body

    if (!userId || !otp) {
        return res.json({ success: false, message: "Missing Details."})
    }

    try {
        const user = await userModel.findById(userId)

        if (!user) {
            return res.json({ success: false, message: "User not Found."})
        }

        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({ success: false, message: "Invalid OTP."})
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: "OTP Expires."})
        }

        user.isAccountVerified = true
        user.verifyOtp = ''
        user.verifyOtpExpireAt = 0
        await user.save()


        return res.json({ success: true, message: 'Email Verified successfully.'})
        
    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}

// Check if user is authenticated.
export const isAuthenticated = async (req, res) => {
    try {
        res.json({ success: true})
    } catch (error) {
        res.json({ success: false, message: error.message})
    }
}


// Send password Reset OTP.
export const sendResetOtp = async (req, res) => {
    const { email } = req.body

    if (!email) {
        return res.json({ success: false, message: 'Email is required.'})
    }

    try {
        
        const user = await userModel.findOne({email})

        if (!user) {
            return res.json({ success: false, message: 'User not Found.'})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000))

        user.resetOtp = otp
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000

        await user.save()

        // sending OTP.
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Your OTP for Resetting your password is ${otp}, Use this OTP to proceed with resetting your password.`,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }

        await transporter.sendMail(mailOptions)

        return res.json({ success: true, message: 'OTP sent to your email.'})

    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}


// Reset User Password.
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: 'Email, OTP, and New Password are required.'})
    }

    try {
        
        const user = await userModel.findOne({email})

        if (!user) {
            return res.json({ success: false, message: 'User not Found.'})
        }

        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP.'})
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP Expired.'})
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10)

        user.password = hashedPassword
        user.resetOtp = ''
        user.resetOtpExpireAt = 0

        await user.save()

        return res.json({ success: true, message: 'Password has been Reset Successfully.'})

    } catch (error) {
        return res.json({ success: false, message: error.message })
    }
}