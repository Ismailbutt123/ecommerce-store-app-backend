import ErrorHandler from "../middlewares/errorMiddleware.js";
import { catchAsyncErrors } from "../middlewares/catchAsyncError.js";
import database from "../database/db.js";
import bcrypt from "bcrypt";
import { sendToken } from "../utils/jwtToken.js";
import { generateResetPasswordToken } from "../utils/generateResetPasswordToken.js";
import { generateEmailTemplate } from "../utils/generateForgotPasswordEmailTemplate.js";
import { sendEmail } from "../utils/sendEmail.js";
import crypto from "crypto";
import { v2 as cloudinary } from "cloudinary";

export const register = catchAsyncErrors(async (req, res, next) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return next(new ErrorHandler("Please provide all required fields.", 400));
  }
  if (password.length < 8 || password.length > 16) {
    return next(
      new ErrorHandler("Password must be between 8 and 16 characters.", 400)
    );
  }

  const isAlreadyRegistered = await database.query(
    `SELECT * FROM users WHERE email = $1`,
    [email]
  );

  if (isAlreadyRegistered.rows.length > 0) {
    return next(
      new ErrorHandler("User already registered with this email.", 400)
    );
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await database.query(
    "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
    [name, email, hashedPassword]
  );
  sendToken(user.rows[0], 201, "User registered successfully", res);
});

export const login = catchAsyncErrors(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(new ErrorHandler("Please provide email and password.", 400));
  }
  const user = await database.query(`SELECT * FROM users WHERE email = $1`, [
    email,
  ]);
  if (user.rows.length === 0) {
    return next(new ErrorHandler("Invalid email or password.", 401));
  }
  const isPasswordMatch = await bcrypt.compare(password, user.rows[0].password);
  if (!isPasswordMatch) {
    return next(new ErrorHandler("Invalid email or password.", 401));
  }
  sendToken(user.rows[0], 200, "Logged In.", res);
});

export const getUser = catchAsyncErrors(async (req, res, next) => {
  const { user } = req;
  res.status(200).json({
    success: true,
    user,
  });
});

export const logout = catchAsyncErrors(async (req, res, next) => {
  res
    .status(200)
    .cookie("token", "", {
      expires: new Date(Date.now()),
      httpOnly: true,
      secure: true,
      sameSite: "None",
    })
    .json({
      success: true,
      message: "Logged out successfully.",
    });
});

export const forgotPassword = catchAsyncErrors(async (req, res, next) => {
  const { email } = req.body;
  const { frontendUrl } = req.query;
  let userResult = await database.query(
    `SELECT * FROM users WHERE email = $1`,
    [email]
  );
  if (userResult.rows.length === 0) {
    return next(new ErrorHandler("User not found with this email.", 404));
  }
  const user = userResult.rows[0];
  const { hashedToken, resetPasswordExpireTime, resetToken } =
    generateResetPasswordToken();

  await database.query(
    `UPDATE users SET reset_password_token = $1, reset_password_expire = to_timestamp($2) WHERE email = $3`,
    [hashedToken, resetPasswordExpireTime / 1000, email]
  );

  const resetPasswordUrl = `${frontendUrl}/password/reset/${resetToken}`;

  const message = generateEmailTemplate(resetPasswordUrl);

  try {
    await sendEmail({
      email: user.email,
      subject: "Ecommerce Password Recovery",
      message,
    });
    res.status(200).json({
      success: true,
      message: `Email sent to ${user.email} successfully.`,
    });
  } catch (error) {
    await database.query(
      `UPDATE users SET reset_password_token = NULL, reset_password_expire = NULL WHERE email = $1`,
      [email]
    );
    return next(new ErrorHandler("Email could not be sent.", 500));
  }
});

export const resetPassword = catchAsyncErrors(async (req, res, next) => {
  const { token } = req.params;
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  const user = await database.query(
    "SELECT * FROM users WHERE reset_password_token = $1 AND reset_password_expire > NOW()",
    [resetPasswordToken]
  );
  if (user.rows.length === 0) {
    return next(new ErrorHandler("Invalid or expired reset token.", 400));
  }
  if (req.body.password !== req.body.confirmPassword) {
    return next(new ErrorHandler("Passwords do not match.", 400));
  }
  if (
    req.body.password?.length < 8 ||
    req.body.password?.length > 16 ||
    req.body.confirmPassword?.length < 8 ||
    req.body.confirmPassword?.length > 16
  ) {
    return next(
      new ErrorHandler("Password must be between 8 and 16 characters.", 400)
    );
  }
  const hashedPassword = await bcrypt.hash(req.body.password, 10);

  const updatedUser = await database.query(
    `UPDATE users SET password = $1, reset_password_token = NULL, reset_password_expire = NULL WHERE id = $2 RETURNING *`,
    [hashedPassword, user.rows[0].id]
  );
  sendToken(updatedUser.rows[0], 200, "Password reset successfully", res);
});

export const updatePassword = catchAsyncErrors(async (req, res, next) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;
  console.log(currentPassword, newPassword, confirmNewPassword)
  if (!currentPassword || !newPassword || !confirmNewPassword) {
    return next(new ErrorHandler("Please provide all required fields.", 400));
  }
  const isPasswordMatch = await bcrypt.compare(
    currentPassword,
    req.user.password
  );
  if (!isPasswordMatch) {
    return next(new ErrorHandler("Current password is incorrect.", 401));
  }
  if (newPassword !== confirmNewPassword) {
    return next(new ErrorHandler("New passwords do not match.", 400));
  }

  if (
    newPassword.length < 8 ||
    newPassword.length > 16 ||
    confirmNewPassword.length < 8 ||
    confirmNewPassword.length > 16
  ) {
    return next(
      new ErrorHandler("Password must be between 8 and 16 characters.", 400)
    );
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  await database.query("UPDATE users SET password = $1 WHERE id = $2", [
    hashedPassword,
    req.user.id,
  ]);

  res.status(200).json({
    success: true,
    message: "Password updated successfully.",
  });
});

export const updateProfile = catchAsyncErrors(async (req, res, next) => {
  console.log("BODY:", req.body);
  console.log("USER:", req.user);
  console.log("FILES:", req.files);

  const { name, email } = req.body;

  if (!name || !email) {
    return next(new ErrorHandler("Please provide all required fields.", 400));
  }

  let avatarData = null;

  // Agar user ke paas pehle se avatar hai
  const currentAvatar = req.user.avatar ? req.user.avatar : null;

  // Agar new avatar upload hua
  if (req.files?.avatar) {
    const avatar = req.files.avatar;

    if (!avatar.tempFilePath) {
      return next(new ErrorHandler("Avatar upload failed.", 500));
    }

    // Purana avatar delete karo agar exists karta ho
    if (currentAvatar?.public_id) {
      try {
        await cloudinary.uploader.destroy(currentAvatar.public_id);
      } catch (err) {
        console.error("Failed to delete old avatar:", err);
      }
    }

    // Naya avatar upload karo
    try {
      const uploadedAvatar = await cloudinary.uploader.upload(avatar.tempFilePath, {
        folder: "Ecommerce_Avatars",
        width: 150,
        crop: "scale",
      });

      avatarData = {
        public_id: uploadedAvatar.public_id,
        url: uploadedAvatar.secure_url,
      };
    } catch (err) {
      console.error("Cloudinary upload failed:", err);
      return next(new ErrorHandler("Failed to upload avatar.", 500));
    }
  } else if (currentAvatar) {
    avatarData = currentAvatar;
  }

  // DB update
  let updatedUser;
  try {
    if (avatarData) {
      updatedUser = await database.query(
        "UPDATE users SET name=$1, email=$2, avatar=$3 WHERE id=$4 RETURNING *",
        [name, email, JSON.stringify(avatarData), req.user.id]
      );
    } else {
      updatedUser = await database.query(
        "UPDATE users SET name=$1, email=$2 WHERE id=$3 RETURNING *",
        [name, email, req.user.id]
      );
    }
  } catch (err) {
    console.error("DB update failed:", err);
    return next(new ErrorHandler("Failed to update profile in DB.", 500));
  }

  // Parse avatar before sending response
  let avatarDataParsed = null;
  if (updatedUser.rows[0].avatar && updatedUser.rows[0].avatar !== "undefined") {
    try {
      avatarDataParsed = JSON.parse(updatedUser.rows[0].avatar);
    } catch (err) {
      console.error("Failed to parse avatar JSON:", err);
    }
  }

  const userResponse = {
    ...updatedUser.rows[0],
    avatar: avatarDataParsed,
  };

  res.status(200).json({
    success: true,
    message: "Profile updated successfully",
    user: userResponse,
  });
});