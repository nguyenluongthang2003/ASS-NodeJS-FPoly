import User from "../models/User";
import { signInValid, signUpValid } from "../validations/userValid";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const { SECRET_CODE } = process.env;

export const signUp = async (req, res) => {
  try {

    const body = req.body;
    const { error } = signUpValid.validate(body, { abortEarly: false });
    if (error) {
      const errors = error.details.map((item) => item.message);
      return res.status(400).json({
        message: errors,
      });
    }

    const { userName, email, password, role } = body;

    const checkEmail = await User.findOne({ email });
    if (checkEmail) {
      return res.status(400).json({
        message: "Email already exists!",
      });
    }

    const hashPassword = await bcrypt.hash(password, 10);

    if (!hashPassword) {
      return res.status(400).json({
        message: "Password is not hashed!",
      });
    }

    const user = await User.create({
      userName,
      email,
      password: hashPassword,
      role,
    });

    user.password = undefined;
    return res.status(200).json({
      message: "Successfully!",
      user,
    });
  } catch (error) {
    return res.status(500).json({
      name: error.name || "Error",
      message: error.message || "Server error!",
    });
  }
};

export const signIn = async (req, res) => {
  try {

    const { error } = signInValid.validate(req.body, { abortEarly: false });

    if (error) {
      const errors = error.details.map((item) => item.message);
      return res.status(400).json({
        message: errors,
      });
    }


    const { email, password } = req.body;

    const checkUser = await User.findOne({ email });
    if (!checkUser) {
      return res.status(400).json({
        message: "Email does not exist!",
      });
    }

    const checkPassword = await bcrypt.compare(password, checkUser.password);

    if (!checkPassword) {
      return res.status(400).json({
        message: "Password is incorrect!",
      });
    }

    const accessToken = jwt.sign({ id: checkUser._id }, SECRET_CODE, {
      expiresIn: "10d",
    });

    if (!accessToken) {
      return res.status(400).json({
        message: "Access token is not created!",
      });
    }

    checkUser.password = undefined;
    return res.status(200).json({
      message: "Successfully!",
      accessToken,
      user: checkUser,
    });
  } catch (error) {
    return res.status(500).json({
      name: error.name || "Error",
      message: error.message || "Server error!",
    });
  }
};
