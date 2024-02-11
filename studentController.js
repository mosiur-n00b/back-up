const asyncHandler = require("express-async-handler")
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { generateToken } = require('../../utils/generateToken')

// importing model
const Student = require("../../models/studentModel");

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mosiur.n00b@gmail.com',
    pass: 'nmextztoxtitrrfs'
  }
});

// Send OTP via email
const sendOTPByEmail = async (email, otp) => {
  try {
    await transporter.sendMail({
      from: 'mosiur.n00b@gmail.com',
      to: email,
      subject: "nodemailer",
      text: `Your OTP is: ${otp}`,
    })
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Error sending OTP via email');
  }
};

//@desc Register a new student
//@route POST /api/application/students/register
//@access Admin

const registerStudent = asyncHandler(async (req, res) => {
  const { name, email, phone, password } = req.body;

  // Validation
  if (!name || !email || !phone || !password) {
    res.status(400);
    throw new Error("Please include all fields");
  }

  // Find if student already exists
  const studentExists = await Student.findOne({ $or: [{ email: email }, { phone: phone }] });

  if (studentExists) {
    res.status(400);
    throw new Error("Student already exists");
  }
  else {
    // Create student
    const student = await Student.create({
      name,
      email,
      phone,
      password,
    });

    // Generate and send OTP
    const otp = student.generateOTP();
    await student.save();
    
    // Send OTP via email
    await sendOTPByEmail(email, otp);

    if (student) {
      generateToken(res, student._id)
      res.status(201).json({
        _id: student._id,
        name: student.name,
        email: student.email,
        phone: student.phone,
      });
    } else {
      res.status(400);
      throw new Error("Invalid student data");
    }
  }
});


// @desc    Login a student
// @route   POST /api/application/students/login
// @access  Public
const loginStudent = asyncHandler(async (req, res) => {
  const { email, password, otp } = req.body;

  try {
    const student = await Student.findOne({ email });
    //console.log(student)

    if (!student) {
      res.status(401);
      throw new Error("Student not found");
    }

    const isPasswordValid = await student.matchPassword(password);

    if (isPasswordValid) {
      // Check if OTP is required
      if (student.otpRequired) {
        const isOTPValid = student.verifyOTP(otp);

        if (!isOTPValid) {
          res.status(401);
          throw new Error("Invalid OTP");
        }

        // Clear OTP after successful login
        student.clearOTP();
        student.otpRequired = false; // Disable OTP for subsequent logins
      }

      await student.save();

      generateToken(res, student._id);
      res.status(200).json({
        _id: student._id,
        name: student.name,
        email: student.email,
        phone: student.phone
      });
    } else {
      res.status(401);
      throw new Error("Invalid credentials");
    }
  } catch (error) {
    console.error('Login Error:', error);
    res.status(401).json({ error: error.message });
  }
});

// @desc    Logout student / clear cookie
// @route   POST /api/application/students/logout
// @access  Public
const logoutStudent = (req, res) => {
  res.cookie('jwt', '', {
    httpOnly: true,
    expires: new Date(0),
  });
  res.status(200).json({ message: 'Logged out successfully' });
};


// @desc    Get current student
// @route   GET /api/application/students/:id
// @access  Private
const getStudent = asyncHandler(async (req, res) => {

  const studentId = req.params.id;

  // Retrieve student details based on the ID
  const student = await Student.findById(studentId);

  // Check if the student is not found
  if (!student) {
    return res.status(404).json({ message: 'Student not found' });
  }

  // Return the student details
  const studentDetails = {
    id: student._id,
    name: student.name,
    email: student.email,
    phone: student.phone,
  };

  res.status(200).json(studentDetails);
});

// @desc    Get all students
// @route   GET /api/application/students/
// @access  Private
const getAllStudents = asyncHandler(async (req, res) => {

  const { search, sort } = req.query

  const queryObject = search ? {
    $or: [

      {
        name: {
          $regex: search,
          $options: 'i',
        }
      },
      {
        college: {
          $regex: search,
          $options: 'i',
        }
      },

    ]
  } : {}

  const sortOptions = {
    newest: '-createdAt',
    oldest: 'createdAt',
    'a-z': 'name',
    'z-a': '-name',
  }
  const sortKey = sortOptions[sort] || sortOptions.newest

  //pagination
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 5;
  const skip = (page - 1) * limit;


  const students = await Student
    .find({ ...queryObject })
    .sort(sortKey)
    .skip(skip)
    .limit(limit)

  const totalStudents = await Student.countDocuments(queryObject)
  const numOfPages = Math.ceil(totalStudents / limit)
  res.status(200).json({ students, totalStudents, numOfPages, currentPage: page })
  // }

})

// @desc    Update student credentials
// @route   PUT /api/application/students/:id
// @access  Private
const updateStudent = asyncHandler(async (req, res) => {
  const studentId = req.params.id;

  try {
    const student = await Student.findById(studentId);

    if (!student) {
      res.status(404);
      throw new Error("Student not found");
    }

    const updatedStudent = await Student.findByIdAndUpdate(
      studentId,
      req.body,
      { new: true }
    )
    res.status(200).json(updatedStudent);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// @desc    EDIT password
// @route   PUT /api/application/students/update-password
// @access  Private

const updatePassword = asyncHandler(async (req, res) => {

  const { studentId, password } = req.body
  const student = await Student.findById(studentId)

  if (!student) {
    res.status(404)
    throw new Error("Student not found")
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt)

  student.password = hashedPassword

  try {
    await student.save()
  } catch (error) {
    throw new Error("Password failed to be save")
  }
  res.status(200).json({ student })
})

// @desc    Forgot password
// @route   POST /api/application/students/forgot-password
// @access  Public
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const student = await Student.findOne({ email });

  if (!student) {
    res.status(404);
    throw new Error("Student not found");
  }

  // Generate and send OTP
  const otp = student.generateOTP();
  await student.save();
  
  // Send OTP via email
  await sendOTPByEmail(email, otp);

  res.status(200).json({ message: 'OTP sent successfully' });
});

// @desc    Reset password using OTP
// @route   POST /api/application/students/reset-password
// @access  Public
const resetPassword = asyncHandler(async (req, res) => {
  const { otp, newPassword } = req.body;
  const student = await Student.findOne({ otp });

  if (!student) {
    res.status(404).json({ error: "Invalid or expired OTP" });
  }

  // Verify OTP
  const isOTPValid = student.verifyOTP(otp);

  if (!isOTPValid) {
    res.status(401).json({ error: "Invalid or expired OTP" });
  }

  // Hash new password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(newPassword, salt);

  // Update password and clear OTP
  student.password = hashedPassword;
  student.otp = undefined;
  await student.save();

  res.status(200).json({ message: "Password reset successful" });
});

// @desc    Delete Student
// @route   DELETE /api/application/students/:id
// @access  Private and Admin Only

const deleteStudent = asyncHandler(async (req, res) => {
  const student = await Student.findById(req.params.id);

  if (!student) {
    res.status(404);
    throw new Error("Student not found");
  }

  await student.deleteOne();

  res.status(200).json({ success: true });
});

module.exports = {
  registerStudent,
  loginStudent,
  getStudent,
  getAllStudents,
  updateStudent,
  updatePassword,
  forgotPassword,
  resetPassword,
  deleteStudent,
  logoutStudent
};
